/*
 * scanner.c -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#include "parser.h"

static zone_return_t refill(const zone_parser_t *par)
{
  // FIXME: implement
  // x. take into account the offset and cursor
  (void)par;
  return ZONE_OUT_OF_MEMORY;
}

static int32_t peek(const zone_parser_t *par, size_t idx)
{
  assert(par);
  assert(par->file->buffer.cursor <= par->file->buffer.used);
  if (idx < par->file->buffer.used - par->file->buffer.cursor)
    return par->file->buffer.data.read[par->file->buffer.cursor + idx];
  return !par->file->handle || feof(par->file->handle) ? 0 : ZONE_NEED_REFILL;
}

static inline zone_return_t
lex_comment(const zone_parser_t *par, zone_token_t *tok, size_t cnt, size_t *len)
{
  int32_t chr;

  chr = peek(par, cnt);
  assert(chr == ';');

  for (cnt++; (chr = peek(par, cnt)) > '\0'; cnt++) {
    if (chr == '\n' || chr == '\r')
      break;
    tok->location.end.column++;
  }

  if (chr < 0)
    return chr;
  *len = cnt;
  tok->string.data = par->file->buffer.data.read + par->file->buffer.cursor;
  tok->string.length = cnt;
  return (tok->code = ';');
}

static inline zone_return_t
lex_quoted_string(const zone_parser_t *par, zone_token_t *tok, size_t off, size_t *len)
{
  size_t cnt = off;
  int32_t chr, esc = 0;

  chr = peek(par, cnt);
  assert(chr == '"');

  for (cnt++; (chr = peek(par, cnt)) >= '\0'; cnt++) {
    switch (chr) {
      case '\0':
        SYNTAX_ERROR(par, "Unexpected end-of-file, expected closing quote "
                          "at %y", &tok->location.end);
      case '\r':
        chr = peek(par, cnt + 1);
        if (chr < 0)
          return chr;
        cnt += (chr == '\n');
        // fall through
      case '\n':
        tok->location.end.line++;
        tok->location.end.column = 1;
        esc = 0;
        break;
      case '\\':
        tok->location.end.column++;
        esc = tok->string.escaped = 1;
        break;
      case '\"':
        if (!esc) {
          tok->location.end.column++;
          *len = cnt + 1;
          assert(cnt >= off);
          tok->string.data = par->file->buffer.data.read + par->file->buffer.cursor + off + 1;
          tok->string.length = (cnt - off) - 1;
          return (tok->code = ZONE_STRING);
        }
        // fall through
      default:
        tok->location.end.column++;
        esc = 0;
        break;
    }
  }

  assert(chr < '\0');
  return chr;
}

static inline zone_return_t
lex_string(const zone_parser_t *par, zone_token_t *tok, size_t off, size_t *len)
{
  size_t cnt = off;
  int32_t chr, esc = 0;
  static const char delim[] = ";()\n\r \t\"";

  chr = peek(par, cnt);
  assert(chr && !strchr(delim, chr));

  for (cnt++; (chr = peek(par, cnt)) > '\0'; cnt++) {
    if (chr == '\\')
      esc = tok->string.escaped = 1;
    else if (esc)
      esc = 0;
    else if (strchr(delim, chr))
      break;
    tok->location.end.column++;
  }

  if (chr < 0)
    return chr;
  *len = cnt;
  assert(cnt >= off);
  tok->string.data = par->file->buffer.data.read + par->file->buffer.cursor + off;
  tok->string.length = cnt - off;
  return (tok->code = ZONE_STRING);
}

static inline bool is_svcparamkey(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

static inline zone_return_t
lex_svcparam(const zone_parser_t *par, zone_token_t *tok, size_t off, size_t *len)
{
  size_t cnt = off;
  int32_t chr;
  static const char delim[] = ";\n\r \t";

  chr = peek(par, cnt);
  assert(chr && !strchr(delim, chr));

  if (!is_svcparamkey(chr))
    SYNTAX_ERROR(par, "Invalid SvcParam at {l}");

  for (cnt++; (chr = peek(par, cnt)) > '\0'; cnt++) {
    if (!is_svcparamkey(chr))
      break;
    tok->location.end.column++;
  }

  if (chr < 0)
    return chr;
  *len = cnt;
  tok->svc_param.key.data = par->file->buffer.data.read + par->file->buffer.cursor;
  tok->svc_param.key.length = cnt;

  if (chr != '=')
    return (tok->code = ZONE_SVC_PARAM);
  if ((chr = peek(par, ++cnt)) < 0)
    return chr;
  if (chr == '\0' || strchr(delim, chr))
    return (tok->code = ZONE_SVC_PARAM);

  // dummy token for scanning SvcParamValue
  zone_token_t dummy = { tok->location, 0, .string = { NULL, 0 } };
  if (chr == '"')
    chr = lex_quoted_string(par, &dummy, cnt, len);
  else
    chr = lex_string(par, &dummy, cnt, len);
  if (chr < 0)
    return chr;
  tok->location = dummy.location;
  tok->svc_param.value = dummy.string;
  return (tok->code = ZONE_SVC_PARAM);
}

static inline void reset_token(const zone_parser_t *par, zone_token_t *tok)
{
  tok->location.end = tok->location.begin = par->file->position;
}

static inline zone_return_t scan_svcb(zone_parser_t *par, zone_token_t *tok)
{
  int32_t code = ' ';

  assert((par->state & 0xff0000) == ZONE_SVC_PARAM);

  do {
    size_t cnt = 1;
    int32_t chr = peek(par, 0);
    if (chr == ';') {
      tok->location.end = tok->location.begin = par->file->position;
      code = lex_comment(par, tok, 0, &cnt);
      goto eval;
    } else if (chr == '(' || chr == ')' || chr == '\0') {
      code = chr;
    } else if (chr == '\r') { // CR+LF (Windows) or CR (Macintosh)
      if ((chr = peek(par, cnt + 1)) < 0)
        return (code = chr);
      cnt += (chr == '\n');
      code = '\n'; // handle end-of-line consistently
    } else if (chr == '\n') { // LF (UNIX)
      code = '\n';
    } else if (chr == ' ' || chr == '\t') {
      code = ' '; // handle tabs and spaces consistently
    } else {
      reset_token(par, tok);
      code = lex_svcparam(par, tok, 0, &cnt);
      goto eval;
    }

    tok->code = code;
    tok->location.end = tok->location.begin = par->file->position;
    if (code == '\n') {
      tok->location.end = tok->location.begin = par->file->position;
      tok->location.end.line++;
      tok->location.end.column = 1;
    } else if (code > 0) {
      tok->location.end.column++;
    }

eval:
    if (code < 0)
      return code;
    if (code > 0)
      par->file->buffer.cursor += cnt;
    par->file->position = tok->location.end;
  } while (code == ' ');

  return code;
}

// zone file scanner is implemented as a 2 stage process. 1st stage scans for
// tokens without grouping context or recognizing ttl, class, type or rdata.
// comments and (quoted) character strings are converted to a single token,
// as are svc parameters. special characters are returned as individual
// tokens. delimiters are discarded unless they serve to signal an implicit
// owner.
static inline zone_return_t
scan(zone_parser_t *par, zone_token_t * tok)
{
  size_t cnt = 0;
  int32_t code = ' ';

  if ((par->state & 0xff0000) == ZONE_SVC_PARAM)
    return scan_svcb(par, tok);

  do {
    int32_t chr = peek(par, 0);
    if (chr == ';') {
      tok->location.end = tok->location.begin = par->file->position;
      code = lex_comment(par, tok, 0, &cnt);
    } else if (chr == '"') {
      tok->location.end = tok->location.begin = par->file->position;
      code = lex_quoted_string(par, tok, 0, &cnt);
    } else {
      cnt = 1;
      if (chr == '(' || chr == ')' || chr == '\0') {
        code = chr;
      } else if (chr == '\r') { // CR+LF (Windows) or CR (Macintosh)
        if ((chr = peek(par, cnt + 1)) < 0)
          return (code = chr);
        cnt += (chr == '\n');
        code = '\n'; // handle end-of-line consistently
      } else if (chr == '\n') { // LF (UNIX)
        code = '\n';
      } else if (chr != ' ' && chr != '\t') {
        tok->location.end = tok->location.begin = par->file->position;
        code = lex_string(par, tok, 0, &cnt);
        goto eval;
      } else {
        code = ' '; // handle tabs and spaces consistently
      }

      tok->code = code;
      tok->location.end = tok->location.begin = par->file->position;
      if (code == '\n') {
        tok->location.end = tok->location.begin = par->file->position;
        tok->location.end.line++;
        tok->location.end.column = 1;
      } else if (code > 0) {
        tok->location.end.column++; // yeah, this wont work. cnt is to be used instead!!!!
      }
    }
eval:
    if (code < 0)
      return code;
    // do not update cursor on end-of-file
    if (code > 0)
      par->file->buffer.cursor += cnt;
    par->file->position = tok->location.end;
    // any combination of tabs and spaces act as a delimiter between the
    // separate items that make up an entry, but in order to signal an
    // implicit owner to the parser a space is returned if the state is
    // INITIAL.
  } while (code == ' ' && par->state != ZONE_INITIAL);

  return code;
}

// remove \DDD constructs from input. see RFC 1035, section 5.1
ssize_t zone_unescape(const char *str, size_t len, char *buf, size_t size, int strict)
{
  size_t cnt = 0;

  assert(str);
  assert(buf);

  for (size_t i=0; i < len; ) {
    if (str[i] != '\\') {
      if (cnt < size)
        buf[cnt] = str[i];
      cnt++;
      i += 1;
    } else if ((i < len - 1) && (str[i+1] >= '0' && str[i+1] <= '2') &&
               (i < len - 2) && (str[i+2] >= '0' && str[i+2] <= '5') &&
               (i < len - 3) && (str[i+3] >= '0' && str[i+3] <= '5'))
    {
      if (cnt < size)
        buf[cnt] = (str[i+1] - '0') * 100 +
                   (str[i+2] - '0') *  10 +
                   (str[i+3] - '0') *   1;
      cnt++;
      i += 4;
    } else if (len - i >= 1) {
      if (cnt < size)
        buf[cnt] = str[i+1];
      cnt++;
      i += 2;
    } else {
      assert(len - i == 0);
      i += 1;
      // trailing backslash, ignore?
      if (strict)
        return -1;
    }
  }

  assert(cnt <= len);
  return cnt;
}

static inline ssize_t xdigit(const char *enc, size_t len, uint8_t *dig)
{
  char chr = '\0';
  size_t cnt = -1;

  if (!len) {
    return -1;
  } else if (enc[0] != '\\') {
    chr = enc[0];
    cnt = 1;
  } else if (len - 1 && (enc[1] >= '0' && enc[1] <= '2') &&
             len - 2 && (enc[2] >= '0' && enc[2] <= '5') &&
             len - 3 && (enc[3] >= '0' && enc[3] <= '5'))
  {
    chr = (enc[1] - '0') * 100 + (enc[2] - '0') * 10 + (enc[3] - '0');
    cnt = 4;
  } else if (len - 1) {
    chr = enc[1];
    cnt = 2;
  } else {
    return -1;
  }

  if (chr >= '0' && chr <= '9')
    *dig = (uint8_t)chr - '0';
  else if (chr >= 'a' && chr <= 'f')
    *dig = (uint8_t)(chr - 'a') + 10;
  else if (chr >= 'A' && chr <= 'F')
    *dig = (uint8_t)(chr - 'A') + 10;
  else
    return -1;
  return cnt;
}

ssize_t zone_decode(
  const char *enc, size_t enclen, uint8_t *dec, size_t decsize)
{
  size_t cnt, len = 0;

  for (cnt = 0; cnt < enclen; len++) {
    uint8_t hi, lo;
    ssize_t inc;
    if ((inc = xdigit(enc + cnt, enclen - cnt, &hi)) <= 0)
      return -1;
    cnt += (size_t)inc;
    assert(cnt <= enclen);
    if ((inc = xdigit(enc + cnt, enclen - cnt, &lo)) <= 0)
      return -1;
    cnt += (size_t)inc;
    assert(cnt <= enclen);
    if (len < decsize)
      dec[len] = (hi << 4) | lo;
  }

  return (ssize_t)len;
}

static inline uint32_t multiply(uint32_t lhs, uint32_t rhs, uint32_t max)
{
  return (max < lhs || (lhs && max / lhs < rhs)) ? max + 1 : lhs * rhs;
}

static inline uint32_t add(uint32_t lhs, uint32_t rhs, uint32_t max)
{
  return (max < lhs || max - lhs < rhs) ? max + 1 : lhs + rhs;
}

#include "scanner-types.h"

static inline int mapcmp(const void *p1, const void *p2)
{
  int eq;
  const struct map *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->namelen);
  assert(m2 && m2->name && m2->namelen);
  if ((eq = strncasecmp(m1->name, m2->name, m1->namelen)) != 0)
    return eq;
  if (m1->namelen == m2->namelen)
    return 0;
  return m1->namelen < m2->namelen ? -1 : +1;
}

uint16_t zone_is_type(const char *str, size_t len)
{
  struct map *map, key = { 0, str, len };

#ifndef NDEBUG
  for (size_t i = 1; i < sizeof(types)/sizeof(types[0]); i++)
    assert(mapcmp(&types[i - 1], &types[i]) < 0);
#endif

  if (!len)
    return -1;

  switch (str[0]) {
    case 'r':
    case 'R':
      if (len == 5 && strncasecmp(str, "RRSIG", 5) == 0)
        return TYPE_RRSIG;
      break;
    case 'n':
    case 'N':
      if (len == 2 && strncasecmp(str, "NS", 2) == 0)
        return TYPE_NS;
      if (len == 4 && strncasecmp(str, "NSEC", 4) == 0)
        return TYPE_NSEC;
      if (len == 5 && strncasecmp(str, "NSEC3", 5) == 0)
        return TYPE_NSEC3;
      if (len == 10 && strncasecmp(str, "NSEC3PARAM", 10) == 0)
        return TYPE_NSEC3PARAM;
      break;
    case 'd':
    case 'D':
      if (len == 2 && strncasecmp(str, "DS", 2) == 0)
        return TYPE_DS;
      if (len == 6 && strncasecmp(str, "DNSKEY", 6) == 0)
        return TYPE_DNSKEY;
      break;
    case 'a':
    case 'A':
      if (len == 1 && strncasecmp(str, "A", 1) == 0)
        return TYPE_A;
      if (len == 4 && strncasecmp(str, "AAAA", 4) == 0)
        return TYPE_AAAA;
      break;
    case 's':
    case 'S':
      if (len == 3 && strncasecmp(str, "SOA", 3) == 0)
        return TYPE_SOA;
      break;
    case 't':
    case 'T':
      if (len == 3 && strncasecmp(str, "TXT", 3) == 0)
        return TYPE_TXT;
      break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return 0;
    case 'i':
    case 'I':
      if (len == 2 && strncasecmp(str, "IN", 2) == 0)
        return 0;
      break;
  }

  map = bsearch(
    &key, types, sizeof(types)/sizeof(types[0]), sizeof(types[0]), &mapcmp);
  if (map)
    return (int32_t)(map->type);
  return 0;
}

static inline int32_t scan_type(zone_parser_t *par, zone_token_t *tok)
{
  uint32_t type;

  assert(tok->code == ZONE_STRING);

  // FIXME: unescape here first!
  if ((type = zone_is_type(tok->string.data, tok->string.length)) > 0)
    goto done;
  // support unknown DNS resource record types (rfc 3597)
  if (tok->string.length < 4)
    return 0;
  if (strncasecmp(tok->string.data, "TYPE", 4) != 0)
    return 0;

  if (tok->string.length == 4)
    SYNTAX_ERROR(par, "Invalid type at {l}, missing type number");

  type = 0;
  for (size_t i = 4; i < tok->string.length; i++) {
    char chr = tok->string.data[i];
    if (chr < '0' || chr > '9')
      SYNTAX_ERROR(par, "Invalid type at {l}, non-digit in type number");
    type = add(multiply(type, 10, UINT16_MAX), (uint32_t)(chr - '0'), UINT16_MAX);
    if (type > UINT16_MAX)
      SYNTAX_ERROR(par, "Invalid type at {l}, type number exceeds maximum");
  }

done:
  assert(type <= UINT16_MAX);
  tok->int16 = (uint16_t)type;
  return tok->code = ZONE_TYPE | ZONE_INT16;
}

uint16_t zone_is_class(const char *str, size_t len)
{
  if (len != 2)
    return 0;
  if (strncasecmp(str, "IN", 2) == 0)
    return 1;
  if (strncasecmp(str, "CH", 2) == 0)
    return 2;
  if (strncasecmp(str, "CS", 2) == 0)
    return 3;
  if (strncasecmp(str, "HS", 2) == 0)
    return 4;
  return 0;
}

static inline zone_return_t
scan_class(zone_parser_t *par, zone_token_t *tok)
{
  uint32_t class;

  assert(tok->code == ZONE_STRING);

  // FIXME: unescape here first!
  if ((class = zone_is_class(tok->string.data, tok->string.length)) > 0)
    goto done;
  // support unknown DNS class (rfc 3597)
  if (tok->string.length < 5)
    return 0;
  if (strncasecmp(tok->string.data, "CLASS", 5) != 0)
    return 0;

  if (tok->string.length == 5)
    SYNTAX_ERROR(par, "Invalid class at {l}, missing class number");

  class = 0;
  for (size_t i = 5; i < tok->string.length; i++) {
    uint8_t c = tok->string.data[i];
    if (c < '0' || c > '9')
      SYNTAX_ERROR(par, "Invalid class at {l}, non-digit in class number");
    class = add(multiply(class, 10, UINT16_MAX), (uint32_t)c - '0', UINT16_MAX);
    if (class > UINT16_MAX)
      SYNTAX_ERROR(par, "Invalid class at {l}, class number exceeds maximum");
  }

done:
  assert(class <= UINT16_MAX);
  tok->int16 = (uint16_t)class;
  return tok->code = ZONE_CLASS | ZONE_INT16;
}

static inline zone_return_t
scan_ttl(zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t ret;
  uint32_t ttl;

  if ((ret = zone_parse_ttl(par, tok, &ttl)) < 0)
    return ret;
  assert(ttl <= INT32_MAX);
  tok->int32 = ttl;
  return tok->code = ZONE_TTL | ZONE_INT32;
}

static inline zone_return_t
scan_rr(zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t code = 0;

  // TYPE bit must always be set as state would be ZONE_BACKSLASH_HASH or
  // ZONE_SVC_PRIORITY if TYPE had been previously encountered
  assert(par->state & ZONE_TYPE);

  if ((code = scan_type(par, tok)) > 0) {
    par->state &= ~ZONE_RR;
    assert(tok->code == (ZONE_TYPE|ZONE_INT16));
    if (tok->int16 == 64 || tok->int16 == 65)
      par->state |= ZONE_SVC_PRIORITY;
    else
      par->state |= ZONE_BACKSLASH_HASH;
  } else if ((par->state & ZONE_CLASS) && (code = scan_class(par, tok)) > 0) {
    par->state &= ~ZONE_CLASS;
    assert(tok->code == (ZONE_CLASS|ZONE_INT16));
  } else if ((par->state & ZONE_TTL) && (code = scan_ttl(par, tok)) > 0) {
    par->state &= ~ZONE_TTL;
    assert(tok->code == (ZONE_TTL|ZONE_INT32));
  }

  if (!code) {
    assert(tok->code == ZONE_STRING);
    const char *expect = "type";
    if ((par->state & (ZONE_CLASS|ZONE_TTL)) == (ZONE_CLASS|ZONE_TTL))
      expect = "ttl, class or type";
    else if ((par->state & ZONE_TTL) == ZONE_TTL)
      expect = "ttl or type";
    else if ((par->state & ZONE_CLASS) == ZONE_CLASS)
      expect = "class or type";
    SYNTAX_ERROR(par, "Invalid item at {l}, expected %s", expect);
  }

  return code;
}

static inline zone_return_t
scan_rdata(zone_parser_t *par, zone_token_t *tok)
{
  zone_code_t code = 0;
  const uint32_t state = zone_item(par->state);
  uint64_t num = 0;

  switch (state) {
    case ZONE_BACKSLASH_HASH:
    case ZONE_SVC_PRIORITY:
      assert((tok->code & ZONE_STRING) == ZONE_STRING);
      // flip GENERIC_DATA flag and transition to rdlength if "\#" is found
      if (tok->string.length == 2 && strncmp(tok->string.data, "\\#", 2) == 0) {
        par->state = ZONE_RDLENGTH | ZONE_GENERIC_RDATA | (par->state & ~ZONE_ITEM_MASK);
        return (tok->code |= ZONE_BACKSLASH_HASH);
      } else if (state == ZONE_SVC_PRIORITY) {
        par->state = ZONE_TARGET_NAME | (par->state & ~ZONE_ITEM_MASK);
        return (tok->code |= ZONE_SVC_PRIORITY);
      } else {
        assert(!(par->state & ZONE_GENERIC_RDATA));
        par->state = ZONE_RDATA | (par->state & ~ZONE_ITEM_MASK);
        return (tok->code |= ZONE_RDATA);
      }
    case ZONE_RDLENGTH:
      assert((tok->code & ZONE_STRING) == ZONE_STRING);
      assert(par->state & ZONE_GENERIC_RDATA);
      if ((code = zone_parse_int(par, NULL, tok, UINT16_MAX, &num)) < 0)
        return code;
      assert(num <= UINT16_MAX);
      par->state = ZONE_RDATA | (par->state & ~ZONE_ITEM_MASK);
      tok->int16 = (uint16_t)num;
      return (tok->code = (ZONE_RDLENGTH | ZONE_INT16));
    case ZONE_TARGET_NAME:
      assert((tok->code & ZONE_STRING) == ZONE_STRING);
      par->state = ZONE_SVC_PARAM | (par->state & ~ZONE_ITEM_MASK);
      return (tok->code |= ZONE_TARGET_NAME);
    case ZONE_SVC_PARAM:
      assert((tok->code & ZONE_SVC_PARAM) == ZONE_SVC_PARAM);
      return (tok->code |= ZONE_SVC_PARAM);
    default:
      assert(state == ZONE_RDATA);
      assert((tok->code & ZONE_STRING) == ZONE_STRING);
      return (tok->code |= ZONE_RDATA);
  }
}

zone_return_t
zone_scan(zone_parser_t *par, zone_token_t *tok)
{
  zone_code_t code;

  do {
    code = scan(par, tok);
    if (code == ZONE_NEED_REFILL) {
      code = refill(par);
    } else if (code == '(') {
      if (par->state & ZONE_GROUPED)
        SYNTAX_ERROR(par, "Nested braces");
      // parentheses are not allowed within control entries, require blank or
      // resource record line
      if (par->state == ZONE_INITIAL)
        par->state = ZONE_OWNER;
      par->state |= ZONE_GROUPED;
    } else if (code == ')') {
      if (!(par->state & ZONE_GROUPED))
        SYNTAX_ERROR(par, "Closing brace without opening brace");
      par->state &= ~ZONE_GROUPED;
      assert(par->state != ZONE_INITIAL);
    } else if (code == ' ') {
      const uint32_t state = zone_item(par->state);
      assert(state == ZONE_INITIAL || state == ZONE_OWNER);
      par->state = ZONE_RR | (par->state & ~ZONE_ITEM_MASK);
    } else if (code == '\0') {
      if (par->state & ZONE_GROUPED)
        SYNTAX_ERROR(par, "Unexpected end-of-file, expected closing brace");
      return code;
    } else if (code == '\n') {
      // discard newlines within parentheses
      if (par->state & ZONE_GROUPED)
        continue;
      par->state = ZONE_INITIAL;
      return code;
    } else if (code > 0) {
      assert((code & ZONE_STRING) == ZONE_STRING ||
             (code & ZONE_SVC_PARAM) == ZONE_SVC_PARAM);
      if (par->state == ZONE_INITIAL || zone_item(par->state) == ZONE_OWNER) {
        tok->code = (code |= ZONE_OWNER);
        par->state = ZONE_RR | (par->state & ~ZONE_ITEM_MASK);
        return code;
      } else if (zone_item(par->state) & ZONE_RR) {
        return scan_rr(par, tok);
      } else {
        return scan_rdata(par, tok);
      }
    }
  } while (code == ZONE_NEED_REFILL);

  return code;
}
