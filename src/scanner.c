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

#include "zone.h"

static void error(const zone_parser_t *par, const char *fmt, ...)
{
  assert(par);
  assert(fmt);
  // pending a proper implementation
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

#define SYNTAX_ERROR(parser, ...) \
  do { error(parser, __VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0);
#define SEMANTIC_ERROR(parser, ...) \
  do { error(parser, __VA_ARGS__); return ZONE_SEMANTIC_ERROR; } while (0);

static int32_t refill(const zone_parser_t *par)
{
  // FIXME: implement
  // x. take into account the offset and cursor
  (void)par;
  return ZONE_NO_MEMORY;
}

static int32_t peek(const zone_parser_t *par, size_t idx)
{
  assert(par);
  assert(par->file->buffer.cursor <= par->file->buffer.used);
  if (idx < par->file->buffer.used - par->file->buffer.cursor)
    return par->file->buffer.data.read[par->file->buffer.cursor + idx];
  return !par->file->handle || feof(par->file->handle) ? 0 : ZONE_NEED_REFILL;
}

static inline int32_t
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

static inline int32_t
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
          *len = cnt;
          assert(cnt >= off);
          tok->string.data = par->file->buffer.data.read + par->file->buffer.cursor + off + 1;
          tok->string.length = (cnt - off) - 2;
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

static inline int32_t
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

static inline int32_t
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

#include "types.h"

static inline void reset_token(const zone_parser_t *par, zone_token_t *tok)
{
  tok->location.end = tok->location.begin = par->file->position;
}

static inline int32_t scan_svcb(zone_parser_t *par, zone_token_t *tok)
{
  int32_t code = ' ';
  enum { PRIORITY = 0, TARGET_NAME, PARAMS } state;

  assert(par->state & ZONE_RDATA);
  // 8 least significant bits are reserved for specialized the RDATA scanners
  state = par->state & 0xf;

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
    } else if (state == PARAMS) {
      reset_token(par, tok);
      code = lex_svcparam(par, tok, 0, &cnt);
      goto eval;
    } else {
      assert(state == PRIORITY || state == TARGET_NAME);
      reset_token(par, tok);
      if (chr == '"')
        code = lex_quoted_string(par, tok, 0, &cnt);
      else
        code = lex_string(par, tok, 0, &cnt);
      par->state = (par->state & ~0xf) | (state ? PARAMS : TARGET_NAME);
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
static inline int32_t
scan(zone_parser_t *par, zone_token_t * tok)
{
  size_t cnt = 0;
  int32_t code = ' ';

  if ((par->state & ZONE_RDATA) && par->scanner)
    return par->scanner(par, tok);

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

static inline int32_t istype(const char *str, size_t len)
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
      return -1;
    case 'i':
    case 'I':
      if (len == 2 && strncasecmp(str, "IN", 2) == 0)
        return -1;
      break;
  }

  map = bsearch(
    &key, types, sizeof(types)/sizeof(types[0]), sizeof(types[0]), &mapcmp);
  if (map)
    return (int32_t)(map->type);
  return -1;
}


static inline int32_t multype(int32_t a, int32_t b)
{
  return (INT32_MAX / b > a) ? INT32_MAX : a * b;
}

static inline int32_t addtype(int32_t a, int32_t b)
{
  return (INT32_MAX - b) > a ? INT32_MAX : a + b;
}

static inline int32_t scan_type(zone_parser_t *par, zone_token_t *tok)
{
  int32_t type = -1;

  assert(tok->code == ZONE_STRING);
  assert(!tok->string.escaped);

  type = istype(tok->string.data, tok->string.length);
  if (type >= 0)
    goto found;
  // support unknown DNS resource record types (rfc 3597)
  if (tok->string.length < 4)
    return 0;
  if (strncasecmp(tok->string.data, "TYPE", 4) != 0)
    return 0;

  if (tok->string.length == 4)
    SYNTAX_ERROR(par, "Invalid type at {l}, missing type number");

  type = 0;
  for (size_t i = 4; i < tok->string.length && type <= 65535; i++) {
    uint8_t c = tok->string.data[i];
    if (c < '0' || c > '9')
      SYNTAX_ERROR(par, "Invalid type at {l}, non-digit in type number");
    type = addtype(multype(type, 10), (int32_t)(c - '0'));
  }

  if (type > 65535)
    SYNTAX_ERROR(par, "Invalid type at {l}, type number exceeds maximum");

found:
  tok->int16 = (uint16_t)type;
  return tok->code = ZONE_TYPE | ZONE_INT16;
}

static inline int32_t isclass(const char *str, size_t len)
{
  if (len != 2)
    return -1;
  if (strncasecmp(str, "IN", 2) == 0)
    return 1;
  if (strncasecmp(str, "CH", 2) == 0)
    return 2;
  if (strncasecmp(str, "CS", 2) == 0)
    return 3;
  if (strncasecmp(str, "HS", 2) == 0)
    return 4;
  return -1;
}

static inline uint16_t mulclass(int32_t a, int32_t b)
{
  return (INT32_MAX / b > a) ? INT32_MAX : a * b;
}

static inline uint16_t addclass(int32_t a, int32_t b)
{
  return (INT32_MAX - b > a) ? INT32_MAX : a + b;
}

static inline int32_t
scan_class(zone_parser_t *par, zone_token_t *tok)
{
  int32_t class = -1;

  assert(tok->code == ZONE_STRING);
  assert(!tok->string.escaped);

  class = isclass(tok->string.data, tok->string.length);
  if (class >= 0)
    goto found;
  if (tok->string.length < 5)
    return 0;
  if (strncasecmp(tok->string.data, "CLASS", 5) != 0)
    return 0;

  if (tok->string.length == 5)
    SYNTAX_ERROR(par, "Invalid class at {l}, missing class number");

  class = 0;
  for (size_t i = 5; i < tok->string.length && class <= 65535; i++) {
    uint8_t c = tok->string.data[i];
    if (c < '0' || c > '9')
      SYNTAX_ERROR(par, "Invalid class at {l}, non-digit in class number");
    class = addclass(mulclass(class, 10), (int32_t)c - '0');
  }

  if (class > 65535)
    SEMANTIC_ERROR(par, "Invalid class at {l}, class number exceeds maximum");
found:
  tok->int16 = (uint16_t)class;
  return tok->code = ZONE_CLASS | ZONE_INT16;
}

static inline uint32_t isunit(char chr)
{
  static const uint32_t s = 1u, m = 60u*s, h = 60u*m, d = 24u*h, w = 7u*d;

  switch (chr) {
    case 's':
    case 'S':
      return s;
    case 'm':
    case 'M':
      return m;
    case 'h':
    case 'H':
      return h;
    case 'd':
    case 'D':
      return d;
    case 'w':
    case 'W':
      return w;
  }

  return 0;
}

static inline uint32_t multtl(uint32_t a, uint32_t b)
{
  if ((uint32_t)INT32_MAX < a || (uint32_t)INT32_MAX / a < b)
    return (uint32_t)INT32_MAX + 1;
  return a * b;
}

static inline uint32_t addttl(uint32_t a, uint32_t b)
{
  if ((uint32_t)INT32_MAX < a || (uint32_t)INT32_MAX - a < b)
    return (uint32_t)INT32_MAX + 1;
  return a + b;
}


static inline int32_t
scan_ttl(zone_parser_t *par, zone_token_t *tok)
{
  uint32_t num = 0, secs = 0, fact = 0;
  enum { initial, number, unit } state = initial;

  for (size_t i = 0; i < tok->string.length; i++) {
    uint32_t u;
    const uint8_t c = tok->string.data[i];
    switch (state) {
      case initial:
        // ttls must start with a number
        if (c < '0' || c > '9')
          return 0;
        state = number;
        num = c - '0';
        break;
      case number:
        if (c >= '0' && c <= '9') {
          num = addttl(multtl(num, 10), c - '0');
        } else if ((u = isunit(c))) {
          // units must not be repeated e.g. 1m1m
          if (fact == u)
            SYNTAX_ERROR(par, "Invalid ttl at {l}, reuse of unit %c", c);
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (fact && fact < u)
            SYNTAX_ERROR(par, "Invalid ttl at {l}, unit %c follows smaller unit", c);
          num = multtl(num, (fact = u));
          state = unit;
        } else {
          SYNTAX_ERROR(par, "Invalid ttl at {l}, invalid unit %c", c);
        }
        break;
      case unit:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (c < '0' || c > '9')
          SYNTAX_ERROR(par, "Invalid ttl at {l}, non-digit follows unit");
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (fact == 1)
          SYNTAX_ERROR(par, "Invalid ttl at {l}, seconds already specified");
        secs = addttl(secs, num);
        num = c - '0';
        state = number;
        break;
    }
  }

  secs = addttl(secs, num);
  // FIXME: comment RFC2308 msb
  if (secs > (uint32_t)INT32_MAX)
    SEMANTIC_ERROR(par, "Invalid ttl at {l}, value exceeds maximum");
  tok->int32 = secs;
  return tok->code = ZONE_TTL | ZONE_INT32;
}

static inline int32_t
scan_rr(zone_parser_t *par, zone_token_t *tok)
{
  int32_t code;

  // TYPE bit must always be set as state would be RDATA if TYPE had been
  // previously encountered
  assert(par->state & ZONE_TYPE);
  assert(!tok->string.escaped);

  if ((code = scan_type(par, tok)) > 0) {
    par->state &= ~ZONE_RR;
    par->state |= ZONE_RDATA;
    assert(tok->code == (ZONE_TYPE|ZONE_INT16));
    if (tok->int16 == 64 || tok->int16 == 65)
      par->scanner = &scan_svcb;
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

// remove \DDD constructs from input. see RFC 1035, section 5.1
static inline int32_t
unescape(zone_parser_t *par, zone_string_t *str)
{
  char *buf = par->buffer.data;
  const char *s = str->data;
  size_t len = 0;

  // increase local buffer if required
  if (par->buffer.size < str->length) {
    if (!(buf = realloc(par->buffer.data, str->length)))
      return ZONE_NO_MEMORY;
    par->buffer.data = buf;
    par->buffer.size = str->length;
  }

  for (size_t i = 0, n = str->length; i < n; ) {
    if (s[i] != '\\') {
      buf[len++] = s[i];
      i += 1;
    } else if (n - i >= 4 && !(s[i+1] < '0' || s[i+1] > '2') &&
                             !(s[i+2] < '0' || s[i+2] > '5') &&
                             !(s[i+3] < '0' || s[i+3] > '5'))
    {
      buf[len++] = (s[i+1] - '0') * 100 +
                   (s[i+2] - '0') *  10 +
                   (s[i+3] - '0') *   1;
      i += 4;
    } else if (n - i >= 1) {
      buf[len++] = s[i+1];
      i += 2;
    } else {
      // trailing backslash, ignore
      assert(n - i == 0);
    }
  }

  str->data = buf;
  str->length = len;
  return 0;//ZONE_STRING;
}

int32_t
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
      const uint32_t state = par->state & ~ZONE_GROUPED;
      assert(state == ZONE_INITIAL || state == ZONE_OWNER);
      par->state = ZONE_RR | (par->state & ZONE_GROUPED);
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
      int32_t err;
      zone_code_t state = par->state & ~(ZONE_GROUPED | 0xff);
      zone_string_t *str = NULL;

      if (code == ZONE_SVC_PARAM)
        str = &tok->svc_param.value;
      else if (code == ZONE_STRING)
        str = &tok->string;
      assert(str);

      // unescape token, i.e. resolve \DDD and \X
      if (str->escaped && (err = unescape(par, str)))
        return err;

      if (state == ZONE_INITIAL || (state & ZONE_OWNER)) {
        tok->code = (code |= ZONE_OWNER);
        par->state = ZONE_RR;
        return code;
      } else if (state & ZONE_RR) {
        return scan_rr(par, tok);
      } else {
        assert(state == ZONE_RDATA);
        tok->code = (code |= ZONE_RDATA);
        return code;
      }
    }
  } while (code == ZONE_NEED_REFILL);

  return code;
}
