/*
 * scanner.h -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_SCANNER_H
#define ZONE_SCANNER_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "zone.h"

#define SYNTAX_ERROR(par, ...) \
  do { zone_error(par, __VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0)
#define SEMANTIC_ERROR(par, ...) \
  do { zone_error(par, __VA_ARGS__); return ZONE_SEMANTIC_ERROR; } while (0)

typedef zone_code_t zone_char_t;

typedef struct zone_string zone_string_t;
struct zone_string {
  zone_code_t code; // <LF>, <EOF>, ZONE_STRING
  const char *data;
  size_t length;
};

#define ZONE_ESCAPED (1<<12) // characters and strings
#define ZONE_DECIMAL (3<<12) // characters
#define ZONE_QUOTED (1<<10) // strings

// remove \DDD constructs from input. see RFC 1035, section 5.1
static inline size_t zone_unescape(
  const zone_string_t *zstr, char *str, size_t size)
{
  size_t len = 0;

  assert(zstr);
  assert(str);

  if (!(zstr->code & ZONE_ESCAPED)) {
    size_t len = size < zstr->length ? size : zstr->length;
    memmove(str, zstr->data, len);
    return len;
  }

  for (size_t cnt = len; len < size && cnt < zstr->length; ) {
    if (zstr->data[cnt] != '\\') {
      str[len++] = zstr->data[cnt];
      cnt += 1;
    } else if (zstr->length - cnt > 3 &&
              (zstr->data[cnt+1] >= '0' && zstr->data[cnt+1] <= '2') &&
              (zstr->data[cnt+2] >= '0' && zstr->data[cnt+2] <= '5') &&
              (zstr->data[cnt+3] >= '0' && zstr->data[cnt+3] <= '5'))
    {
      str[len++] = (zstr->data[cnt+1] - '0') * 100 +
                   (zstr->data[cnt+2] - '0') * 10  +
                   (zstr->data[cnt+3] - '0');
      cnt += 4;
    } else if (zstr->length - cnt > 1) {
      str[len++] = zstr->data[cnt+1];
      cnt += 2;
    } else {
      cnt += 1;
    }
  }

  return len;
}

static inline int zone_compare(
  const zone_string_t *zstr, const char *str, size_t len)
{
  assert(zstr && zstr->data);
  assert(str);

  size_t i1 = 0, i2 = 0;
  const char *s1 = zstr->data, *s2 = str;
  const size_t n1 = zstr->length, n2 = len;

  if (!(zstr->code & ZONE_ESCAPED)) {
    const size_t n = n1 < n2 ? n1 : n2;
    const int eq = strncasecmp(s1, s2, n);
    if (eq)
      return eq;
    return n1 < n2 ? -1 : (n1 > n2 ? +1 : 0);
  }

  for (; i1 < n1 && i2 < n2; i2++) {
    if ((s1[i1]|0x20) == (s2[i2]|0x20)) {
      i1++;
    } else if (s1[i1] != '\\') {
      return s1[i1] - s2[i2];
    } else {
      char c;
      size_t n;

      if (n1 - i1 > 3 && (s1[i1+1] >= '0' && s1[i1+1] <= '2') &&
                         (s1[i1+2] >= '0' && s1[i1+2] <= '5') &&
                         (s1[i1+3] >= '0' && s1[i1+3] <= '5'))
      {
        c = (s1[i1+1]-'0') * 100 + (s1[i1+2]-'0') * 10 + (s1[i1+3]-'0');
        n = 4;
      } else if (n1 - i1 > 1) {
        c = s1[i1+1];
        n = 2;
      } else {
        c = s1[i1];
        n = 1;
      }

      if ((c|0x20) == (s2[i2]|0x20))
        return c - s2[i2];
      i1 += n;
    }
  }

  if (i1 == n1 && i2 == n2)
    return 0;
  else if (i1 < n1)
    return -1;
  else
    return +1;
}


typedef struct zone_token zone_token_t;
struct zone_token {
  zone_location_t location;
  size_t cursor;
  union {
    // FIXME: remove connection between code and string...
    zone_code_t code;
    zone_string_t string;
  };
};

// scanner states
#define ZONE_INITIAL (0)
// ZONE_TTL
// ZONE_CLASS
// ZONE_TYPE
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)
// ZONE_OWNER
// ZONE_RDATA

// control directive states
#define ZONE_DOLLAR_INCLUDE (4 << 3)
#define ZONE_DOLLAR_ORIGIN (5 << 3)
#define ZONE_DOLLAR_TTL (6 << 3)

// secondary scanner states
#define ZONE_GROUPED (1<<24)
#define ZONE_GENERIC_RDATA (1<<25) // parsing generic rdata (RFC3597)
#define ZONE_DEFERRED_RDATA (1<<26)

// specialized return codes
#define ZONE_DEFER_ACCEPT (-50)

static inline void zone_flush(zone_parser_t *par, const zone_token_t *tok)
{
  assert(par && tok);
  assert(tok->cursor <= par->file->buffer.length);
  assert(tok->cursor >= par->file->buffer.offset);
  assert(tok->code == '\0' ||
         tok->cursor == tok->string.length +
           ((uint64_t)tok->string.data - (uint64_t)par->file->buffer.data));
  par->file->buffer.offset = tok->cursor + ((tok->code & ZONE_QUOTED) != 0);
  par->file->position = tok->location.end;
}

static inline zone_char_t zone_quick_peek(zone_parser_t *par, size_t cur)
{
  if (cur < par->file->buffer.length)
    return par->file->buffer.data[ cur ];
  return '\0'; // end-of-file
}

static inline zone_return_t zone_skip_space(zone_parser_t *par)
{
  assert(par);

  for (zone_char_t chr; ;) {
    switch ((chr = zone_quick_peek(par, par->file->buffer.offset))) {
      case ' ':
      case '\t':
        par->file->position.column += 1;
        par->file->buffer.offset += 1;
        break;
      case '\r':
        if (chr != '\r' || !(par->state.scanner & ZONE_GROUPED))
          return chr;
        par->file->position.line++;
        par->file->position.column = 1;
        par->file->buffer.offset += 1;
        // handle lf, cr and cr+lf consistently
        if (zone_quick_peek(par, par->file->buffer.offset + 1) != '\n')
          break;
        par->file->buffer.offset += 1;
        break;
      case '\n':
        if (chr != '\n' || !(par->state.scanner & ZONE_GROUPED))
          return chr;
        par->file->position.line++;
        par->file->position.column = 1;
        par->file->buffer.offset += 1;
        break;
      default:
        return chr;
    }
  }
}

static inline zone_return_t zone_skip_comment(zone_parser_t *par)
{
  assert(par);

  for (zone_char_t chr;;) {
    switch ((chr = zone_quick_peek(par, par->file->buffer.offset))) {
      case '\r':
      case '\n':
      case '\0':
        return chr;
      default:
        par->file->position.column += 1;
        par->file->buffer.offset += 1;
        break;
    }
  }
}

static inline zone_char_t zone_scan(
  zone_parser_t *par, zone_token_t *tok)
{
  assert(par && tok);

  tok->code = '\0';
  for (zone_char_t chr;;) {
    switch ((chr = zone_skip_space(par))) {
      case ';':
        chr = zone_skip_comment(par);
        assert(chr == '\r' || chr == '\n' || chr == '\0');
        break;
      case '\r':
        if ((chr = zone_quick_peek(par, par->file->buffer.offset + 1)) < 0)
          return chr;
        tok->code = '\n'; // handle lf, cr and cr+lf consistently
        tok->string.data = par->file->buffer.data + par->file->buffer.offset;
        tok->string.length = 1 + (chr == '\n');
        tok->cursor = par->file->buffer.offset + tok->string.length;
        goto token;
      case '\n':
        tok->code = '\n';
        tok->string.data = par->file->buffer.data + par->file->buffer.offset;
        tok->string.length = 1;
        tok->cursor = par->file->buffer.offset + tok->string.length;
        goto token;
      case '(':
        if (par->state.scanner & ZONE_GROUPED)
          SYNTAX_ERROR(par, "Nested braces");
        par->state.scanner |= ZONE_GROUPED;
        par->file->buffer.offset++;
        par->file->position.column++;
        break;
      case ')':
        if (!(par->state.scanner & ZONE_GROUPED))
          SYNTAX_ERROR(par, "Closing brace without opening brace");
        par->state.scanner &= ~ZONE_GROUPED;
        par->file->buffer.offset++;
        par->file->position.column++;
        break;
      case '\0':
        tok->code = '\0';
        tok->string.data = NULL;
        tok->string.length = 0;
        tok->cursor = par->file->buffer.offset;
        goto token;
      case '"':
        tok->code = ZONE_STRING | ZONE_QUOTED;
        tok->string.data = par->file->buffer.data + par->file->buffer.offset + 1;
        tok->string.length = 0;
        tok->cursor = par->file->buffer.offset + 1;
        goto token;
      default:
        if (chr < 0)
          return chr;
        tok->code = ZONE_STRING;
        tok->string.data = par->file->buffer.data + par->file->buffer.offset;
        tok->string.length = 0;
        tok->cursor = par->file->buffer.offset;
        goto token;
    }
  }

token:
  tok->location.begin = tok->location.end = par->file->position;
  return tok->code;
}

static inline zone_return_t zone_delimit(
  const zone_parser_t *par, zone_token_t *tok)
{
  assert(tok->cursor >= par->file->buffer.offset);
  assert(tok->cursor <= par->file->buffer.length);
  assert(tok->string.data >= par->file->buffer.data + par->file->buffer.offset);
  assert(tok->string.data <= par->file->buffer.data + tok->cursor);
  tok->string.length =
    tok->cursor - ((uintptr_t)tok->string.data - (uintptr_t)par->file->buffer.data);
  return 0;
}

static inline zone_return_t zone_get(
  zone_parser_t *par, zone_token_t *tok)
{
  assert(par && tok && (tok->code & ZONE_STRING));

  zone_char_t chr;

  switch ((chr = zone_quick_peek(par, tok->cursor))) {
    case ';':
    case '(':
    case ')':
    case ' ':
    case '\t':
      if (!(tok->code & ZONE_QUOTED))
        return zone_delimit(par, tok);
      tok->cursor++;
      tok->location.end.column++;
      return chr;
    case '"':
      if (!(tok->code & ZONE_QUOTED))
        return zone_delimit(par, tok);
      tok->location.end.column++;
      return zone_delimit(par, tok);
    case '\r': // handle cr+lf consistently, but return separately in string
      if (!(tok->code & ZONE_QUOTED))
        return zone_delimit(par, tok);
      if ((chr = zone_quick_peek(par, tok->cursor + 1)) < 0)
        return chr;
      tok->cursor++;
      if (chr == '\n') {
        tok->location.end.column++;
      } else {
        tok->location.end.line++;
        tok->location.end.column = 1;
      }
      return '\r';
    case '\n':
      if (!(tok->code & ZONE_QUOTED))
        return zone_delimit(par, tok);
      tok->cursor++;
      tok->location.end.line++;
      tok->location.end.column = 1;
      return chr;
    case '\0':
      return zone_delimit(par, tok);
    case '\\':
      break; // escaped character, slow path
    default:
      tok->cursor++;
      tok->location.end.column++;
      return chr;
  }

  tok->code |= ZONE_ESCAPED;

  switch ((chr = zone_quick_peek(par, tok->cursor + 1))) {
    case '\r': // handle cr+lf consistently, but return separately in string
      tok->cursor += 2;
      if (zone_quick_peek(par, tok->cursor + 2) == '\n') {
        tok->location.end.column++;
      } else {
        tok->location.end.line++;
        tok->location.end.column = 1;
      }
      return chr | ZONE_ESCAPED;
    case '\n':
      tok->cursor += 2;
      tok->location.end.line++;
      tok->location.end.column = 1;
      return chr | ZONE_ESCAPED;
    case '0':
    case '1':
    case '2':
      break;
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case '\0':
      goto bad_escape;
    default:
      tok->cursor += 2;
      tok->location.end.column += 2;
      return chr | ZONE_ESCAPED;
  }

  zone_char_t esc, unesc = chr - '0';
  for (size_t cnt = 2; cnt < 4; cnt++) {
    switch ((esc = zone_quick_peek(par, tok->cursor + cnt))) {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
        unesc *= 10;
        unesc += esc - '0';
        break;
      default:
        goto bad_escape;
    }
  }

  tok->cursor += 4;
  tok->location.end.column += 4;
  return unesc | ZONE_DECIMAL;
bad_escape:
  if (!(par->options.flags & ZONE_LENIENT))
    SYNTAX_ERROR(par, "Invalid escape sequence");
  tok->cursor += 2;
  tok->location.end.column += 2;
  return chr | ZONE_ESCAPED;
}

// FIXME: implement zone_unget

static inline zone_return_t zone_lex(
  zone_parser_t *par, zone_token_t *tok)
{
  zone_char_t chr;

  while ((chr = zone_get(par, tok)) > 0)
    ;

  return chr;
}

#endif // ZONE_SCANNER_H
