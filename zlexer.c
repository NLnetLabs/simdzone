/*
 * zlexer.c -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2001-2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "zonec.h"

static int32_t syntax_error(const char *fmt, ...)
{
  // throw error
  return SYNTAX_ERROR;
}

#define REFILL() \
  do { return ZONE_NEED_REFILL; } while (0);
#define SYNTAX_ERROR(...) \
  do { syntax_error(__VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0);

static inline int32_t
scan_comment(
  const parser_t *restrict parser,
  token_t *restrict token,
  size_t *length)
{
  int32_t chr;
  size_t cnt = 0;

  chr = peek(par, cnt);
  assert(chr == ';');

  token->end = token->begin = parser->position;
  for (cnt++; (chr = peek(parser, cnt)) > '\0'; cnt++) {
    if (chr == '\n' || chr == '\r')
      break;
    token->end.column++;
  }

  if (chr < 0)
    return chr;
  token->value.comment.data = parser->buffer.data + parser->buffer.cursor;
  token->value.comment.length = cnt;
  return (token->code = ';');
}

static inline int32_t
scan_quoted_string(
  const parser_t *restrict parser,
  token_t *restrict token,
  size_t *length)
{
  int32_t chr;
  size_t cnt = 0;
  static const char *fmt =
    "Unexpected end-of-file, expected closing quote at %y";

  chr = peek(parser, cnt);
  assert(chr == '"');

  token->location.end = token->location.begin = parser->position;
  for (cnt++; (chr = peek(parser, cnt)) >= '\0'; cnt++) {
    switch (chr) {
      case '\0':
        return syntax_error(parser, fmt, &token->location.end);
      case '\r':
        chr = peek(parser, cnt + 1);
        if (chr < 0)
          return chr;
        cnt += (chr == '\n');
        // fall through
      case '\n':
        token->location.end.line++;
        token->location.end.column = 1;
        esc = 0;
        break;
      case '\\':
        token->location.end.column++;
        esc = token->escaped = 1;
        break;
      case '\"':
        if (!esc) {
          token->location.end.column++;
          token->value.string.data = parser->buffer.data + parser->buffer.cursor;
          token->value.string.length = cnt - 2;
          return (token->code = STRING);
        }
        // fall through
      default:
        token->location.end.column++;
        esc = 0;
        break;
    }
  }

  assert(chr < '\0');
  return chr;
}

static inline int32_t
scan_string(
  const parser_t *restrict parser,
  token_t *restrict token,
  size_t *length)
{
  int32_t chr, esc = 0;
  size_t cnt = 0;
  static const char delim[] = ";()\n\r \t\"";

  chr = peek(parser, cnt);
  assert(chr && !strchr(delim, chr));

  token->location.end = token->location.begin = parser->position;
  for (cnt++; (chr = peek(parser, cnt)) > '\0'; cnt++) {
    if (chr == '\\')
      esc = token->escaped = 1;
    else if (esc)
      esc = 0;
    else if (strchr(delim, chr))
      break;
    token->location.end.column++;
  }

  if (chr < 0)
    return chr;
  *length = cnt;
  token->value.string.date = parser->buffer.data + parser->buffer.cursor;
  token->value.string.length = cnt;
  return (token->code = STRING);
}

// zone file scanner is implemented as a 2 stage process. 1st stage scans for
// tokens without grouping context or recognizing ttl, class, type or rdata.
// comments and (quoted) character strings are converted to a single token,
// special characters are returned as individual tokens. delimiters are
// discarded unless they serve to signal an implicit owner.
static inline int32_t
scan_raw(parser_t *restrict parser, token_t *restrict token)
{
  size_t cnt = 0;
  int32_t code = ' ';

  do {
    int32_t chr = peek(parser, 0);
    if (chr == ';') {
      code = scan_comment(parser, token, &cnt);
    } else if (chr == '"') {
      code = scan_quoted_string(parser, token, &cnt);
    } else {
      cnt = 1;
      if (chr == '(' || chr == ')') {
        code = chr;
      } else if (chr == '\r') { // CR+LF (Windows) or CR (Macintosh)
        chr = peek(parser, cnt + 1);
        cnt += (chr == '\n');
        if (chr < 0)
          code = chr;
        else
          code = '\n'; // handle end-of-line consistently
      } else if (chr == '\n') { // LF (UNIX)
        code = '\n';
      } else if (chr != ' ' && chr != '\t') {
        code = scan_string(parser, token, &cnt);
        goto eval;
      } else {
        code = ' '; // handle tabs and spaces consistently
      }

      token->code = code;
      token->end = token->begin = parser->position;
      if (code == '\n') {
        token->end = token->begin = parser->position;
        token->end.line++;
        token->end.column = 1;
      } else if (code > 0) {
        token->end.column++;
      }
    }
eval:
    if (code < 0)
      return code;
    // do not update cursor on end-of-file
    if (code > 0)
      parser->buffer.cursor += cnt;
    parser->position = token->end;
    // any combination of tabs and spaces act as a delimiter between the
    // separate items that make up an entry, but in order to signal an
    // implicit owner to the parser a space is returned if the state is
    // INITIAL.
  } while (code == ' ' && parser->state != INITIAL);

  return code;
}

// remove \DDD constructs from the input. see RFC 1035, section 5.1
static inline int32_t
unescape(parser_t *restrict parser, token_t *restrict token)
{
  assert(token->code == STRING);
  assert(token->escaped);

  // increase local buffer if required
  if (token->buffer.size < token->value.string.length) {
    // alloc
    // check for errors
  }

  // make into do-while
  char *dest = token->buffer.data;
  const char *s = token.value.string.data;
  for (size_t i = 0, j = 0, n = token.value.string.length; i < n; ) {
    if (s[i] != '\\') {
      dest[j] = src[i];
      i += 1;
    } else if (n - i >= 4 && !(s[i+1] < '0' || s[i+1] > '9') &&
                             !(s[i+2] < '0' || s[i+2] > '9') &&
                             !(s[i+3] < '0' || s[i+3] > '9'))
    {
      uint32_t x = (s[i+1] - '0') * 100 +
                   (s[i+2] - '0') *  10 +
                   (s[i+3] - '0') *   1;
      if (x <= 255) {
        i += 4;
        dest[j++] = (uint8_t)x;
      } else {
        i += 1;
        // syntax error!!!!
      }
    } else if (n - i >= 1) {
      dest[j++] = s[i+1];
      i += 2;
    } else {
      // trailing backslash, ignore
      assert(n - i == 0);
    }
  }

  token->value.string.data = token->buffer.data;
  token->value.string.length = j;
  return STRING;
}

//
// we split the type lookup table from the rrtype descriptor table?
//
static inline int compare(const token_t *token, const char *type)
{
  //
  // lets just use the bsearch algorithm here to map the rrtype
  // to a numeric identifier!
  //
  return strncasecmp(token.value.string.data, type, token.value.string.length);
  // cannot use strncasecmp here!!!!
}

static inline int32_t
have(const parser_t *restrict parser, const token_t *restrict token, const uint8_t *string)
{
  // simple compare
}

static inline int32_t
have_type(parser_t *restrict parser, token_t *restrict token)
{
  int32_t type;

  assert(token->code == STRING);
  assert(!token->escaped);

  type = rrtype_by_name(
    token->value.string.data, token->value.string.length, &token->value.type);
  if (type >= 0)
    return token->code = TYPE;
  if (token->value.string.length < 5)
    return 0;
  if (strncasecmp(token->value.string.data, "TYPE", 4) != 0)
    return 0;

  type = 0;
  for (size_t i = 4; i < token->value.string.length && type <= 65535; i++) {
    uint8_t c = token->value.string.data[i];
    if (c < '0' || c > '9')
      return 0;
    type *= 10;
    type += (int32_t)(c - '0');
  }

  if (!type || type > 65535)
    return 0;
  token->value.type = (uint16_t)type;
  return token->code = TYPE;
}

static inline int32_t
have_class(parser_t *restrict parser, token_t *restrict token)
{
  int32_t class;

  assert(token->code == STRING);
  assert(!token->escaped);

  class = strtoclass(
    token->value.string.data, token->value.string.length, &token->value.class);
  if (class >= 0)
    return token->code = CLASS;
  if (token->value.string.length < 6)
    return 0;
  if (strncasecmp(token->value.string.data, "CLASS", 5) != 0)
    return 0;

  class = 0;
  for (size_t i = 5; i < token->value.string.length && class <= 65535; i++) {
    uint8_t c = token->value.string.data[i];
    if (c < '0' || c > '9')
      return 0;
    class *= 10;
    class += (int32_t)(c - '0');
  }

  if (!class || class > 65535)
    return 0;
  token->value.class = (uint16_t)class;
  return token->code = CLASS;
}

static inline int32_t
have_ttl(const parser_t *restrict parser, const token_t *restrict token)
{
  int32_t ttl;

  ttl = strtottl(
    token->value.string.data, token->value.string.length, &token->value.ttl);
  return (ttl >= 0) ? token->code = TTL : 0;
}

static inline int32_t
scan_rr(parser_t *restrict parser, token_t *restrict token)
{
  // TYPE bit must always be set as state would be RDATA if TYPE had been
  // previously encountered
  assert(parser->state & TYPE);
  assert(!token->escaped);

  if (have_type(parser, token)) {
    parser->state &= ~RR;
    parser->state |= RDATA;
    assert(token->code == TYPE);
  } else if ((parser->state & CLASS) && have_class(parser, token)) {
    parser->state &= ~CLASS;
    assert(token->code == CLASS);
  } else if ((parser->state & TTL) && have_ttl(parser, token)) {
    parser->state &= ~TTL;
    assert(token->code == TTL);
  } else {
    // >> syntax error!
    // >> we only handle the TTL and CLASS here (nope)
    // >> an unknown entry in place of the TYPE is simply promoted (nope)
    //    upwards as type, it's up to the level above that to interpret it
    //    correctly
    //parser->state &= ~RR;
    //parser->state |= RDATA;
    //return token->code = STRING;
    return syntax_error();
  }

  return token->code;
}

// this function is to handle global state only.
// parsing of owner, rr, etc should be done in separate functions
// actually, in a function that just calls this one...
//
// this function is the equivalent of yylex, it should just fill the token
// and return the type of token
// based on that the parser validates rrdata and creates the actual record!

//
// we simply call scan in a loop and generate records
//
// internal scan function only recognizes basic tokens, what fields
// we're actually parsing is determined below
//

// we should account for rfc3597
// https://www.rfc-editor.org/rfc/rfc3597

int32_t scan(parser_t *restrict parser, token_t *restrict token)
{
  int32_t code;
  token_t tok;
  uint32_t state;
  uint32_t seen = 0u;

  for (;;) {
    code = scan_raw(par, &tok);

    if (code < 0) {
      return code;
    } else if (code == '(') {
      if (parser->state & GROUPED)
        return syntax_error("Nested braces");
      // parentheses are not allowed within control entries, require blank or
      // resource record line
      if (parser->state == INITIAL)
        parser->state = OWNER;
      parser->state |= GROUPED;
    } else if (code == ')') {
      if (!(parser->state & GROUPED))
        return syntax_error("Closing brace without opening brace");
      parser->state &= ~GROUPED;
      assert(parser->state != INITIAL);
    } else if (code = ' ') {
      const uint32_t state = parser->state & ~GROUPED;
      assert(state == INITIAL || state == OWNER);
      parser->state = RR | (parser->state & GROUPED);
      return code;
    } else if (code = '\0') {
      if (parser->state & GROUPED)
        return syntax_error("Unexpected end-of-file, expected closing brace");
      return code;
    } else if (code == '\n') {
      // discard newlines within parentheses
      if (parser->state & GROUPED)
        continue;
      parser->state = INITIAL;
      return code;
    } else {
      const uint32_t state = parser->state & ~GROUPED;

      assert(code == STRING);

      if (state == INITIAL) {
        // actual control entries are handled in the calling function,
        // not here!!!!
        assert(!(parser->state & GROUPED));
        if (have(parser, token, "$ORIGIN")) {
          parser->state = ORIGIN_CONTROL;
        } else if (have(parser, token, "$INCLUDE")) {
          parser->state = INCLUDE_CONTROL;
        } else if (have(parser, token, "$TTL")) { // mention RFC!
          parser->state = TTL_CONTROL;
        } else if (token.value.string.length > 0 && token.value.string.data[0] == '$') {
          // warn about unsupported directive
          parser->state = UNKNOWN_CONTROL;
        } else {
          parser->state = OWNER;
        }

        state = parser->state;
      }

      if (state == OWNER) {
        int32_t err;

        // unescape token, i.e. resolve \DDD and \X
  //
  // we know the length of the token...
  // unescaped the current item first!
  //
  // the token has a local buffer associated with it to avoid memory allocations
  // >> this is the slow path
  //   >> it goes over the string again in order to unescape, let's assume that
  //      it doesn't occur very often
  //if (token->escaped && (err = unescape(parser, token)) < 0)
  //  return err;
 
        if ((err = unescape(parser, token)))
          return err;

        if (state == OWNER) {
          // right, so we make the owner the problem of the calling function
          // because they might want to buffer it slightly differently etc...
          token->code = OWNER;
          // we do need to unescape here!!!!
          parser->state = RR;
        } else if (state & RR) {
          return scan_rr(parser, token);
        } else {
          assert(state == RDATA);
          assert(token->code == STRING);
          return code;
        }
      }
    }
  }
}
