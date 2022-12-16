/*
 * parser.h -- recursive descent parser for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef PARSER_H
#define PARSER_H
#include <stdlib.h>
#include <arpa/inet.h>
#include <strings.h>

#include "scanner.h"
#include "lookup.h"

extern const zone_table_t *zone_types;

// then the parser functions will be declared here

#define OWNER (0)
#define TYPE (1)
#define CLASS (2)
#define TTL (3)
#define RDATA (4)

typedef zone_return_t(*rdata_print_t)(
  zone_parser_t *, zone_field_t *);

struct rdata_descriptor {
  zone_field_info_t info;
  rdata_print_t print;
};

typedef struct type_descriptor type_descriptor_t;
struct type_descriptor {
  zone_type_info_t info;
  const struct rdata_descriptor *rdata;
  zone_return_t (*parse)(zone_parser_t *, const type_descriptor_t *, void *);
};

static inline uint64_t is_unit(char c)
{
  static const uint32_t s = 1u, m = 60u*s, h = 60u*m, d = 24u*h, w = 7u*d;

  switch (c) {
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

#define MAYBE_ERROR(parser, code, ...) \
  do { \
    if (parser->state.scanner & ZONE_RR) \
      return 1; \
    zone_error(parser, __VA_ARGS__); \
    return code; \
  } while (0)

#define MAYBE_SYNTAX_ERROR(parser, ...) \
  MAYBE_ERROR(parser, ZONE_SYNTAX_ERROR, __VA_ARGS__)

#define MAYBE_SEMANTIC_ERROR(parser, ...) \
  MAYBE_ERROR(parser, ZONE_SEMANTIC_ERROR, __VA_ARGS__)

static inline zone_return_t scan_ttl(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token,
  uint32_t *seconds)
{
  uint64_t value = 0, unit = 0, number, factor = 0;
  enum { NUMBER, UNIT } state = NUMBER;

  // FIXME: assert dsc refers to TTL!

  // ttls must start with a number
  number = token->string.data[0] - '0';
  if (number > 9)
    MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s", descriptor->name);

  for (size_t i=1; i < token->string.length; i++) {
    const uint64_t digit = token->string.data[i] - '0';

    switch (state) {
      case NUMBER:
        if (digit <= 9) {
          number = (number * 10) + digit;
          if (value > INT32_MAX)
            MAYBE_SEMANTIC_ERROR(parser, "Invalid ttl in %s, exceeds maximum",
              descriptor->name);
        } else if ((factor = is_unit(token->string.data[i]))) {
          // units must not be repeated e.g. 1m1m
          if (unit == factor)
            MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s, reuse of unit %c",
              descriptor->name, token->string.data[i]);
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (unit && unit < factor)
            MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s, unit %c follows smaller unit",
              descriptor->name, token->string.data[i]);
          unit = factor;
          number = number * unit;
          state = UNIT;
        } else {
          MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s, invalid unit",
            descriptor->name);
        }
        break;
      case UNIT:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (digit > 9)
          MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s, non-digit follows unit",
            descriptor->name);
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (unit == 1)
          MAYBE_SYNTAX_ERROR(parser, "Invalid ttl in %s, digit follows unit s",
            descriptor->name);
        value = value + number;
        number = digit;
        state = NUMBER;
        break;
    }
  }

  value = value + number;
  // FIXME: comment RFC2308 msb
  if (value > INT32_MAX)
    MAYBE_SEMANTIC_ERROR(parser, "Invalid ttl in %s, exceeds maximum",
      descriptor->name);
  *seconds = value;
  return 0;
}

static inline zone_return_t scan_name(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token,
  uint8_t octets[256],
  size_t *length)
{
  size_t label = 0, octet = 1;

  (void)parser;

  for (size_t i=0; i < token->string.length; i++) {
    if (octet >= 255)
      SYNTAX_ERROR(parser, "Invalid name in %s, name exceeds maximum",
        descriptor->name);

    // FIXME: account for newlines and escaped characters!

    switch (token->string.data[i]) {
      case '.':
        if (octet - 1 == label)
          SYNTAX_ERROR(parser, "Invalid name in %s, empty label",
            descriptor->name);
        // fall through
      case '\0':
        if ((octet - 1) - label > 63)
          SYNTAX_ERROR(parser, "Invalid name in %s, label exceeds maximum",
            descriptor->name);
        octets[label] = (octet - label) - 1;
        if (token->string.data[i] != '.')
          break;
        label = octet;
        octets[octet++] = 0;
        break;
      default:
        octets[octet++] = token->string.data[i];
        break;
    }
  }

  *length = octet;
  return 0;
}

static inline zone_return_t scan_type(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token,
  uint16_t *code)
{
  zone_symbol_t *symbol;

  if (!(symbol = zone_lookup(zone_types, &token->string)))
    goto unknown_type;
  assert(symbol->value <= UINT16_MAX);
  *code = (uint_fast16_t)symbol->value;
  return 0;
unknown_type:
  // support unknown DNS record types, see RFC3597
  if (token->string.length <= 4 || strncasecmp(token->string.data, "TYPE", 4) != 0)
    goto bad_type;

  uint64_t v = 0;
  for (size_t i=4; i < token->string.length; i++) {
    const uint64_t n = token->string.data[i] - '0';
    if (n > 9)
      goto bad_type;
    v = (v * 10) + n;
    if (v > UINT16_MAX)
      goto bad_type;
  }

  *code = (uint16_t)v;
  return 0;
bad_type:
  MAYBE_SYNTAX_ERROR(parser, "Invalid type in %s", descriptor->name);
}

static inline zone_return_t scan_class(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token,
  uint16_t *code)
{
  if (token->string.length != 2)
    goto unknown_class;
  else if (strncasecmp(token->string.data, "IN", 2) == 0)
    *code = 1;
  else if (strncasecmp(token->string.data, "CH", 2) == 0)
    *code = 2;
  else if (strncasecmp(token->string.data, "CS", 2) == 0)
    *code = 3;
  else if (strncasecmp(token->string.data, "HS", 2) == 0)
    *code = 4;
  else
    goto bad_class;

  return 0;
unknown_class:
  // support unknown DNS classes, see RFC3597
  if (token->string.length <= 5 || strncasecmp(token->string.data, "CLASS", 5) != 0)
    goto bad_class;

  uint64_t v = 0;
  for (size_t i=5; i < token->string.length; i++) {
    const uint64_t n = token->string.data[i] - '0';
    if (n > 9)
      goto bad_class;
    v = (v * 10) + n;
    if (v > UINT16_MAX)
      goto bad_class;
  }

  *code = (uint16_t)v;
  return 0;
bad_class:
  MAYBE_SYNTAX_ERROR(parser, "Invalid class in %s", descriptor->name);
}

static zone_return_t parse_ttl(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  uint32_t seconds = 0;
  zone_return_t result;

  if ((result = scan_ttl(parser, descriptor, token, &seconds)) < 0)
    return result;
  assert(seconds <= INT32_MAX);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl(seconds);
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

/* Number of days per month (except for February in leap years). */
static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static int is_leap_year(int year)
{
  return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int leap_days(int y1, int y2)
{
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
static time_t mktime_from_utc(const struct tm *tm)
{
  int year = 1900 + tm->tm_year;
  time_t days = 365 * (year - 1970) + leap_days(1970, year);
  time_t hours;
  time_t minutes;
  time_t seconds;
  int i;

  for (i = 0; i < tm->tm_mon; ++i) {
      days += mdays[i];
  }
  if (tm->tm_mon > 1 && is_leap_year(year)) {
      ++days;
  }
  days += tm->tm_mday - 1;

  hours = days * 24 + tm->tm_hour;
  minutes = hours * 60 + tm->tm_min;
  seconds = minutes * 60 + tm->tm_sec;

  return seconds;
}

static inline zone_return_t parse_time(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  char buf[] = "YYYYmmddHHMMSS";

  if (token->string.length >= sizeof(buf))
    SYNTAX_ERROR(parser, "Invalid time in %s", descriptor->name);
  memcpy(buf, token->string.data, token->string.length);
  buf[token->string.length] = '\0';

  const char *end = NULL;
  struct tm tm;
  if (!(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    SYNTAX_ERROR(parser, "Invalid time in %s", descriptor->name);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl(mktime_from_utc(&tm));
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

static inline zone_return_t parse_int8(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->string.length; i++) {
    const uint64_t n = token->string.data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT8_MAX)
      SEMANTIC_ERROR(parser, "Value in %s exceeds maximum", descriptor->name);
  }

  parser->rdata[parser->rdlength] = (uint8_t)v;
  parser->rdlength += sizeof(uint8_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&descriptor->symbols, &token->string)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", descriptor->name);
  assert(symbol->value <= UINT8_MAX);
  parser->rdata[parser->rdlength] = (uint8_t)symbol->value;
  parser->rdlength += sizeof(uint8_t);
  return 0;
}

static inline zone_return_t parse_int16(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->string.length; i++) {
    const uint64_t n = token->string.data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT16_MAX)
      SEMANTIC_ERROR(parser, "Value for %s exceeds maximum", descriptor->name);
  }

  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)v);
  parser->rdlength += sizeof(uint16_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&descriptor->symbols, &token->string)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", descriptor->name);
  assert(symbol->value <= UINT16_MAX);
  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)symbol->value);
  parser->rdlength += sizeof(uint16_t);
  return 0;
}

static inline zone_return_t parse_int32(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->string.length; i++) {
    const uint64_t n = token->string.data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT32_MAX)
      SEMANTIC_ERROR(parser, "Value for %s exceeds maximum", descriptor->name);
  }

  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl((uint32_t)v);
  parser->rdlength += sizeof(uint32_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&descriptor->symbols, &token->string)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", descriptor->name);
  assert(symbol->value <= UINT16_MAX);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl((uint32_t)symbol->value);
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

static inline zone_return_t parse_ip4(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  char buf[INET_ADDRSTRLEN + 1];

  if (token->string.length > INET_ADDRSTRLEN)
    SYNTAX_ERROR(parser, "Invalid IPv4 address in %s", descriptor->name);
  memcpy(buf, token->string.data, token->string.length);
  buf[token->string.length] = '\0';
  if (inet_pton(AF_INET, buf, &parser->rdata[parser->rdlength]) != 1)
    SYNTAX_ERROR(parser, "Invalid IPv4 address in %s", descriptor->name);
  parser->rdlength += sizeof(struct in_addr);
  return 0;
}

static inline zone_return_t parse_ip6(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  char buf[INET6_ADDRSTRLEN + 1];

  if (token->string.length > INET6_ADDRSTRLEN)
    SYNTAX_ERROR(parser, "Invalid IPv6 address in %s", descriptor->name);
  memcpy(buf, token->string.data, token->string.length);
  buf[token->string.length] = '\0';
  if (inet_pton(AF_INET6, buf, &parser->rdata[parser->rdlength]) != 1)
    SYNTAX_ERROR(parser, "Invalid IPv6 address in %s", descriptor->name);
  parser->rdlength += sizeof(struct in6_addr);
  return 0;
}

static inline zone_return_t parse_name(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  // a freestanding "@" denotes the current origin
  if (token->string.length == 1 && token->string.data[0] == '@') {
    memcpy(
     &parser->rdata[parser->rdlength],
      parser->file->origin.name.octets,
      parser->file->origin.name.length);
    parser->rdlength += parser->file->origin.name.length;
    return 0;
  }

  size_t length = 0;
  zone_return_t result;

  if ((result = scan_name(
    parser, descriptor, token,
    &parser->rdata[parser->rdlength],
    &length)) < 0)
    return result;
  parser->rdlength += length;
  if (parser->rdata[parser->rdlength - 1] != 0) {
    if (length >= 256 - parser->file->origin.name.length)
      SYNTAX_ERROR(parser, "Invalid name in %s, length exceeds maximum",
        descriptor->name);
    memcpy(&parser->rdata[parser->rdlength],
            parser->file->origin.name.octets,
            parser->file->origin.name.length);
    parser->rdlength += parser->file->origin.name.length;
  }

  return 0;
}

static inline zone_return_t parse_string(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  if (token->string.length > 255)
    SEMANTIC_ERROR(parser, "String in %s exceeds maximum length", descriptor->name);

  // FIXME: check if string contains newlines

  memcpy(&parser->rdata[parser->rdlength+1], token->string.data, token->string.length);
  parser->rdata[parser->rdlength] = (uint8_t)token->string.length;
  parser->rdlength += token->string.length + 1;
  return 0;
}

static inline zone_return_t parse_type(
  zone_parser_t *parser,
  const zone_field_info_t *descriptor,
  zone_token_t *token)
{
  uint16_t code;
  zone_return_t result;

  if ((result = scan_type(parser, descriptor, token, &code)) < 0)
    return result;
  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)code);
  parser->rdlength += sizeof(uint16_t);
  return 0;
}

static inline zone_return_t accept_rr(
  zone_parser_t *parser, void *user_data)
{
  return parser->options.accept(
    parser,
   &parser->items[OWNER],
   &parser->items[TTL],
   &parser->items[CLASS],
   &parser->items[TYPE],
    parser->rdata_items,
    parser->rdlength,
    parser->rdata,
    user_data);
}

#include "base16.h"
#include "base32.h"
#include "base64.h"
#include "nsec.h"
#include "grammar.h"

static inline zone_return_t parse_owner(
  zone_parser_t *parser, zone_token_t *token)
{
  static const zone_field_info_t descriptor =
    { "owner", 5, ZONE_OWNER|ZONE_NAME, 0, { 0 }, NULL };
  zone_return_t result;

  if ((result = scan_name(
    parser, &descriptor, token,
    parser->file->owner.name.octets,
   &parser->file->owner.name.length)) < 0)
    return result;

  // FIXME: definitely not correct
  parser->items[OWNER] = (zone_field_t){
    .code = ZONE_OWNER|ZONE_NAME,
    .length = parser->file->owner.name.length,
    .data = { .octets = parser->file->owner.name.octets } };
  return 0;
}

static zone_return_t maybe_type(zone_parser_t *parser, zone_token_t *token)
{
  zone_return_t result;
  static const zone_field_info_t info =
    { "type", 4, ZONE_TYPE|ZONE_INT16, 0, { 0 }, NULL };

  if ((result = scan_type(parser, &info, token, &parser->file->last_type)) < 0)
    return result;
  return ZONE_TYPE * !result;
}

static zone_return_t maybe_class(zone_parser_t *parser, zone_token_t *token)
{
  zone_return_t result;
  static const zone_field_info_t info =
    { "class", 5, ZONE_CLASS|ZONE_INT16, 0, { 0 }, NULL };

  if ((result = scan_class(parser, &info, token, &parser->file->last_class)) < 0)
    return result;
  return ZONE_CLASS * !result;
}

static zone_return_t maybe_ttl(
  zone_parser_t *parser, zone_token_t *token)
{
  zone_return_t result;
  static const zone_field_info_t info =
    { "ttl", 3, ZONE_TTL|ZONE_INT32, 0, { 0 }, NULL };

  if ((result = scan_ttl(parser, &info, token, &parser->file->last_ttl)) < 0)
    return result;
  return ZONE_TTL * !result;
}

typedef zone_return_t(*maybe_t)(zone_parser_t *, zone_token_t *);

static inline zone_return_t parse_rr(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  zone_return_t result;

  if (parser->file->start_of_line) {
    if ((result = parse_owner(parser, token)) < 0)
      return result;
    if ((result = lex(parser, token)) < 0)
      return result;
  }

  parser->state.scanner = ZONE_RR | (parser->state.scanner & GROUPED);

  int first = 0, last = 2;
  static const maybe_t maybe[3] =
    { maybe_ttl, maybe_type, maybe_class };
  static const char *expect[] =
    { "type", "ttl or type", "class or type", "ttl, class, or type" };

  do {
    zone_code_t item = 0;

    const int numeric = ((uint8_t)token->string.data[0] - '0' > 9);
    for (int i=(first || numeric); !item && i <= last; i++) {
      if ((item = maybe[i](parser, token)) < 0)
        return item;
    }

    parser->state.scanner &= ~item;

    if (item == ZONE_TYPE)
      break;
    else if (item == ZONE_TTL)
      first = 1;
    else if (item == ZONE_CLASS)
      last = 1;
    else
      SEMANTIC_ERROR(parser, "Invalid item, expected %s",
        expect[parser->state.scanner & (ZONE_TTL|ZONE_CLASS)]);

    if ((result = lex(parser, token)) < 0)
      return result;
  } while (1);

  parser->state.scanner = ZONE_RDATA | (parser->state.scanner & GROUPED);

  const struct type_descriptor *descriptor = &descriptors[*parser->items[TYPE].data.int16];

  parser->rdlength = 0;
  return descriptor->parse(parser, descriptor, user_data);

}

// RFC1035 section 5.1
// $INCLUDE <file-name> [<domain-name>] [<comment>]
static inline zone_return_t parse_dollar_include(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  (void)parser;
  (void)token;
  (void)user_data;
  NOT_IMPLEMENTED(parser, "$INCLUDE directive not implemented yet");
}

static inline zone_return_t parse_origin(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  zone_return_t result = scan_name(
    parser, info, token,
    parser->file->origin.name.octets,
   &parser->file->origin.name.length);
  if (result < 0)
    return result;

  // require a fully qualified domain name
  const size_t length = parser->file->origin.name.length;
  if (length == 0 || parser->file->origin.name.octets[length - 1] != 0)
    SEMANTIC_ERROR(parser, "Invalid name in %s, not fully qualified",
      info->name);

  return 0;
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
static inline zone_return_t parse_dollar_origin(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t info =
    { "$ORIGIN", 7, ZONE_DOLLAR_ORIGIN|ZONE_NAME, 0, { 0 }, NULL };

  zone_return_t result;

  (void)user_data;

  if ((result = lex(parser, token)) < 0)
    return result;
  if (result != 'c')
    SYNTAX_ERROR(par, "$ORIGIN directive takes a domain name");
  if ((result = parse_origin(parser, &info, token)) < 0)
    return result;
  if ((result = lex(parser, token)) < 0)
    return result;
  if (result != '\n' && result != '\0')
    SYNTAX_ERROR(par, "$ORIGIN directive takes just a single argument");

  return 0;
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
static inline zone_return_t parse_dollar_ttl(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t info =
    { "$TTL", 4, ZONE_INT32, 0, { 0 }, NULL };

  (void)user_data;
  zone_return_t result;

  if ((result = lex(parser, token)) < 0)
    return result;
  if ((result = scan_ttl(parser, &info, token, &parser->file->default_ttl)) < 0)
    return result;
  if ((result = lex(parser, token)) < 0)
    return result;
  if (result != '\n' && result != '\0')
    SYNTAX_ERROR(parser, "$TTL directive takes just a single argument");
  parser->file->last_ttl = parser->file->default_ttl;
  return 0;
}

static inline zone_return_t parse(zone_parser_t *parser, void *user_data)
{
  static const char ttl[] = "$TTL";
  static const char origin[] = "$ORIGIN";
  static const char include[] = "$INCLUDE";

  zone_token_t token;
  zone_return_t result = 0;

  do {
    switch ((result = lex(parser, &token))) {
      case 'c': // contiguous
        if (!parser->file->start_of_line || token.string.data[0] != '$')
          result = parse_rr(parser, &token, user_data);
        else if (token.string.length == sizeof(include) - 1 &&
                 strncasecmp(token.string.data, include, sizeof(include)-1) == 0)
          result = parse_dollar_include(parser, &token, user_data);
        else if (token.string.length == sizeof(origin) - 1 &&
                 strncasecmp(token.string.data, origin, sizeof(origin) - 1) == 0)
          result = parse_dollar_origin(parser, &token, user_data);
        else if (token.string.length == sizeof(ttl) - 1 &&
                 strncasecmp(token.string.data, ttl, sizeof(ttl) - 1) == 0)
          result = parse_dollar_ttl(parser, &token, user_data);
        else
          result = parse_rr(parser, &token, user_data);
        break;
      case 'q': // quoted (never a directive)
        result = parse_rr(parser, &token, user_data);
        break;
      case '\n':
        break;
      case '\0':
        return 0;
      default:
        break;
    }
  } while (result >= 0);

  // FIXME: set state to return on error!

  return result;
}

#if 0
static inline zone_return_t parse(zone_parser_t *parser, void *user_data)
{
  zone_token_t token;
  zone_return_t result;

  (void)user_data;

  while ((result = lex(parser, &token)) > 0) {
    if (result == '\n')
      printf("token: <newline>\n");
    else
      printf("token: '%.*s'\n", (int)token.string.length, token.string.data);
  }

  return result;
}
#endif

#endif // PARSER_H
