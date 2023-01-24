/*
 * parser.h -- recursive descent parser for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef PARSER_H
#define PARSER_H
#include <stdlib.h>
#include <arpa/inet.h>
#include <strings.h>

#include "scanner.h"
#include "table.h"

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

// FIXME: scan_ttl should fallback to recognizing units instead
zone_always_inline()
static inline zone_return_t scan_ttl(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  zone_token_t *token,
  uint32_t *seconds)
{
  uint64_t value = 0, unit = 0, number, factor = 0;
  enum { NUMBER, UNIT } state = NUMBER;

  // FIXME: assert dsc refers to TTL!

  // ttls must start with a number
  number = token->data[0] - '0';
  if (number > 9)
    SYNTAX_ERROR(parser, "Invalid ttl in %s", info->name.data);

  for (size_t i=1; i < token->length; i++) {
    const uint64_t digit = token->data[i] - '0';

    switch (state) {
      case NUMBER:
        if (digit <= 9) {
          number = (number * 10) + digit;
          if (value > INT32_MAX)
            SEMANTIC_ERROR(parser, "Invalid ttl in %s, exceeds maximum",
              info->name.data);
        } else if ((factor = is_unit(token->data[i]))) {
          // units must not be repeated e.g. 1m1m
          if (unit == factor)
            SYNTAX_ERROR(parser, "Invalid ttl in %s, reuse of unit %c",
              info->name.data, token->data[i]);
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (unit && unit < factor)
            SYNTAX_ERROR(parser, "Invalid ttl in %s, unit %c follows smaller unit",
              info->name.data, token->data[i]);
          unit = factor;
          number = number * unit;
          state = UNIT;
        } else {
          SYNTAX_ERROR(parser, "Invalid ttl in %s, invalid unit", info->name.data);
        }
        break;
      case UNIT:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (digit > 9)
          SYNTAX_ERROR(parser, "Invalid ttl in %s, non-digit follows unit",
            info->name.data);
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (unit == 1)
          SYNTAX_ERROR(parser, "Invalid ttl in %s, digit follows unit s",
            info->name.data);
        value = value + number;
        number = digit;
        state = NUMBER;
        break;
    }
  }

  value = value + number;
  // FIXME: comment RFC2308 msb
  if (value > INT32_MAX)
    SEMANTIC_ERROR(parser, "Invalid ttl in %s, exceeds maximum",
      info->name.data);
  *seconds = value;
  return ZONE_TTL;
}

extern const zone_table_t *zone_identifiers;
extern const zone_fast_table_t *zone_fast_identifiers;

zone_always_inline()
static inline uint8_t subs(uint8_t x, uint8_t y)
{
  uint8_t res = x - y;
  res &= -(res <= x);
  return res;
}

zone_always_inline()
static inline zone_return_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->data[n] & 0xdf);
  h *= 0x07;
  h += (uint8_t)token->length;

  const zone_fast_table_t *table = &zone_fast_identifiers[k];

  vector8x16_t keys;
  load_8x16(&keys, table->keys);
  const uint64_t bits = find_8x16(&keys, h) | (1u << 15);
  const uint64_t index = trailing_zeroes(bits);
  const zone_symbol_t *symbol = table->symbols[index];

  if (symbol &&
      token->length == symbol->key.length &&
      strncasecmp(token->data, symbol->key.data, symbol->key.length) == 0)
  {
    *code = symbol->value & 0xffffu;
    return symbol->value >> 16;
  }

  if (token->length > 4 &&
      strncasecmp(token->data, "TYPE", 4) == 0)
  {
    uint64_t v = 0;
    for (size_t i=4; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_type;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_type;
    }

    *code = (uint16_t)v;
    return ZONE_TYPE;
bad_type:
    SEMANTIC_ERROR(parser, "Invalid type in %s", info->name.data);
  }

  if (token->length > 5 &&
      strncasecmp(token->data, "CLASS", 5) == 0)
  {
    uint64_t v = 0;
    for (size_t i=5; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_class;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_class;
    }

    *code = (uint16_t)v;
    return ZONE_CLASS;
bad_class:
    SEMANTIC_ERROR(parser, "Invalid class in %s", info->name.data);
  }

  SEMANTIC_ERROR(parser, "Invalid type or class in %s", info->name.data);
}

zone_always_inline()
static inline zone_return_t scan_type(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->data[n] & 0xdf);
  h *= 0x07;
  h += (uint8_t)token->length;

  const zone_fast_table_t *table = &zone_fast_identifiers[k];

  vector8x16_t keys;
  load_8x16(&keys, table->keys);
  const uint64_t bits = find_8x16(&keys, h) | (1u << 15);
  const uint64_t index = trailing_zeroes(bits);
  const zone_symbol_t *symbol = table->symbols[index];

  if (symbol &&
      token->length == symbol->key.length &&
      strncasecmp(token->data, symbol->key.data, symbol->key.length) == 0)
  {
    *code = symbol->value & 0xffff;
    return symbol->value >> 16;
  }

  if (token->length > 4 &&
      strncasecmp(token->data, "TYPE", 4) == 0)
  {
    uint64_t v = 0;
    for (size_t i=4; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_type;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_type;
    }

    *code = (uint16_t)v;
    return ZONE_TYPE;
  }

bad_type:
  SEMANTIC_ERROR(parser, "Invalid type in %s", info->name.data);
}

static inline zone_return_t parse_type(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  uint16_t code;
  zone_return_t result;

  if ((result = scan_type(parser, info, token, &code)) < 0)
    return result;
  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)code);
  parser->rdlength += sizeof(uint16_t);
  return 0;
}

static inline zone_return_t scan_name(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  zone_token_t *token,
  uint8_t octets[256],
  size_t *length)
{
  size_t label = 0, octet = 1;

  (void)parser;

  for (size_t i=0; i < token->length; i++) {
    if (octet >= 255)
      SYNTAX_ERROR(parser, "Invalid name in %s, name exceeds maximum",
        info->name.data);

    // FIXME: account for escaped characters!
    //   >> actually, we should only end up in this functions if escape
    //      characters occur!!!!

    switch (token->data[i]) {
      case '.':
        if (octet - 1 == label)
          SYNTAX_ERROR(parser, "Invalid name in %s, empty label",
            info->name.data);
        // fall through
      case '\0':
        if ((octet - 1) - label > 63)
          SYNTAX_ERROR(parser, "Invalid name in %s, label exceeds maximum",
            info->name.data);
        octets[label] = (octet - label) - 1;
        if (token->data[i] != '.')
          break;
        label = octet;
        octets[octet++] = 0;
        break;
      default:
        octets[octet++] = token->data[i];
        break;
    }
  }

  *length = octet;
  return 0;
}

static zone_return_t parse_ttl(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  uint32_t seconds = 0;
  zone_return_t result;

  if ((result = scan_ttl(parser, info, token, &seconds)) < 0)
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
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  char buf[] = "YYYYmmddHHMMSS";

  if (token->length >= sizeof(buf))
    SYNTAX_ERROR(parser, "Invalid time in %s", info->name.data);
  memcpy(buf, token->data, token->length);
  buf[token->length] = '\0';

  const char *end = NULL;
  struct tm tm;
  if (!(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    SYNTAX_ERROR(parser, "Invalid time in %s", info->name.data);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl(mktime_from_utc(&tm));
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

static inline zone_return_t parse_int8(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT8_MAX)
      SEMANTIC_ERROR(parser, "Value in %s exceeds maximum", info->name.data);
  }

  parser->rdata[parser->rdlength] = (uint8_t)v;
  parser->rdlength += sizeof(uint8_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&info->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", info->name.data);
  assert(symbol->value <= UINT8_MAX);
  parser->rdata[parser->rdlength] = (uint8_t)symbol->value;
  parser->rdlength += sizeof(uint8_t);
  return 0;
}

static inline zone_return_t parse_int16(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT16_MAX)
      SEMANTIC_ERROR(parser, "Value for %s exceeds maximum", info->name.data);
  }

  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)v);
  parser->rdlength += sizeof(uint16_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&info->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", info->name.data);
  assert(symbol->value <= UINT16_MAX);
  *((uint16_t *)&parser->rdata[parser->rdlength]) = htons((uint16_t)symbol->value);
  parser->rdlength += sizeof(uint16_t);
  return 0;
}

static inline zone_return_t parse_int32(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  // FIXME: can make this switched based too?!?!
  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT32_MAX)
      SEMANTIC_ERROR(parser, "Value for %s exceeds maximum", info->name.data);
  }

  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl((uint32_t)v);
  parser->rdlength += sizeof(uint32_t);
  return 0;
parse_symbol:
  if (!(symbol = zone_lookup(&info->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid integer in %s", info->name.data);
  assert(symbol->value <= UINT16_MAX);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl((uint32_t)symbol->value);
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

static inline zone_return_t parse_ip4(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  char buf[INET_ADDRSTRLEN + 1];

  if (token->length > INET_ADDRSTRLEN)
    SYNTAX_ERROR(parser, "Invalid IPv4 address in %s", info->name.data);
  memcpy(buf, token->data, token->length);
  buf[token->length] = '\0';
  if (inet_pton(AF_INET, buf, &parser->rdata[parser->rdlength]) != 1)
    SYNTAX_ERROR(parser, "Invalid IPv4 address in %s", info->name.data);
  parser->rdlength += sizeof(struct in_addr);
  return 0;
}

static inline zone_return_t parse_ip6(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  char buf[INET6_ADDRSTRLEN + 1];

  if (token->length > INET6_ADDRSTRLEN)
    SYNTAX_ERROR(parser, "Invalid IPv6 address in %s", info->name.data);
  memcpy(buf, token->data, token->length);
  buf[token->length] = '\0';
  if (inet_pton(AF_INET6, buf, &parser->rdata[parser->rdlength]) != 1)
    SYNTAX_ERROR(parser, "Invalid IPv6 address in %s", info->name.data);
  parser->rdlength += sizeof(struct in6_addr);
  return 0;
}

static inline zone_return_t parse_escaped_name(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  zone_return_t result;
  size_t length = 0;

  if ((result = scan_name(
    parser, info, token, &parser->rdata[parser->rdlength], &length)) < 0)
    return result;
  parser->rdlength += length;
  if (parser->rdata[parser->rdlength - 1] != 0) {
    if (length >= 256 - parser->file->origin.name.length)
      SYNTAX_ERROR(parser, "Invalid name in %s, length exceeds maximum",
        info->name.data);
    memcpy(&parser->rdata[parser->rdlength],
            parser->file->origin.name.octets,
            parser->file->origin.name.length);
    parser->rdlength += parser->file->origin.name.length;
  }

  return 0;
}

static inline uint32_t *dump_8x(uint32_t *tail, uint32_t block, uint64_t bits)
{
  int count = count_ones(bits);

  for (int i=0; i < 2; i++) {
    tail[i] = block + trailing_zeroes(bits);
    bits = clear_lowest_bit(bits);
  }

  if (zone_unlikely(count > 2)) {
    for (int i=2; i < 4; i++) {
      tail[i] = block + trailing_zeroes(bits);
      bits = clear_lowest_bit(bits);
    }

    if (zone_unlikely(count > 4)) {
      for (int i=4; i < count; i++) {
        tail[i] = block + trailing_zeroes(bits);
        bits = clear_lowest_bit(bits);
      }
    }
  }

  return tail + count;
}

zone_always_inline()
static inline zone_return_t parse_name(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  // FIXME: properly handle escaped names
  //if (token->code & ESCAPED) {
  //  return parse_escaped_name(parser, info, token);
  //} else
  if (token->length == 0) {
    SEMANTIC_ERROR(parser, "Invalid name in %s, empty", info->name.data);
  } else if (token->length == 1) {
    // a freestanding "@" denotes the current origin
    if (token->data[0] == '@') {
      memcpy(
       &parser->rdata[parser->rdlength],
        parser->file->origin.name.octets,
        parser->file->origin.name.length);
      parser->rdlength += parser->file->origin.name.length;
      return 0;
    // a freestanding "." denotes root
    } else if (token->data[0] == '.') {
      parser->rdata[parser->rdlength] = 0;
      parser->rdlength += 1;
      return 0;
    }
  } else if (token->length > 255) {
    goto bad_name;
  }

  uint32_t *head = parser->state.name.tape, *tail = parser->state.name.tape;
  size_t block = 0;
  const uint32_t blocks = token->length / VECTOR8X_SIZE;
  vector8x_t input;

  for (; block < blocks; block += VECTOR8X_SIZE) {
    load_8x(&input, (uint8_t*)token->data+block);
    const uint64_t dot = find_8x(&input, '.');
    tail = dump_8x(tail, block, dot);
  }

  // (1 << 0) - 1 == 0
  const uint64_t mask = (1llu << (token->length - block)) - 1;
  load_8x(&input, (uint8_t*)token->data+block);
  const uint64_t dot = find_8x(&input, '.') & mask;
  tail = dump_8x(tail, block, dot);

  *tail = token->length;

  uint8_t *octets = &parser->rdata[parser->rdlength];
  uint32_t label = 0, length;

  memcpy(octets+1, token->data, token->length);
  for (; head != tail; head++) {
    length = *head - label;
    if (!length || length > 63)
      goto bad_name;
    octets[label] = length;
    label += length + 1;
  }

  assert(head == tail);
  length = *head - label;
  if (length > 63)
    goto bad_label;
  octets[label] = length;

  parser->rdlength += 1 + token->length;

  if (octets[label] == 0)
    return 0;

  if (parser->file->origin.name.length > 256 - token->length)
    goto bad_name;

  memcpy(&parser->rdata[parser->rdlength],
          parser->file->origin.name.octets,
          parser->file->origin.name.length);
  parser->rdlength += parser->file->origin.name.length;
  return 0;

bad_label:
  SYNTAX_ERROR(parser, "Invalid label in %s, exceeds 63 octets", info->name.data);
bad_name:
  SYNTAX_ERROR(parser, "Invalid name in %s, exceeds 255 octets", info->name.data);
}

static inline zone_return_t parse_string(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  if (token->length > 255)
    SEMANTIC_ERROR(parser, "String in %s exceeds maximum length", info->name.data);

  // FIXME: check for newlines >> no need to check for newlines anymore specifically
  //        do need to check if escaped!!!!

  memcpy(&parser->rdata[parser->rdlength+1], token->data, token->length);
  parser->rdata[parser->rdlength] = (uint8_t)token->length;
  parser->rdlength += token->length + 1;
  return 0;
}

static inline zone_return_t accept_rr(
  zone_parser_t *parser, zone_field_t *fields, void *user_data)
{
  parser->rdata_items = fields;
  return parser->options.accept(
    parser,
   &parser->items[0],
   &parser->items[3],
   &parser->items[2],
   &parser->items[1],
    parser->rdata_items,
    parser->rdlength,
    parser->rdata,
    user_data);
}

#include "base16.h"
#include "base32.h"
#include "base64.h"
#include "nsec.h"
#include "rdata.h"

static zone_return_t parse_escaped_owner(
  zone_parser_t *parser, zone_token_t *token)
{
  zone_return_t result;
    static const zone_field_info_t info =
      { { 5, "owner" }, ZONE_OWNER|ZONE_NAME, 0, { 0 } };

  if ((result = scan_name(
    parser, &info, token,
    parser->file->owner.name.octets,
   &parser->file->owner.name.length)) < 0)
    return result;

  // FIXME: definitely not correct
  parser->items[0] = (zone_field_t){
    .code = ZONE_OWNER|ZONE_NAME,
    .length = parser->file->owner.name.length,
    .data = { .octets = parser->file->owner.name.octets } };
  return 0;
}

zone_always_inline()
static inline zone_return_t parse_owner(
  zone_parser_t *parser, zone_token_t *token)
{
  // FIXME: we don't quite need uint32_t for names
  //        uint8_t will suffice!
  uint32_t *head = parser->state.name.tape, *tail = parser->state.name.tape;
  size_t block = 0;
  const uint32_t blocks = token->length / VECTOR8X_SIZE;
  vector8x_t input;
  //zone_return_t result;

  //if (token->code & ESCAPED) {
  //  return parse_escaped_owner(parser, token);
  //} else
  if (token->length == 0) {
    SEMANTIC_ERROR(parser, "Invalid name in owner");
  } else if (token->length == 1) {
    // a freestanding "@" denotes the origin
    if (token->data[0] == '@') {
      parser->file->owner = parser->file->origin;
      return 0;
    } else if (token->data[0] == '.') {
      parser->file->names[0] = 0;
      parser->file->owner.name.octets = parser->file->names;
      parser->file->owner.name.length = 1;
      return 0;
    }
  } else if (zone_unlikely(token->length > 255)) {
    SYNTAX_ERROR(parser, "Invalid name in owner");
  }

  for (; block < blocks; block += VECTOR8X_SIZE) {
    load_8x(&input, (uint8_t*)token->data+block);
    const uint64_t dot = find_8x(&input, '.');
    tail = dump_8x(tail, block, dot);
  }

  const uint64_t mask = (1llu << (token->length - block)) - 1;
  load_8x(&input, (uint8_t*)token->data+block);
  const uint64_t dot = find_8x(&input, '.') & mask;
  tail = dump_8x(tail, block, dot);

  *tail = token->length;

  uint8_t *octets = parser->file->names + (255 - token->length);
  uint32_t label = 0, length;

  memcpy(octets+1, token->data, token->length);
  for (; head != tail; head++) {
    length = *head - label;
    if (!length || length > 63)
      goto bad_name;
    octets[label] = length;
    label += length + 1;
  }

  assert(head == tail);
  length = *head - label;
  if (length > 63)
    goto bad_label;
  octets[label] = length;

  parser->file->owner.name.octets = octets;
  parser->file->owner.name.length = 1 + token->length;
  parser->items[0].data.octets = octets;
  parser->items[0].length = 1 + token->length;

  if (octets[label] == 0)
    return 0;
  if (parser->file->origin.name.length > 255 - token->length)
    goto bad_name;

  parser->file->owner.name.length += parser->file->origin.name.length;
  parser->items[0].length += parser->file->origin.name.length;
  return 0;
bad_label:
  SEMANTIC_ERROR(parser, "Invalid name in owner");
bad_name:
  SEMANTIC_ERROR(parser, "Invalid name in owner");
}

zone_always_inline()
static inline zone_return_t parse_rr(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  zone_return_t result;

  uint16_t code;
  uint32_t ttl;

  static const zone_field_info_t ttl_info =
    { { 3, "ttl" }, ZONE_TTL|ZONE_INT32, 0, { 0 } };
  static const zone_field_info_t type_info =
    { { 4, "type" }, ZONE_TYPE|ZONE_INT16, 0, { 0 } };

  if (parser->file->start_of_line) {
    if ((result = parse_owner(parser, token)) < 0)
      return result;
    if ((result = lex(parser, token)) < 0)
      return result;
  }

  if ((uint8_t)token->data[0] - '0' > 9)
    result = scan_type_or_class(parser, &type_info, token, &code);
  else
    result = scan_ttl(parser, &ttl_info, token, &ttl);

  if (result < 0)
    return result;

  switch (result) {
    case ZONE_TTL:
      parser->file->last_ttl = ttl;
      goto class_or_type;
    case ZONE_CLASS:
      parser->file->last_class = code;
      goto ttl_or_type;
    default:
      assert(result == ZONE_TYPE);
      parser->file->last_type = code;
      goto rdata;
  }

ttl_or_type:
  if ((result = lex(parser, token)) < 0)
    return result;
  if ((uint8_t)token->data[0] - '0' > 9)
    result = scan_type(parser, &type_info, token, &code);
  else
    result = scan_ttl(parser, &ttl_info, token, &ttl);

  if (result < 0)
    return result;

  switch (result) {
    case ZONE_TTL:
      parser->file->last_ttl = ttl;
      goto type;
    default:
      assert(result == ZONE_TYPE);
      parser->file->last_type = code;
      goto rdata;
  }

class_or_type:
  if ((result = lex(parser, token)) < 0)
    return result;
  if ((result = scan_type_or_class(parser, &type_info, token, &code)) < 0)
    return result;

  switch (result) {
    case ZONE_CLASS:
      parser->file->last_class = code;
      goto type;
    default:
      assert(result == ZONE_TYPE);
      parser->file->last_type = code;
      goto rdata;
  }

type:
  if ((result = lex(parser, token)) < 0)
    return result;
  if ((result = scan_type(parser, &type_info, token, &code)) < 0)
    return result;

  parser->file->last_type = code;

rdata:
  // FIXME: check if record type is directly indexable
  parser->rdlength = 0;
  return types[code].parse(parser, &types[code].info, user_data);
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
      info->name.data);

  return 0;
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
static inline zone_return_t parse_dollar_origin(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t info =
    { { 7, "$ORIGIN" }, ZONE_DOLLAR_ORIGIN|ZONE_NAME, 0, { 0 } };

  zone_return_t result;

  (void)user_data;

  if ((result = lex(parser, token)) < 0)
    return result;
  if ((result = parse_origin(parser, &info, token)) < 0)
    return result;
  if ((result = lex(parser, token)) < 0)
    return result;
  if (result)
    SYNTAX_ERROR(parser, "$ORIGIN directive takes just a single argument");

  return 0;
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
static inline zone_return_t parse_dollar_ttl(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t info =
    { { 4, "$TTL" }, ZONE_INT32, 0, { 0 } };

  (void)user_data;
  zone_return_t result;

  if ((result = lex(parser, token)) < 0)
    return result;
  if ((result = scan_ttl(parser, &info, token, &parser->file->default_ttl)) < 0)
    return result;
  if ((result = lex(parser, token)) < 0)
    return result;
  if (result)
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
      case ZONE_CONTIGUOUS: // contiguous
        if (!parser->file->start_of_line || token.data[0] != '$')
          result = parse_rr(parser, &token, user_data);
        else if (token.length == sizeof(include) - 1 &&
                 strncasecmp(token.data, include, sizeof(include)-1) == 0)
          result = parse_dollar_include(parser, &token, user_data);
        else if (token.length == sizeof(origin) - 1 &&
                 strncasecmp(token.data, origin, sizeof(origin) - 1) == 0)
          result = parse_dollar_origin(parser, &token, user_data);
        else if (token.length == sizeof(ttl) - 1 &&
                 strncasecmp(token.data, ttl, sizeof(ttl) - 1) == 0)
          result = parse_dollar_ttl(parser, &token, user_data);
        else
          result = parse_rr(parser, &token, user_data);
        break;
      case ZONE_QUOTED: // quoted (never a directive)
        result = parse_rr(parser, &token, user_data);
        break;
      case ZONE_DELIMITER:
        if (!token.data[0])
          return 0;
        break;
      default:
        break;
    }
  } while (result >= 0);

  // FIXME: set state to return on error!

  return result;
}

#endif // PARSER_H
