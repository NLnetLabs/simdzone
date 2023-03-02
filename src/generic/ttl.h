/*
 * ttl.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TTL_H
#define TTL_H

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
zone_nonnull_all()
static inline zone_return_t scan_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token,
  uint32_t *seconds)
{
  uint64_t value = 0, unit = 0, number, factor = 0;
  enum { NUMBER, UNIT } state = NUMBER;

  // ttls must start with a number
  number = (unsigned char)token->data[0] - '0';
  if (number > 9)
    SYNTAX_ERROR(parser, "Invalid %s in %s",
                 field->name.data, type->name.data);

  for (size_t i=1; i < token->length; i++) {
    const uint64_t digit = (unsigned char)token->data[i] - '0';

    switch (state) {
      case NUMBER:
        if (digit <= 9) {
          number = (number * 10) + digit;
          if (value > INT32_MAX)
            SEMANTIC_ERROR(parser, "Invalid %s in %s, value exceeds maximum",
                           field->name.data, type->name.data);
        } else if ((factor = is_unit(token->data[i]))) {
          // units must not be repeated e.g. 1m1m
          if (unit == factor)
            SYNTAX_ERROR(parser, "Invalid %s in %s, reuse of unit %c",
                         field->name.data, type->name.data, token->data[i]);
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (unit && unit < factor)
            SYNTAX_ERROR(parser, "Invalid %s in %s, unit %c follows smaller unit",
                         field->name.data, type->name.data, token->data[i]);
          unit = factor;
          number = number * unit;
          state = UNIT;
        } else {
          SYNTAX_ERROR(parser, "Invalid %s in %s, invalid unit",
                       field->name.data, type->name.data);
        }
        break;
      case UNIT:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (digit > 9)
          SYNTAX_ERROR(parser, "Invalid %s in %s, non-digit follows unit",
                       field->name.data, type->name.data);
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (unit == 1)
          SYNTAX_ERROR(parser, "Invalid %s in %s, digit follows unit s",
                       field->name.data, type->name.data);
        value = value + number;
        number = digit;
        state = NUMBER;
        break;
    }
  }

  value = value + number;
  // FIXME: comment RFC2308 msb
  if (value > INT32_MAX)
    SEMANTIC_ERROR(parser, "Invalid %s in %s, value exceeds maximum",
                   field->name.data, type->name.data);
  *seconds = (uint32_t)value;
  return ZONE_TTL;
}

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t parse_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint32_t seconds = 0;
  zone_return_t result;

  if ((result = scan_ttl(parser, type, field, token, &seconds)) < 0)
    return result;
  assert(seconds <= INT32_MAX);
  seconds = htonl(seconds);
  memcpy(&parser->rdata[parser->rdlength], &seconds, sizeof(seconds));
  parser->rdlength += sizeof(uint32_t);
  return 0;
}

#endif // TTL_H
