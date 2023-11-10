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

// [sS] = 1, [mM] = 60, [hH] = 60*60, [dD] = 24*60*60, [wW] = 7*24*60*60
static const uint32_t units[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x00 - 0x0f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x10 - 0x1f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x20 - 0x2f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x30 - 0x3f
  0, 0, 0, 0, 86400, 0, 0, 0, 3600, 0, 0, 0, 0, 60, 0, 0, // 0x40 - 0x4f
  0, 0, 0, 1, 0, 0, 0, 604800, 0, 0, 0, 0, 0, 0, 0, 0,    // 0x50 - 0xf5
  0, 0, 0, 0, 86400, 0, 0, 0, 3600, 0, 0, 0, 0, 60, 0, 0, // 0x60 - 0x6f
  0, 0, 0, 1, 0, 0, 0, 604800, 0, 0, 0, 0, 0, 0, 0, 0,    // 0x70 - 0x7f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x80 - 0x8f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0x90 - 0x9f
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0xa0 - 0xaf
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0xb0 - 0xbf
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0xc0 - 0xcf
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0xd0 - 0xdf
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // 0xe0 - 0xef
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0          // 0xf0 - 0xff
};

zone_nonnull_all
static zone_really_inline int32_t scan_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token,
  uint32_t *seconds)
{
  int32_t r;
  uint64_t t = 0, m = parser->options.secondary ? UINT32_MAX : INT32_MAX;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  const char *p = token->data;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    t = t * 10 + d;
  }

  if (zone_likely(contiguous[ (uint8_t)*p ] != CONTIGUOUS)) {
    // FIXME: comment RFC2308 msb
    if (t > m || !t || p - token->data > 10)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    if (t & (1llu << 31))
      SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    *seconds = (uint32_t)t;
    return ZONE_TTL;
  } else if (p == token->data || !parser->options.pretty_ttls) {
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  }

  uint64_t n = t, u = 0, f = 0;
  enum { NUMBER, UNIT } s = UNIT;

  for (t = 0; ; p++) {
    const uint64_t d = (uint8_t)*p - '0';

    if (s == NUMBER) {
      if (d <= 9) {
        n = n * 10 + d;
      } else if (!(u = units[ (uint8_t)*p ])) {
        break;
      // units must not be repeated e.g. 1m1m
      } else if (u == f) {
        SYNTAX_ERROR(parser, "Invalid %s in %s, reuse of unit %c",
                     NAME(field), TNAME(type), *p);
      // greater units must precede smaller units. e.g. 1m1s, not 1s1m
      } else if (u < f) {
        SYNTAX_ERROR(parser, "Invalid %s in %s, unit %c follows smaller unit",
                     NAME(field), TNAME(type), *p);
      } else {
        f = u;
        n = n * u;
        s = UNIT;
      }

      if (n > m)
        SYNTAX_ERROR(parser, "Invalid %s in %s",
                     NAME(field), TNAME(type));
    } else if (s == UNIT) {
      // units must be followed by a number. e.g. 1h30m, not 1hh
      if (d > 9)
        SYNTAX_ERROR(parser, "Invalid %s in %s, non-digit follows unit",
                     NAME(field), TNAME(type));
      // units must not be followed by a number if smallest unit,
      // i.e. seconds, was previously specified
      if (f == 1)
        SYNTAX_ERROR(parser, "Invalid %s in %s, digit follows unit s",
                     NAME(field), TNAME(type));
      t = t + n;
      n = d;
      s = NUMBER;

      if (t > m)
        SYNTAX_ERROR(parser, "Invalid %s in %s",
                     NAME(field), TNAME(type));
    }
  }

  if (zone_unlikely(contiguous[ (uint8_t)*p ] != CONTIGUOUS))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  t = t + n;
  if (t > m || !t)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  if (t & (1llu << 31))
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *seconds = (uint32_t)t;
  return ZONE_TTL;
}

zone_nonnull_all
static zone_really_inline int32_t parse_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;
  uint32_t t = 0;

  if ((r = scan_ttl(parser, type, field, token, &t)) < 0)
    return r;
  t = htobe32(t);
  memcpy(&parser->rdata->octets[parser->rdata->length], &t, sizeof(t));
  parser->rdata->length += sizeof(t);
  return ZONE_TTL;
}

#endif // TTL_H
