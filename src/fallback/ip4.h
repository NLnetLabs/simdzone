/*
 * ip4.h -- fallback parser for IPv4 addresses
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef IP4_H
#define IP4_H

zone_nonnull_all
static zone_really_inline int32_t parse_ip4(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint8_t *o = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *os = o;
  uint64_t n = 0;
  const char *p = token->data;
  static const uint8_t m[] = { 0, 0, 10, 100 };

  *o = 0;
  for (const char *ps = p;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d <= 9) {
      n = n * 10 + (uint8_t)d;
    } else {
      if (!(p - ps) || p - ps > 3 || n < m[(p - ps)] || n > 255 || o - os > 3)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      ps = p + 1;
      *o++ = (uint8_t)n;
      if (*p != '.')
        break;
      n = 0;
    }
  }

  if (is_contiguous((uint8_t)*p) || o - os != 4)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  parser->rdata->length += 4;
  return ZONE_IP4;
}

#endif // IP4_H
