/*
 * ilnp64.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ILNP64_H
#define ILNP64_H

// FIXME: very likely eligable for vectorization (or optimization even), but
//        gains are small as the type is not frequently used
zone_nonnull_all
static zone_really_inline int32_t parse_ilnp64(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint16_t a[4] = { 0, 0, 0, 0 };
  size_t n = 0;
  const char *p = token->data, *g = p;
  for (;;) {
    const uint8_t c = (uint8_t)*p;
    if (c == ':') {
      if (n == 3 || p == g || p - g > 4)
        break;
      g = p += 1;
      n += 1;
    } else {
      uint16_t x;
      if (c >= '0' && c <= '9')
        x = c - '0';
      else if (c >= 'A' && c <= 'F')
        x = c - ('A' - 10);
      else if (c >= 'a' && c <= 'f')
        x = c - ('a' - 10);
      else
        break;
      a[n] = (uint16_t)(a[n] << 4u) + x;
      p += 1;
    }
  }

  if (n != 3 || p == g || p - g > 4 || contiguous[(uint8_t)*p] == CONTIGUOUS)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  a[0] = htobe16(a[0]);
  a[1] = htobe16(a[1]);
  a[2] = htobe16(a[2]);
  a[3] = htobe16(a[3]);
  memcpy(parser->rdata->octets+parser->rdata->length, a, 8);
  parser->rdata->length += 8;
  return ZONE_ILNP64;
}

#endif // ILNP64_H
