/*
 * nsap.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NSAP_H
#define NSAP_H

// https://datatracker.ietf.org/doc/html/rfc1706 (historic)

zone_nonnull_all
static zone_really_inline int32_t parse_nsap(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  const char *p = token->data;

  // RFC1706 section 7
  // NSAP format is "0x" (i.e., a zero followed by an 'x' character) followed
  // by a variable length string of hex characters (0 to 9, a to f). The hex
  // string is case-insensitive. "."s (i.e., periods) may be inserted in the
  // hex string anywhere after "0x" for readability. The "."s have no
  // significance other than for readability and are not propagated in the
  // protocol (e.g., queries or zone transfers).

  if (p[0] != '0' || (p[1] & 0xdf) != 'X')
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  p += 2;

  uint8_t x0 = 0x80, x1 = 0x80;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_LIMIT];

  while (w < we) {
    x0 = b16rmap[(uint8_t)p[0]];
    x1 = b16rmap[(uint8_t)p[1]];
    if (!((x0 | x1) & 0x80)) {
      w[0] = (uint8_t)((x0 << 4) | x1);
      w += 1; p += 2;
    } else {
      while (p[0] == '.')
        (void)(p += 1), x0 = b16rmap[(uint8_t)p[0]];
      if (x0 & 0x80)
        break;
      p += 1;
      x1 = b16rmap[(uint8_t)p[0]];
      while (p[0] == '.')
        (void)(p += 1), x1 = b16rmap[(uint8_t)p[0]];
      if (x1 == 0x90)
        break;
      w[0] = (uint8_t)((x0 << 4) | x1);
      w += 1; p += 1;
    }
  }

  if (w == ws || w >= we || x0 != 0x80)
    SYNTAX_ERROR(parser, "Invalid %s in %s record", NAME(field), TNAME(type));

  parser->rdata->length += (size_t)(w - ws);
  return ZONE_BLOB;
}

#endif // NSAP_H
