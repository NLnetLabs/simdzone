/*
 * eui48.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef EUI_H
#define EUI_H

// RFC7043 section 3.2: xx-xx-xx-xx-xx-xx
zone_nonnull_all
static zone_really_inline int32_t parse_eui48(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  uint8_t c, x[12];
  uint8_t *w = parser->rdata->octets + parser->rdata->length;
  const uint8_t *p = (uint8_t *)token->data;

  c = (p[ 2] == '-') & (p[ 5] == '-') &
      (p[ 8] == '-') & (p[11] == '-') &
      (p[14] == '-');
  if (!c)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  x[ 0] = b16rmap[p[ 0]];
  x[ 1] = b16rmap[p[ 1]];
  x[ 2] = b16rmap[p[ 3]];
  x[ 3] = b16rmap[p[ 4]];
  x[ 4] = b16rmap[p[ 6]];
  x[ 5] = b16rmap[p[ 7]];
  x[ 6] = b16rmap[p[ 9]];
  x[ 7] = b16rmap[p[10]];
  x[ 8] = b16rmap[p[12]];
  x[ 9] = b16rmap[p[13]];
  x[10] = b16rmap[p[15]];
  x[11] = b16rmap[p[16]];

  c = x[ 0] | x[ 1] | x[ 2] | x[ 3] | x[ 4] | x[ 5] |
      x[ 6] | x[ 7] | x[ 8] | x[ 9] | x[10] | x[11];
  if (c & 0x80)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  w[0] = (uint8_t)((x[ 0] << 4) | x[ 1]);
  w[1] = (uint8_t)((x[ 2] << 4) | x[ 3]);
  w[2] = (uint8_t)((x[ 4] << 4) | x[ 5]);
  w[3] = (uint8_t)((x[ 6] << 4) | x[ 7]);
  w[4] = (uint8_t)((x[ 8] << 4) | x[ 9]);
  w[5] = (uint8_t)((x[10] << 4) | x[11]);

  parser->rdata->length += 6;
  return ZONE_EUI48;
}

// RFC7043 section 4.2, require xx-xx-xx-xx-xx-xx-xx-xx
zone_nonnull_all
static zone_really_inline int32_t parse_eui64(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  uint8_t c, x[16];
  uint8_t *w = parser->rdata->octets + parser->rdata->length;
  const uint8_t *p = (uint8_t *)token->data;

  c = (p[ 2] == '-') & (p[ 5] == '-') & (p[ 8] == '-') & (p[11] == '-') &
      (p[14] == '-') & (p[17] == '-') & (p[20] == '-');
  if (!c)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  x[ 0] = b16rmap[p[ 0]];
  x[ 1] = b16rmap[p[ 1]];
  x[ 2] = b16rmap[p[ 3]];
  x[ 3] = b16rmap[p[ 4]];
  x[ 4] = b16rmap[p[ 6]];
  x[ 5] = b16rmap[p[ 7]];
  x[ 6] = b16rmap[p[ 9]];
  x[ 7] = b16rmap[p[10]];
  x[ 8] = b16rmap[p[12]];
  x[ 9] = b16rmap[p[13]];
  x[10] = b16rmap[p[15]];
  x[11] = b16rmap[p[16]];
  x[12] = b16rmap[p[18]];
  x[13] = b16rmap[p[19]];
  x[14] = b16rmap[p[21]];
  x[15] = b16rmap[p[22]];

  c = x[ 0] | x[ 1] | x[ 2] | x[ 3] | x[ 4] | x[ 5] | x[ 6] | x[ 7] |
      x[ 8] | x[ 9] | x[10] | x[11] | x[12] | x[13] | x[14] | x[15];
  if (c & 0x80)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  w[0] = (uint8_t)((x[ 0] << 4) | x[ 1]);
  w[1] = (uint8_t)((x[ 2] << 4) | x[ 3]);
  w[2] = (uint8_t)((x[ 4] << 4) | x[ 5]);
  w[3] = (uint8_t)((x[ 6] << 4) | x[ 7]);
  w[4] = (uint8_t)((x[ 8] << 4) | x[ 9]);
  w[5] = (uint8_t)((x[10] << 4) | x[11]);
  w[6] = (uint8_t)((x[12] << 4) | x[13]);
  w[7] = (uint8_t)((x[14] << 4) | x[15]);

  parser->rdata->length += 8;
  return ZONE_EUI64;
}

#endif // EUI_H
