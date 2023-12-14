/*
 * eui.h -- EUI-48 and EUI-64 (RFC7043) parser
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef EUI_H
#define EUI_H

nonnull((1,2))
static really_inline int
eui_base16_dec_loop_generic_32_inner(const uint8_t *s, uint8_t *o, int dash)
{
  const uint32_t val1 = base16_table_dec_32bit_d0[s[0]]
                      | base16_table_dec_32bit_d1[s[1]];
  const uint32_t val2 = base16_table_dec_32bit_d0[s[3]]
                      | base16_table_dec_32bit_d1[s[4]];

  if (val1 > 0xff || val2 > 0xff || (dash ^ ((s[2] == '-') ^ (s[5] == '-'))))
    return 0;

  o[0] = (uint8_t)val1;
  o[1] = (uint8_t)val2;

  return 1;
}

// RFC7043 section 3.2, require xx-xx-xx-xx-xx-xx
nonnull_all
static really_inline int32_t parse_eui48(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  const uint8_t *input = (const uint8_t *)token->data;
  if (token->length == 17 &&
      eui_base16_dec_loop_generic_32_inner(input, rdata->octets, 0) &&
      eui_base16_dec_loop_generic_32_inner(input+6, rdata->octets+2, 0) &&
      eui_base16_dec_loop_generic_32_inner(input+12, rdata->octets+4, 1))
    return (void)(rdata->octets += 6), 0;
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
}

// RFC7043 section 4.2, require xx-xx-xx-xx-xx-xx-xx-xx
nonnull_all
static really_inline int32_t parse_eui64(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  const uint8_t *input = (const uint8_t *)token->data;
  if (token->length == 23 &&
      eui_base16_dec_loop_generic_32_inner(input, rdata->octets, 0) &&
      eui_base16_dec_loop_generic_32_inner(input+6, rdata->octets+2, 0) &&
      eui_base16_dec_loop_generic_32_inner(input+12, rdata->octets+4, 0) &&
      eui_base16_dec_loop_generic_32_inner(input+18, rdata->octets+6, 1))
    return (void)(rdata->octets += 8), 0;
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
}

#endif // EUI_H
