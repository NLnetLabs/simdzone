/*
 * nxt.h
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NXT_H
#define NXT_H

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol);

zone_nonnull_all
static zone_really_inline int32_t parse_nxt(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  uint16_t code;
  const zone_symbol_t *symbol;

  if (token->code == CONTIGUOUS) {
    scan_type(parser, type, field, token, &code, &symbol);
    int32_t result;
    uint8_t bit = (uint8_t)(code % 8);
    uint8_t block = (uint8_t)(code / 8), highest_block = block;
    uint8_t *octets = &parser->rdata->octets[parser->rdata->length];

    memset(octets, 0, block + 1);
    octets[block] = (uint8_t)(1 << (7 - bit));

    lex(parser, token);
    while (token->code == CONTIGUOUS) {
      if ((result = scan_type(parser, type, field, token, &code, &symbol)) < 0)
        return result;
      bit = (uint8_t)(code % 8);
      block = (uint8_t)(code / 8);
      if (block > highest_block) {
        memset(&octets[highest_block+1], 0, block - highest_block);
        highest_block = block;
      }
      octets[block] |= 1 << (7 - bit);
      lex(parser, token);
    }

    parser->rdata->length += highest_block + 1;
  }

  return have_delimiter(parser, type, token);
}

#endif // NXT_H
