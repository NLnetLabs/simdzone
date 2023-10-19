/*
 * nsec.h -- parse NSEC (RFC4043) rdata in (DNS) zone files
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NSEC_H
#define NSEC_H

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol);

typedef uint8_t zone_nsec_t[256 + 2];

zone_nonnull_all
static zone_really_inline int32_t parse_nsec(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  uint16_t code;
  const zone_symbol_t *symbol;

  uint8_t *octets = &parser->rdata->octets[parser->rdata->length];
  zone_nsec_t *bitmap = (void *)octets;
  // FIXME: convert to static assert
  assert(parser->rdata->length < sizeof(parser->rdata) - (256 * (256 + 2)));

  uint32_t highest_window = 0;
  uint32_t windows[256] = { 0 };

  do {
    scan_type(parser, type, field, token, &code, &symbol);

    const uint8_t bit = (uint8_t)(code % 256);
    const uint8_t window = code / 256;
    const uint8_t block = bit / 8;

    if (!windows[window])
      memset(bitmap[window], 0, sizeof(bitmap[window]));
    if (window > highest_window)
      highest_window = window;
    windows[window] |= 1 << block;
    bitmap[window][2 + block] |= (1 << (7 - bit % 8));
    lex(parser, token);
  } while (token->code == CONTIGUOUS);

  for (uint32_t window = 0; window <= highest_window; window++) {
    if (!windows[window])
      continue;
    const uint8_t blocks = (uint8_t)(64 - leading_zeroes(windows[window]));
    memmove(&octets[0], &bitmap[window], 2 + blocks);
    octets[0] = (uint8_t)window;
    octets[1] = blocks;
    octets += 2 + blocks;
  }

  parser->rdata->length += (uintptr_t)octets - (uintptr_t)bitmap;
  return ZONE_TYPE_BITMAP;
}

#endif // NSEC_H
