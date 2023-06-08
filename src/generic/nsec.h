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

typedef uint8_t zone_nsec_t[256 + 2];

zone_nonnull_all
static zone_really_inline int32_t parse_nsec(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  uint16_t code;
  uint16_t highest_bit = 0;

  uint8_t *data = &parser->rdata->octets[parser->rdata->length];
  zone_nsec_t *bitmap = (void *)&parser->rdata->octets[parser->rdata->length];
  assert(parser->rdata->length < sizeof(parser->rdata) - (256 * (256 + 2)));

  // (mostly copied from NSD)
  // nsecbits contains up to 64K bits that represent the types available for
  // a name. walk the bits according to the nsec++ draft from jakob.

  do {
    scan_type(parser, type, field, token, &code);

    const uint8_t bit = (uint8_t)((uint16_t)code % 256);
    const uint8_t window = (uint8_t)((uint16_t)code / 256);

    if (code > highest_bit) {
      const size_t skip = highest_bit / 256 + !!highest_bit;
      if (!skip || window > skip)
        memset(bitmap[skip], 0, (window + 1) - skip * sizeof(*bitmap));
      highest_bit = code;
    }

    if (bit > bitmap[window][1])
      bitmap[window][1] = bit;
    bitmap[window][2 + bit / 8] |= (1 << (7 - bit % 8));
    lex(parser, token);
  } while (token->code == CONTIGUOUS);

  // iterate and compress all (maybe 256) windows
  size_t length = 0;
  const size_t windows = 1 + highest_bit / 256;
  for (size_t window = 0; window < windows; window++) {
    // FIXME: cannot be correct!
    const uint8_t blocks = 1 + bitmap[window][1] / 8;
    if (!blocks)
      continue;
    data[length] = (uint8_t)window;
    data[length+1] = blocks;
    memmove(&data[length+2], &bitmap[window][2], blocks);
  }

  parser->rdata->length += length;
  return ZONE_TYPE_BITMAP;
}

#endif // NSEC_H
