/*
 * nsec.h -- parse NSEC (RFC4043) rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NSEC_H
#define NSEC_H

static zone_return_t parse_nsec(
  zone_parser_t *parser, const zone_field_info_t *info, const zone_token_t *token)
{
  uint16_t code;
  zone_return_t result;

  if ((result = scan_type(parser, info, token, &code)) < 0)
    return result;

  const uint16_t bit = (uint16_t)code % 256;
  const uint16_t window = (uint16_t)code / 256;

  if (code > parser->state.nsec.highest_bit) {
    size_t off = parser->state.nsec.highest_bit / 256 + (parser->state.nsec.highest_bit != 0);
    size_t size = ((window + 1) - off) * sizeof(parser->state.nsec.bitmap[off]);
    if (!off || window > off)
      memset(&parser->state.nsec.bitmap[off], 0, size);
    parser->state.nsec.highest_bit = code;
  }

  if (code > parser->state.nsec.bitmap[window][1])
    parser->state.nsec.bitmap[window][1] = bit;
  parser->state.nsec.bitmap[window][2 + bit / 8] |= (1 << (7 - bit % 8));
  return 0;
}

static zone_return_t accept_nsec(
  zone_parser_t *parser, void *user_data)
{
  // (mostly copied from NSD)
  // nsecbits contains up to 64K bits that represent the types available for
  // a name. walk the bits according to the nsec++ draft from jakob.

  size_t length = 0;
  uint8_t *window;

  (void)user_data;

  // iterate over and compress all (maybe 256) windows
  for (size_t i = 0, n = 1 + parser->state.nsec.highest_bit / 256; i < n; i++) {
    uint8_t len = parser->state.nsec.bitmap[i][1] / 8 + 1;
    if (!len)
      continue;
    window = &parser->rdata[parser->rdlength + length];
    length += 2 * sizeof(uint8_t) + len;
    window[0] = (uint8_t)i;
    window[1] = (uint8_t)len;
    memmove(&window[2], &parser->state.nsec.bitmap[i][2], len);
  }

  parser->rdlength += length;
  parser->state.nsec.highest_bit = 0;
  return 0;
}

#endif // NSEC_H
