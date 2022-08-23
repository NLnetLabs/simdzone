/*
 * nsec.h -- parser for NSEC (rfc4043) rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_NSEC_H
#define ZONE_NSEC_H

static zone_return_t parse_nsec(
  zone_parser_t *par, zone_token_t *tok)
{
  uint16_t type;
  zone_return_t ret;

  if ((ret = lex_type(par, par->rr.descriptors.rdata, tok, &type)) < 0)
    return ret;

  const uint16_t bit = (uint16_t)type % 256;
  const uint16_t window = (uint16_t)type / 256;

  if (type > par->state.nsec.highest_bit) {
    size_t off = par->state.nsec.highest_bit / 256 + (par->state.nsec.highest_bit != 0);
    size_t size = ((window + 1) - off) * sizeof(par->state.nsec.bitmap[off]);
    if (!off || window > off)
      memset(&par->state.nsec.bitmap[off], 0, size);
    par->state.nsec.highest_bit = type;
  }

  if (type > par->state.nsec.bitmap[window][1])
    par->state.nsec.bitmap[window][1] = bit;
  par->state.nsec.bitmap[window][2 + bit / 8] |= (1 << (7 - bit % 8));
  return ZONE_DEFER_ACCEPT;
}

static zone_return_t accept_nsec(
  zone_parser_t *par, zone_field_t *fld, void *ptr)
{
  // (mostly copied from NSD)
  // nsecbits contains up to 64K bits that represent the types available for
  // a name. walk the bits according to the nsec++ draft from jakob.

  size_t length = 0;
  uint8_t *window;

  // iterate over and compress all (maybe 256) windows
  for (size_t i = 0, n = 1 + par->state.nsec.highest_bit / 256; i < n; i++) {
    uint8_t len = par->state.nsec.bitmap[i][1] / 8 + 1;
    if (!len)
      continue;
    window = &par->rdata[par->rdlength + length];
    length += 2 * sizeof(uint8_t) + len;
    window[0] = (uint8_t)i;
    window[1] = (uint8_t)len;
    memmove(&window[2], &par->state.nsec.bitmap[i][2], len);
  }

  fld->octets = &par->rdata[par->rdlength];
  fld->length = length;

  par->rdlength += length;
  par->state.nsec.highest_bit = 0;
  return par->options.accept.rdata(par, fld, ptr);
}

#endif // ZONE_NSEC_H
