/*
 * nsec.h -- parser for NSEC records in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_NSEC_H
#define ZONE_NSEC_H

// implements parsing NSEC (rfc4043) records

static inline zone_return_t accept_nsec(
  zone_parser_t *par, zone_field_t *fld, void *ptr)
{
  // (mostly copied from NSD)
  // nsecbits contains up to 64K bits that represent the types available for
  // a name. walk the bits according to the nsec++ draft from jakob.

  uint8_t *window;

  // iterate over and compress all (maybe 256) windows
  for (size_t i = 0, n = 1 + par->rdata.state.nsec.highest_bit / 256; i < n; i++) {
    uint8_t len = par->rdata.nsec[i][1] / 8 + 1; // saves us from having to iterate a lot of data
    if (!len)
      continue;
    window = ((uint8_t *)par->rdata.nsec) + par->rdata.length;
    par->rdata.length += 2 * sizeof(uint8_t) + len;
    window[0] = (uint8_t)i;
    window[1] = (uint8_t)len;
    memmove(&window[2], &par->rdata.nsec[i][2], len);
  }

  fld->wire.length = par->rdata.length;
  par->rdata.state.nsec.highest_bit = 0;
  return par->options.accept.rdata(par, fld, ptr);
}

static inline zone_return_t parse_nsec(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int32_t type;
  static const uint32_t flags = ZONE_ESCAPED | ZONE_STRICT | ZONE_GENERIC;

  (void)fld;
  (void)ptr;
  type = zone_is_type(tok->string.data, tok->string.length, flags);
  if (type < 0)
    SYNTAX_ERROR(par, "{l}: Invalid escape sequence in type", tok);
  if (type == 0)
    SEMANTIC_ERROR(par, "{l}: Invalid type in NSEC record", tok);
  assert(type <= UINT16_MAX);
  const uint16_t window = (uint16_t)type / 256;
  const uint16_t bit = (uint16_t)type % 256;

  // FIXME: record the highest bit for a window in the second byte
  //        so we don't have to iterate all 256 bits!!!!
  // ensure newly used windows are zeroed out before use
  if (type > par->rdata.state.nsec.highest_bit) {
    size_t off = (par->rdata.state.nsec.highest_bit / 256) + (par->rdata.state.nsec.highest_bit != 0);
    size_t size = ((window + 1)-off) * sizeof(par->rdata.nsec[off]);
    if (!off || window > off)
      memset(&par->rdata.nsec[off], 0, size);
    par->rdata.state.nsec.highest_bit = type;
  }

  // bits are counted from left to right, so bit #0 is the left most bit
  par->rdata.nsec[window][1] = bit;
  par->rdata.nsec[window][2 + bit / 8] |= (1 << (7 - bit % 8));

  return ZONE_DEFER_ACCEPT;
}

#endif // ZONE_NSEC_H
