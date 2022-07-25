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

  uint32_t blks[256]; // window blocks in use
  uint8_t lens[256]; // number of octets used per window block
  uint8_t *octs, *blk;
  size_t cnt = 0, size = 0;
  zone_return_t ret;

  // iterate over all 256 windows
  for (size_t i = 0, n = 1 + par->parser.nsec.highest_bit / 256; i < n; i++) {
    lens[i] = 0;
    for (size_t j = 0; j < 256 / 8; j++)
      if (par->parser.nsec.bits[i][j])
        lens[i] = j + 1;
    // skip if no bits were set
    if (!lens[i])
      continue;
    blks[cnt++] = i;
    size += 2 * sizeof(uint8_t) + lens[i];
  }

  if (!(octs = zone_malloc(par, size)))
    return ZONE_OUT_OF_MEMORY;

  blk = octs;
  for (size_t i = 0; i < cnt; i++) {
    blk[0] = (uint8_t)blks[i];
    blk[1] = (uint8_t)lens[blks[i]];
    memcpy(&blk[2], &par->parser.nsec.bits[blks[i]], lens[blks[i]]);
    blk += 2 + lens[blks[i]];
  }

  assert(fld->code == (ZONE_RDATA|ZONE_NSEC));
  fld->nsec.length = size;
  fld->nsec.octets = octs;

  if ((ret = par->options.accept.rdata(par, fld, ptr)) < 0)
    zone_free(par, octs);
  par->parser.nsec.highest_bit = 0;
  return ret;
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

  // ensure newly used windows are zeroed out before use
  if (type > par->parser.nsec.highest_bit) {
    size_t off = (par->parser.nsec.highest_bit / 256) + (par->parser.nsec.highest_bit != 0);
    size_t size = ((window + 1)-off) * sizeof(par->parser.nsec.bits[off]);
    if (!off || window > off)
      memset(&par->parser.nsec.bits[off], 0, size);
    par->parser.nsec.highest_bit = type;
  }

  // bits are counted from left to right, so bit #0 is the left most bit
  par->parser.nsec.bits[window][bit / 8] |= (1 << (7 - bit % 8));

  return ZONE_DEFER_ACCEPT;
}

static inline zone_return_t parse_generic_nsec(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_NOT_IMPLEMENTED;
}

#endif // ZONE_NSEC_H
