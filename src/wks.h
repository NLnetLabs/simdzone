/*
 * nsec.h -- parser for NSEC records in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_WKS_H
#define ZONE_WKS_H

static inline zone_return_t accept_wks(
  zone_parser_t *par, zone_field_t *fld, void *ptr)
{
  par->rdata.state.wks.protocol = NULL;
  par->rdata.state.wks.highest_port = 0;
  return par->options.accept.rdata(par, fld, ptr);
}

static inline zone_return_t parse_wks_protocol(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char buf[32];
  ssize_t cnt;
  struct protoent *proto;

  (void)fld;
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  const char *str = tok->string.data;
  const size_t len = tok->string.length;
  if ((cnt = zone_unescape(str, len, buf, sizeof(buf), 1)) < 0)
    SYNTAX_ERROR(par, "{l}: Invalid escape sequence in protocol", tok);
  if ((size_t)cnt >= sizeof(buf))
    SEMANTIC_ERROR(par, "{l}: Invalid protocol in WKS record", tok);

  buf[(size_t)cnt] = '\0';
  if (!(proto = getprotobyname(buf))) {
    uint64_t u64;
    zone_return_t ret;
    const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;
    if ((ret = zone_parse_int(par, desc, tok, UINT8_MAX, &u64)) < 0)
      return ret;;
    assert(u64 <= UINT8_MAX);
    proto = getprotobynumber((int)u64);
  }

  if (!proto)
    SEMANTIC_ERROR(par, "{l}: Unknown protocol", tok);

  assert(proto);
  par->rdata.state.wks.protocol = proto;
  par->rdata.state.wks.highest_port = 0;

  par->rdata.int8 = (uint8_t)proto->p_proto;
  return ZONE_RDATA;
}

static inline zone_return_t parse_generic_wks_protocol(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_NOT_IMPLEMENTED;
}

static inline zone_return_t parse_wks(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int port = 0;
  char buf[32];
  ssize_t cnt;
  const struct protoent *proto;
  const struct servent *serv;

  (void)ptr;
  assert(par->rdata.state.wks.protocol);
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  assert((fld->code & ZONE_WKS) == ZONE_WKS);

  const char *str = tok->string.data;
  const size_t len = tok->string.length;
  if ((cnt = zone_unescape(str, len, buf, sizeof(buf), 1)) < 0)
    SEMANTIC_ERROR(par, "{l}: Invalid escape sequence in service", tok);
  if ((size_t)cnt >= sizeof(buf))
    SEMANTIC_ERROR(par, "{l}: Invalid service", tok);

  buf[(size_t)cnt] = '\0';
  proto = par->rdata.state.wks.protocol;
  assert(proto);
  if ((serv = getservbyname(buf, proto->p_name))) {
    port = ntohs((uint16_t)serv->s_port);
  } else {
    uint64_t u64;
    zone_return_t ret;
    const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;
    if ((ret = zone_parse_int(par, desc, tok, UINT16_MAX, &u64)) < 0)
      return ret;
    assert(u64 <= UINT16_MAX);
    port = (int)u64;
  }

  assert(port >= 0 && port <= 65535);
  const uint16_t octet = (uint16_t)port / 8;

  if (octet > par->rdata.state.wks.highest_port / 8) {
    // ensure newly used octets are zeroed out before use
    size_t off = 0;
    if (par->rdata.state.wks.highest_port)
      off = par->rdata.state.wks.highest_port / 8 + 1;
    size_t size = ((octet - off) + 1) * sizeof(par->rdata.wks[off]);
    memset(&par->rdata.wks[off], 0, size);
    par->rdata.state.wks.highest_port = port;
    par->rdata.length = par->rdata.state.wks.highest_port / 8 + 1;
  }

  par->rdata.wks[octet] |= (1 << (7 - port % 8));

  return ZONE_DEFER_ACCEPT;
}

#endif // ZONE_WKS_H
