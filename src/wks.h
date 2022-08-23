/*
 * wks.c -- some useful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <stdlib.h>
#include <netdb.h>

#include "parser.h"

static zone_return_t parse_wks_protocol(
  zone_parser_t *par, zone_token_t *tok)
{
  char buf[32];
  size_t len;
  struct protoent *proto;
  zone_return_t ret;

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;
  len = zone_unescape(&tok->string, buf, sizeof(buf));
  if (len >= sizeof(buf))
    SYNTAX_ERROR(par, "Invalid protocol in WKS record");
  buf[len] = '\0';

  if (!(proto = getprotobyname(buf))) {
    char *end = NULL;
    long lng = strtol(buf, &end, 10);
    if (lng < 0 || lng > UINT8_MAX)
      SYNTAX_ERROR(par, "Invalid protocol in WKS record");
    proto = getprotobynumber((int)lng);
  }

  if (!proto)
    SEMANTIC_ERROR(par, "Invalid protocol in WKS record");

  par->state.wks.protocol = proto;
  par->state.wks.highest_port = 0;
  *((uint8_t *)&par->rdata[par->rdlength]) = (uint8_t)proto->p_proto;
  return 0;
}

static zone_return_t parse_wks(
  zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t ret;
  const struct protoent *proto;
  const struct servent *serv;

  assert(par && tok);
  proto = par->state.wks.protocol;
  assert(proto);

  int port;
  char buf[32];

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;
  size_t len = zone_unescape(&tok->string, buf, sizeof(buf));
  if (len >= sizeof(buf))
    SEMANTIC_ERROR(par, "Invalid service");
  buf[len] = '\0';

  if ((serv = getservbyname(buf, proto->p_name))) {
    port = ntohs((uint16_t)serv->s_port);
  } else {
    char *end = NULL;
    const long lng = strtol(buf, &end, 10);
    if (lng < 0 || lng > UINT16_MAX || buf == end || !*end)
      SEMANTIC_ERROR(par, "Invalid service");
    port = (int)lng;
  }

  assert(port >= 0 && port <= UINT16_MAX);
  const uint16_t oct = (uint16_t)port / 8;
  if (oct > par->state.wks.highest_port / 8) {
    // ensure newly used octets are zeroed out before use
    size_t off = 0;
    if (par->state.wks.highest_port)
      off = par->state.wks.highest_port / 8 + 1;
    size_t size = ((oct - off) + 1) * sizeof(uint8_t);
    memset(&par->rdata[par->rdlength + off], 0, size);
    par->state.wks.highest_port = port;
  }

  par->rdata[par->rdlength + oct] |= (1 << (7 - port % 8));

  return 0;
}

static zone_return_t accept_wks(
  zone_parser_t *par, zone_field_t *fld, void *ptr)
{
  const size_t length = par->state.wks.highest_port / 8 + 1;
  par->state.wks.protocol = NULL;
  par->state.wks.highest_port = 0;
  fld->octets = &par->rdata[par->rdlength];
  fld->length = length;
  par->rdlength += length;
  return par->options.accept.rdata(par, fld, ptr);
}
