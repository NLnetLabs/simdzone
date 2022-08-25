/*
 * svcb.h -- parser for svcb rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_SVCB_H
#define ZONE_SVCB_H

#include "lookup.h"
#include "scanner.h"

static inline zone_string_t cut(
  const zone_string_t *str, const zone_string_t *substr)
{
  assert(str);

  size_t unesc = 0, off;

  if (!substr || !substr->data)
    off = 0;
  else
    off = (substr->data - str->data) + substr->length;

  for (size_t cnt=off, esc=0; cnt <= str->length; cnt++) {
    if (cnt == str->length) {
      if (cnt > off)
        return (zone_string_t){ unesc, str->data + off, cnt - off };
      break;
    } else if (esc) {
      esc = 0;
    } else if (str->data[cnt] == '\\') {
      esc = 1;
      if (!unesc)
        unesc = ZONE_ESCAPED;//cnt - off;
    } else if (str->data[cnt] == ',') {
      if (cnt > off) // discard consecutive commas
        return (zone_string_t){ unesc, str->data + off, cnt - off };
      unesc = 0;
      off = cnt + 1;
    }
  }

  return (zone_string_t){ 0, NULL, 0 };
}

static inline zone_return_t get_unknown_svc_param_key(
  const zone_string_t *str, uint16_t *key)
{
  char buf[] = "key65535", *end = NULL;
  size_t len;

  len = zone_unescape(str, buf, sizeof(buf));
  if (len >= sizeof(buf) || len <= 3)
    return -1;
  buf[len] = '\0';
  if (strncasecmp(buf, "key", 3) != 0)
    return -1;
  if (buf[3] < '0' || buf[3] > '9')
    return -1;
  long lng = strtol(&buf[3], &end, 10);
  if (*end || lng < 0 || lng > UINT16_MAX)
    return -1;
  *key = (uint16_t)lng;
  return 0;
}

static inline zone_return_t get_svc_param_key(
  const zone_string_t *str, uint16_t *key)
{
#define X(name, value) { name, sizeof(name) - 1, value }
  static const zone_key_value_t keys[] = {
    X("alpn", 1),
    X("dohpath", 7),
    X("ech", 5),
    X("ipv4hint", 4),
    X("ipv6hint", 6),
    X("mandatory", 0),
    X("no-default-alpn", 2),
    X("port", 3)
  };
#undef X

  static const zone_map_t map = { keys, sizeof(keys)/sizeof(keys[0]) };
  zone_key_value_t *entry;

  if (!(entry = zone_lookup(&map, str)))
    return get_unknown_svc_param_key(str, key);

  *key = (uint16_t)entry->value;
  return 0;
}

static int keycmp(const void *a, const void *b)
{
  return (int)ntohs(*(uint16_t *)a) - (int)ntohs(*(uint16_t *)b);
}

static inline zone_return_t parse_mandatory(
  zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t ret;

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;

  size_t keys = 0;
  const size_t rdlength = par->rdlength;

  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   The presentation value SHALL be a comma-seperatred list of one or more
  //   valid SvcParamKeys, ...
  for (zone_string_t s={0}; (s = cut(&tok->string, &s)).length;) {
    uint16_t key;
    if (get_svc_param_key(&s, &key) == -1)
      SEMANTIC_ERROR(par, "Invalid parameter in mandatory parameter");
    if (par->rdlength > UINT16_MAX - sizeof(key))
      SEMANTIC_ERROR(par, "Invalid record, RDATA too large");
    ((uint16_t *)&par->rdata[par->rdlength])[0] = key;
    par->rdlength += sizeof(key);
    keys++;
  }

  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   In wire format, the keys are represented by their numeric values in
  //   network byte order, concatenated in ascending order.
  qsort(&par->rdata[rdlength], keys, sizeof(uint16_t), keycmp);
  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   Keys MAY appear in any order, but MUST NOT appear more than once.
  for (size_t key=1; key < keys; key++) {
    if (keycmp(&((uint16_t *)&par->rdata[rdlength])[key - 1],
               &((uint16_t *)&par->rdata[rdlength])[key]) == 0)
      SEMANTIC_ERROR(par, "Invalid mandatory, duplicate keys");
  }

  return 0;
}

static inline zone_return_t parse_alpn(
  zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t ret;

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;

  for (zone_string_t s={0}; (s = cut(&tok->string, &s)).length;) {
    size_t n = zone_unescape(&s, (char *)&par->rdata[par->rdlength+1], UINT16_MAX - par->rdlength);
    if (n > UINT8_MAX)
      SEMANTIC_ERROR(par, "Invalid alpn, alpn identifier too large");
    if (1+n > UINT16_MAX - par->rdlength)
      SEMANTIC_ERROR(par, "Invalid record, RDATA too large");
    *((uint16_t *)&par->rdata[par->rdlength]) = (uint16_t)n;
    par->rdlength += 1+n;
  }

  return 0;
}

static inline zone_return_t parse_port(
  zone_parser_t *par, zone_token_t *tok)
{
  static const zone_field_descriptor_t dsc =
    { "port", 4, ZONE_INT16, 0, { 0 }, NULL };

  uint64_t num = 0;
  zone_return_t ret;

  if ((ret = lex_int(par, &dsc, tok, &num)) < 0)
    return ret;
  if (par->rdlength > UINT16_MAX - sizeof(uint16_t))
    SEMANTIC_ERROR(par, "Invalid record, RDATA too large");
  ((uint16_t *)&par->rdata[par->rdlength])[0] = htons((uint16_t)num);
  par->rdlength += sizeof(uint16_t);
  return 0;
}

static inline zone_return_t parse_ech(
  zone_parser_t *par, zone_token_t *tok)
{
  zone_return_t ret;

  if ((ret = parse_base64(par, tok)) < 0)
    return ret;
  if (par->state.base64 != 0 && par->state.base64 != 5)
    SEMANTIC_ERROR(par, "Invalid base64 sequence in ech parameter");

  par->state.base64 = 0;
  return 0;
}

static inline zone_return_t parse_iphint(
  zone_parser_t *par, zone_token_t *tok, int af)
{
  zone_return_t ret;
  const size_t ipsize =
    af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
  const uint16_t iphint =
    af == AF_INET ? 4 : 6;

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;

  par->rdlength += 4;

  for (zone_string_t s={0}; (s = cut(&tok->string, &s)).length;) {
    char buf[INET6_ADDRSTRLEN + 1];
    size_t len = zone_unescape(&s, buf, sizeof(buf));
    if (len >= sizeof(buf))
      SEMANTIC_ERROR(par, "Invalid address in ip%uhint parameter", iphint);
    if (par->rdlength > UINT16_MAX - ipsize)
      SEMANTIC_ERROR(par, "Invalid record, RDATA exceeds maximum");
    buf[len] = '\0';
    if (inet_pton(af, buf, &par->rdata[par->rdlength]) != 1)
      SEMANTIC_ERROR(par, "Invalid address in ip%uhint parameter", iphint);
    par->rdlength += ipsize;
  }

  return 0;
}

static inline zone_return_t parse_ipv4hint(
  zone_parser_t *par, zone_token_t *tok)
{
  return parse_iphint(par, tok, AF_INET);
}

static inline zone_return_t parse_ipv6hint(
  zone_parser_t *par, zone_token_t *tok)
{
  return parse_iphint(par, tok, AF_INET6);
}

static zone_return_t parse_svc_param(
  zone_parser_t *par, zone_token_t *tok)
{
#define X(id, name, empty, function) \
  { id, name, sizeof(name) - 1, empty, function }
  static const struct {
    uint16_t key;
    const char *name;
    size_t length;
    int32_t empty; // { no=0, yes=1, maybe=2 }
    rdata_parse_t parse;
  } params[] = {
    X(0, "mandatory", 0, parse_mandatory),
    X(1, "alpn", 0, parse_alpn),
    X(2, "no-default-alpn", 1, 0),
    X(3, "port", 0, parse_port),
    X(4, "ipv4hint", 0, parse_ipv4hint),
    X(5, "ech", 0, parse_ech),
    X(6, "ipv6hint", 0, parse_ipv6hint),
    X(7, "dohpath", 0, 0)
  };
#undef X

  uint16_t key;

  assert(zone_type(tok->code) == ZONE_STRING);

  // FIXME: update and format this comment nicely to explain what is going on
  // bit of a hack, but we simply increase the position and let the rest of the
  // functions handle it!
  //
  // FIXME: implement zone_lex_until or zone_lex_only?!
  zone_char_t chr;
  while ((chr = zone_get(par, tok))) {
    if (chr < 0)
      return chr;
    if (chr != '=')
      continue;
    // unget the '=' (equals sign) character
    tok->cursor--;
    tok->location.end.column--;
    break;
  }

  // string lengths are updated only when the delimiter is encountered for
  // performance reasons, temporary delimit
  (void)zone_delimit(par, tok);

  if (get_svc_param_key(&tok->string, &key) != 0)
    SEMANTIC_ERROR(par, "Invalid or unsupported key in service parameter");

  // check for duplicate keys here
  const uint16_t oct = (uint16_t)key / 8;
  if (key <= par->state.svcb.highest_key / 8) {
    if (par->state.svcb.bitmap[oct] & (1 << (7 - key % 8)))
      SEMANTIC_ERROR(par, "Duplicate service parameter");
  } else {
    size_t off = 0;
    if (par->state.svcb.highest_key)
      off = par->state.svcb.highest_key / 8 + 1;
    size_t size = ((oct - off) + 1) + sizeof(uint8_t);
    memset(&par->state.svcb.bitmap[off], 0, size);
    par->state.svcb.highest_key = key;
  }

  par->state.svcb.bitmap[oct] |= (1 << (7 - key % 8));


  // discard the '=' (equals sign) character
  if (zone_quick_peek(par, tok->cursor) == '=') {
    tok->cursor++;
    tok->location.end.column++;
  }

  // discard the '"' (double quote) character unless quoted
  if (!(tok->code & ZONE_QUOTED) && zone_quick_peek(par, tok->cursor) == '"') {
    tok->code |= ZONE_QUOTED;
    tok->cursor++;
    tok->location.end.column++;
  }

  // discard the key and proceed normally from here on
  tok->string.data = par->file->buffer.data + tok->cursor;
  tok->string.length = 0;


  if (par->rdlength > UINT16_MAX - 2 * sizeof(uint16_t))
    SEMANTIC_ERROR(par, "Invalid record, RDATA too large");

  zone_return_t ret;
  size_t length;
  const size_t rdlength = par->rdlength;
  par->rdlength += 2 * sizeof(uint16_t);

  if (key < sizeof(params)/sizeof(params[0]) && params[key].parse) {
    if ((ret = params[key].parse(par, tok)) < 0)
      return ret;
    length = (par->rdlength - rdlength) - 2 * sizeof(uint16_t);
  } else {
    if ((ret = zone_lex(par, tok)) < 0)
      return ret;
    length = zone_unescape(
      &tok->string, (char *)&par->rdata[par->rdlength], UINT16_MAX - par->rdlength);
    if (length > UINT16_MAX - par->rdlength)
      SEMANTIC_ERROR(par, "Invalid record, RDATA too large");
    par->rdlength += length;
  }

  ((uint16_t *)&par->rdata[rdlength])[0] = htons(key);
  ((uint16_t *)&par->rdata[rdlength])[1] = htons(length);

  if (key >= sizeof(params)/sizeof(params[0]))
    return 0;
  if (params[key].empty == 0 && length == 0)
    SEMANTIC_ERROR(par, "value exepected for SvcParam");
  if (params[key].empty == 1 && length != 0)
    SEMANTIC_ERROR(par, "SvcParam should not have a value");

  return 0;
}

#endif // ZONE_SVCB_H
