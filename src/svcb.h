/*
 * svcb.c -- parser for SVCB records in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#ifndef ZONE_SVCB_H
#define ZONE_SVCB_H

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#include "parser.h"
#include "util.h"
#include "base64.h"

typedef struct { size_t off, len; } slice_t;

static slice_t cut(const char *str, size_t off, size_t len)
{
  for (size_t cnt = off, esc = 0; cnt <= len; cnt++) {
    if (cnt == len) {
      if (cnt > off)
        return (slice_t){ off, cnt-off };
      break;
    } else if (str[cnt] == '\\') {
      esc = 1;
    } else if (esc) {
      esc = 0;
    } else if (str[cnt] == ',') {
      if (cnt > off) // discard consecutive commas
        return (slice_t){ off, cnt-off };
      off = cnt + 1;
    }
  }

  return (slice_t){ 0, 0 };
}

struct svc_param {
  uint16_t key;
  const char *name;
  const size_t namelen;
  zone_return_t (*parse)(zone_parser_t *, const zone_token_t *, zone_field_t *, void *);
};

static int svcb_key_cmp(const void *p1, const void *p2)
{
  const struct svc_param *s1 = p1, *s2 = p2;
  assert(s1 && s1->name && s1->namelen);
  assert(s2 && s2->name && s2->namelen);
  return zone_stresccasecmp(s1->name, s1->namelen, s2->name, s2->namelen);
}

static int32_t is_unknown_key(const char *str, size_t len)
{
  char buf[sizeof("key65535")];
  ssize_t cnt;

  if ((cnt = zone_unescape(str, len, buf, sizeof(buf), 0)) < 4)
    return -1;
  if ((size_t)cnt >= sizeof(buf))
    return -1;

  buf[cnt] = '\0';
  if (strncasecmp(buf, "key", sizeof("key") - 1) != 0)
    return -1;

  int32_t key = 0;
  for (cnt=3; buf[cnt] >= '0' && buf[cnt] <= '9'; cnt++)
    key = (key * 10) + (buf[cnt] - '0');
  if (buf[cnt] != '\0' || key > 65535)
    return -1;
  return key;
}

static int32_t find_svcb_key(const char *str, size_t len)
{
  struct svc_param *param, *key = &(struct svc_param){ 0, str, len, 0 };
#define X(name, id) { id, name, sizeof(name) - 1, 0 }
  static const struct svc_param keys[] = {
    X("alpn", 1),
    X("ech", 5),
    X("ipv4hint", 4),
    X("ipv6hint", 6),
    X("mandatory", 0),
    X("no-default-alpn", 2),
    X("port", 3)
  };
#undef X

  static const size_t size = sizeof(keys[0]);
  static const size_t nmemb = sizeof(keys)/size;

  if ((param = bsearch(key, keys, nmemb, size, svcb_key_cmp)))
    return (int32_t)param->key;
  return is_unknown_key(str, len);
}

static int uint16_cmp(const void *a, const void *b)
{
  return ntohs(*(uint16_t *)a) - ntohs(*(uint16_t *)b);
}

static zone_return_t
parse_mandatory(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t size, keycnt = 0;
  uint8_t *octs = par->rdata.svcb;
  uint16_t *keys;
  int32_t key;

  (void)fld;
  (void)ptr;
  assert(tok->svc_param.value.length);

  const char *str = tok->svc_param.value.data;
  const size_t len = tok->svc_param.value.length;

  // count number of keys
  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; keycnt++)
    ;

  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   The presentation value SHALL be a comma-seperatred list of one or more
  //   valid SvcParamKeys, ...
  if (keycnt == 0)
    SEMANTIC_ERROR(par, "{l}: Invalid SvcParam, mandatory requires at least one key", tok);
  if (keycnt > UINT16_MAX / sizeof(uint16_t))
    SEMANTIC_ERROR(par, "{l}: Invalid mandatory, too many addresses", tok);

  par->rdata.length = size = 4 * sizeof(uint8_t) + keycnt * sizeof(uint16_t);
  *((uint16_t *)&octs[0]) = htons(0);
  *((uint16_t *)&octs[2]) = htons(keycnt * sizeof(uint16_t));
  keys = (uint16_t *)&octs[4];
  keycnt = 0;

  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; ) {
    if ((key = find_svcb_key(str+s.off, s.len)) < 0) {
      zone_error(par, "{l}: Invalid key in mandatory SvcParam", tok);
      goto bad_key;
    }
    assert(key >= 0 && key <= 65536);
    keys[keycnt++] = (uint16_t)key;
  }

  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   In wire format, the keys are represented by their numeric values in
  //   network byte order, concatenated in ascending order.
  qsort(keys, keycnt, sizeof(uint16_t), uint16_cmp);
  // draft-ietf-dnsop-svcb-https-08 section 8:
  //   Keys MAY appear in any order, but MUST NOT appear more than once.
  for (size_t i=1; i < keycnt; i++) {
    if (keys[i-1] != keys[i])
      continue;
    zone_error(par, "{l}: Duplicate keys in mandatory SvcParam", tok);
    goto bad_key;
  }

  return 0;
bad_key:
  return ZONE_SEMANTIC_ERROR;
}

static zone_return_t
parse_alpn(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t size = 0, alpncnt = 0;
  uint8_t *alpn, *octs = par->rdata.svcb;
  const char *str = tok->string.data;
  const size_t len = tok->string.length;

  (void)fld;
  (void)ptr;
  // determine amount of memory required
  //   >> do a plain count too, require at least 1 identifier!
  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; ) {
    ssize_t cnt;

    if ((cnt = zone_unescape(str+s.off, s.len, NULL, 0, 1)) < 0)
      SEMANTIC_ERROR(par, "{l}: Invalid alpn, invalid escape sequence in "
                          "identifer", tok);
    if (cnt > 255)
      SEMANTIC_ERROR(par, "{l}: Invalid alpn, identifier exceeds 255 octets");
    if ((size += 1 + (size_t)cnt) > 65535)
      SEMANTIC_ERROR(par, "{l}: Invalid alpn, length exceeds 65535 octets");
    alpncnt++;
  }

  if (alpncnt == 0)
    SEMANTIC_ERROR(par, "{l}: Invalid alpn, at least on identifier is required");

  par->rdata.length = size;
  *((uint16_t *)&octs[0]) = htons(1);
  *((uint16_t *)&octs[2]) = htons((uint16_t)size);
  alpn = &octs[4];
  //alpncnt = 0;

  size_t off = 0;
  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; ) {
    ssize_t cnt;

    cnt = zone_unescape(str+s.off, s.len, (char *)&alpn[off+1], size-(off+1), 0);
    assert(cnt >= 0);
    assert(off + 1 + (size_t)cnt <= size);
    *(uint16_t *)&alpn[off] = htons((uint16_t)cnt);
    off += 1 + (size_t)cnt;
  }

  return 0;
}

static zone_return_t
parse_no_default_alpn(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_NOT_IMPLEMENTED;
}

static zone_return_t
parse_port(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  zone_token_t tmp;
  zone_return_t ret;
  static zone_rdata_descriptor_t dsc = { "port", ZONE_SVC_PARAM, 0, 0, { NULL, 0 }, NULL };
  uint64_t u64;
  uint8_t *octs = par->rdata.svcb;

  (void)fld;
  (void)ptr;
  assert(tok->svc_param.value.length);

  tmp.location = tok->location;
  tmp.code = tok->code;
  tmp.string = tok->svc_param.value;

  if ((ret = zone_parse_int(par, &dsc, &tmp, UINT16_MAX, &u64)) < 0)
    return ret;
  *((uint16_t *)&octs[0]) = htons(3);
  *((uint16_t *)&octs[2]) = htons(sizeof(uint16_t));
  *((uint16_t *)&octs[4]) = htons((uint16_t)u64);
  par->rdata.length = 3 * sizeof(uint16_t);
  return 0;
}

static zone_return_t
parse_ech(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int len;
//  uint8_t *octs;
//  size_t size;
(void)fld;
(void)par;
  (void)ptr;
  assert(tok->svc_param.value.length);
  assert(!tok->svc_param.value.escaped);

  const char *s = tok->svc_param.value.data;
  const size_t n = tok->svc_param.value.length;
  if (n == 1 && s[0] == '0')
    len = 0;
  (void)len;
//  else if ((len = b64_pton(s, n, NULL, 0)) < 0)
//    SEMANTIC_ERROR(par, "{l}: Invalid base64 sequence in ech parameter", tok);
//  else if (len > UINT16_MAX)
//    SEMANTIC_ERROR(par, "{l}: Invalid base64 sequence in ech, "
//                        "value exceeds maximum", tok);
  return ZONE_NOT_IMPLEMENTED;

//  size = 4 * sizeof(uint8_t) + (size_t)len;
//  if (!(octs = zone_malloc(par, size)))
//    return ZONE_OUT_OF_MEMORY;
//  *((uint16_t *)&octs[0]) = htons(5);
//  *((uint16_t *)&octs[2]) = htons((uint16_t)len);
//  if (len > 0)
//    b64_pton(s, n, &octs[4], (size_t)len);
//  fld->svc_param.length = size;
//  fld->svc_param.octets = octs;
//  return 0;
}

static inline int zone_inet_pton(
  int af, const char *restrict src, size_t len, void *restrict dst)
{
  char buf[INET6_ADDRSTRLEN + 1];
  size_t max;
  ssize_t cnt;

  if ((cnt = zone_unescape(src, len, buf, sizeof(buf), 0)) < 0)
    return -1;

  if (af == AF_INET)
    max = INET_ADDRSTRLEN;
  else if (af == AF_INET6)
    max = INET6_ADDRSTRLEN;
  else
    return -1;
  assert(sizeof(buf) <= max + 1);
  if ((size_t)cnt > max)
    return -1;
  //memcpy(src, buf, (size_t)cnt);
  buf[cnt] = '\0';
  return inet_pton(af, buf, dst);
}

#define INET_ADDRSIZE (sizeof(struct in_addr))
#define INET6_ADDRSIZE (sizeof(struct in6_addr))

// FIXME: test with varying inputs. should discard consecutive commas. e.g.
//        ",::1,,", ",," and "::1," must all be handled correctly
static zone_return_t
parse_iphint(
  int af, zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t size, ipcnt = 0;
  uint8_t *ips, *octs = par->rdata.svcb;

  const char *param = af == AF_INET ? "ipv4hint" : "ipv6hint";
  const size_t ipsize = af == AF_INET ? INET_ADDRSIZE : INET6_ADDRSIZE;
  const uint16_t iphint = af == AF_INET ? 4 : 6;

  (void)fld;
  (void)ptr;
  assert(tok->svc_param.value.length);

  const char *str = tok->svc_param.value.data;
  const size_t len = tok->svc_param.value.length;
  // count number of addresses in ipvXhint
  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; ipcnt++) ;

  if (ipcnt > UINT16_MAX / ipsize)
    SEMANTIC_ERROR(par, "{l}: Invalid %s, too many addresses", tok, param);

  size = 4 * sizeof(uint8_t) + ipcnt * ipsize;
  *((uint16_t *)&octs[0]) = htons(iphint);
  *((uint16_t *)&octs[2]) = htons(ipcnt * ipsize);
  ips = &octs[4];
  ipcnt = 0;

  for (slice_t s={0,0}; (s = cut(str, s.off+s.len, len)).len; ) {
    if (zone_inet_pton(af, str+s.off, s.len, &ips[ipsize * ipcnt++]) < 0)
      goto bad_ip;
  }

  par->rdata.length = size;
  return 0;
bad_ip:
  SEMANTIC_ERROR(par, "{l}: Invalid %s, invalid address(es)", tok, param);
  return ZONE_SEMANTIC_ERROR;
}

static zone_return_t
parse_ipv4hint(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  return parse_iphint(AF_INET, par, tok, fld, ptr);
}

static zone_return_t
parse_ipv6hint(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  return parse_iphint(AF_INET6, par, tok, fld, ptr);
}

#define SVCB_KEY(id, name, function) { id, name, sizeof(name) - 1, function }
static const struct svc_param svc_params[] = {
  SVCB_KEY(0, "mandatory", parse_mandatory),
  SVCB_KEY(1, "alpn", parse_alpn),
  SVCB_KEY(2, "no-default-alpn", parse_no_default_alpn),
  SVCB_KEY(3, "port", &parse_port),
  SVCB_KEY(4, "ipv4hint", parse_ipv4hint),
  SVCB_KEY(5, "ech", parse_ech),
  SVCB_KEY(6, "ipv6hint", parse_ipv6hint)
};
#undef SVCB_KEY


static inline zone_return_t parse_svc_param(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int32_t key;
  ssize_t size;
  uint8_t *octs = par->rdata.svcb;

  assert((tok->code & ZONE_SVC_PARAM) == ZONE_SVC_PARAM);
  assert(tok->svc_param.key.data);
  assert(tok->svc_param.key.length);
  size_t len = tok->svc_param.key.length;
  const char *str = tok->svc_param.key.data;

  if ((key = find_svcb_key(str, len)) < 0)
    SEMANTIC_ERROR(par, "{l}: Invalid SvcParam, unsupported key", tok);
  if ((size_t)key <= sizeof(svc_params)/sizeof(svc_params[0]))
    return svc_params[key].parse(par, tok, fld, ptr);

  // unknown key
  str = tok->svc_param.value.data;
  len = tok->svc_param.value.length;
  if (!str || !len)
    size = 0;
  else if ((size = zone_unescape(str, len, NULL, 0, 1)) < 0)
    SEMANTIC_ERROR(par, "{l}: Invalid SvcParam (%u), invalid escape sequence "
                        "in value", tok, (uint16_t)key);
  else if ((size_t)size > 65535 - (4 * sizeof(uint8_t)))
    SEMANTIC_ERROR(par, "{l}: Invalid SvcParam (%u), value exceeds maximum "
                        "length", tok, (uint16_t)key);

  //if (!(octs = zone_malloc(par, 4 * sizeof(uint8_t) + (size_t)size)))
  //  return ZONE_OUT_OF_MEMORY;

  *(uint16_t *)&octs[0] = htons(key);
  *(uint16_t *)&octs[2] = htons((uint16_t)size);
  if (size)
    (void)zone_unescape(str, len, (char *)&octs[4], size, 1);

  par->rdata.length = 4 * sizeof(uint8_t) + (size_t)size;
  //fld->svc_param.length = 4 * sizeof(uint8_t) + (size_t)size;
  //fld->svc_param.octets = octs;
  return 0;
}

#endif // ZONE_SVCB_H
