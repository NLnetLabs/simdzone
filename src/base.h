/*
 * base.h -- parser for basic rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#ifndef ZONE_BASE_H
#define ZONE_BASE_H

#define _XOPEN_SOURCE
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "parser.h"

#include "base64.h"

/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int
is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int
leap_days(int y1, int y2)
{
    --y1;
    --y2;
    return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
time_t
mktime_from_utc(const struct tm *tm)
{
    int year = 1900 + tm->tm_year;
    time_t days = 365 * (year - 1970) + leap_days(1970, year);
    time_t hours;
    time_t minutes;
    time_t seconds;
    int i;

    for (i = 0; i < tm->tm_mon; ++i) {
        days += mdays[i];
    }
    if (tm->tm_mon > 1 && is_leap_year(year)) {
        ++days;
    }
    days += tm->tm_mday - 1;

    hours = days * 24 + tm->tm_hour;
    minutes = hours * 60 + tm->tm_min;
    seconds = minutes * 60 + tm->tm_sec;

    return seconds;
}

zone_return_t parse_ttl(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint32_t ttl;
  zone_return_t ret;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if ((ret = zone_parse_ttl(par, tok, &ttl)) < 0)
    return ret;
  assert(ttl <= INT32_MAX);
  fld->int32 = htonl(ttl);
  return ZONE_RDATA;
}

zone_return_t parse_time(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char buf[] = "YYYYmmddHHMMSS";
  const char *end = NULL;
  ssize_t len = -1;
  struct tm tm;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)ptr;
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || !(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    SYNTAX_ERROR(par, "{l}: Invalid time in %s", tok, desc->name);
  fld->int32 = htonl(mktime_from_utc(&tm));
  return ZONE_RDATA;
}

zone_return_t parse_int8(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t u64;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT8_MAX, &u64)) < 0)
    return ret;
  assert(u64 <= UINT8_MAX);
  fld->int8 = (uint8_t)u64;
  return ZONE_RDATA;
}

zone_return_t parse_int16(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t u64;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT16_MAX, &u64)) < 0)
    return ret;
  assert(u64 <= UINT16_MAX);
  fld->int16 = htons((uint16_t)u64);
  return ZONE_RDATA;
}

zone_return_t parse_int32(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t num;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT32_MAX, &num)) < 0)
    return ret;
  assert(num <= UINT32_MAX);
  fld->int32 = htonl((uint32_t)num);
  return ZONE_RDATA;
}

zone_return_t parse_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in_addr *ip4 = NULL;
  char buf[INET_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    goto bad_ip;
  buf[len] = '\0';
  if (!(ip4 = zone_malloc(par, sizeof(*ip4))))
    return ZONE_OUT_OF_MEMORY;
  if (inet_pton(AF_INET, buf, ip4) != 1)
    goto bad_ip;
  fld->ip4 = ip4;
  return ZONE_RDATA;
bad_ip:
  if (ip4)
    zone_free(par, ip4);
  SYNTAX_ERROR(par, "Invalid IPv4 address at {l}", &tok);
}

zone_return_t parse_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in6_addr *ip6 = NULL;
  char buf[INET6_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)ptr;
  assert((tok->code & 0xf00) == ZONE_STRING);
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    goto bad_ip;
  buf[len] = '\0';
  if (!(ip6 = zone_malloc(par, sizeof(*ip6))))
    return ZONE_OUT_OF_MEMORY;
  if (inet_pton(AF_INET6, buf, ip6) != 1)
    goto bad_ip;
  fld->ip6 = ip6;
  return ZONE_RDATA;
bad_ip:
  if (ip6)
    zone_free(par, ip6);
  SYNTAX_ERROR(par, "Invalid IPv6 address at {l}", &tok);
}

zone_return_t parse_domain_name(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t len;
  uint8_t name[255];
  zone_return_t ret;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if ((ret = zone_parse_name(par, fld->descriptor.rdata, tok, name, &len)) < 0)
    return ret;
  assert(len <= 255);

  fld->name.length = (uint8_t)len;
  fld->name.octets = name;

  if (par->options.accept.name) {
    const void *ref;

    if (!(ref = par->options.accept.name(par, fld, ptr)))
      return ZONE_OUT_OF_MEMORY;
    fld->code = ZONE_RDATA | ZONE_DOMAIN;
    fld->domain = ref;
  } else {
    if (!(fld->name.octets = zone_malloc(par, (size_t)len)))
      return ZONE_OUT_OF_MEMORY;
    memcpy(fld->name.octets, name, (size_t)len);
  }

  return ZONE_RDATA;
}

zone_return_t parse_type(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int32_t id;
  uint32_t flags = ZONE_ESCAPED | ZONE_STRICT | ZONE_GENERIC;

  (void)ptr;
  id = zone_is_type(tok->string.data, tok->string.length, flags);
  if (id < 0)
    SYNTAX_ERROR(par, "{l}: Invalid escape sequence", tok);
  if (id == 0)
    SEMANTIC_ERROR(par, "{l}: Invalid type in %s", tok, fld->descriptor.rdata->name);
  fld->int16 = htons((uint16_t)id);
  return ZONE_RDATA;
}


zone_return_t parse_generic_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in_addr *ip4;
  ssize_t sz;

  (void)ptr;
  if (!(ip4 = zone_malloc(par, sizeof(*ip4))))
    return ZONE_OUT_OF_MEMORY;
  sz = zone_decode(tok->string.data, tok->string.length, (uint8_t*)ip4, sizeof(*ip4));
  if (sz != (ssize_t)sizeof(*ip4))
    goto bad_ip;
  fld->ip4 = ip4;
  return ZONE_RDATA;
bad_ip:
  if (ip4)
    zone_free(par, ip4);
  SEMANTIC_ERROR(par, "Invalid IPv4 address at {l}", &tok);
  return ZONE_SEMANTIC_ERROR;
}

zone_return_t parse_generic_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in6_addr *ip6;
  ssize_t sz;

  (void)ptr;
  if (!(ip6 = zone_malloc(par, sizeof(*ip6))))
    return ZONE_OUT_OF_MEMORY;
  sz = zone_decode(tok->string.data, tok->string.length, (uint8_t *)ip6, sizeof(*ip6));
  if (sz != (ssize_t)sizeof(*ip6))
    goto bad_ip;
  fld->ip6 = ip6;
  return ZONE_RDATA;
bad_ip:
  if (ip6)
    zone_free(par, ip6);
  SEMANTIC_ERROR(par, "Invalid IPv6 address at {l}", &tok);
  return ZONE_SEMANTIC_ERROR;
}

zone_return_t parse_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t len = 0;
  char buf[255];
  const char *str, *name = fld->descriptor.rdata->name;

  (void)ptr;
  if (tok->string.escaped) {
    str = buf;
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  } else {
    str = tok->string.data;
    len = tok->string.length;
  }

  if (len < 0)
    SYNTAX_ERROR(par, "Invalid escape sequence in %s", name);
  if (len > 255)
    SEMANTIC_ERROR(par, "Invalid %s, length exceeds maximum", name);
  // trim input if instructed to be leanient for compatibilty with NSD
  if (len > 255)
    len = 255;
  if (!(fld->string = zone_malloc(par, 1 + (size_t)len)))
    return ZONE_OUT_OF_MEMORY;

  memcpy(fld->string + 1, str, (size_t)len);
  *fld->string = (uint8_t)len;
  return ZONE_RDATA;
}

zone_return_t parse_generic_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t len;
  uint8_t buf[1 /* length */ + 255 /* maximum length */];
  const char *name = fld->descriptor.rdata->name;

  (void)ptr;
  len = zone_decode(tok->string.data, tok->string.length, buf, sizeof(buf));
  if (len < 0)
    SYNTAX_ERROR(par, "Invalid hexadecimal string or escape sequence in %s", name);
  if (len > 1 + 255)
    SEMANTIC_ERROR(par, "Invalid %s, length exceeds maximum", name);
  if (len > 0 && buf[0] != len - 1)
    SEMANTIC_ERROR(par, "Invalid %s, length does not match string length", name);

  // fixup length if maximum (or minimum) is exceeded
  if (len > 1 + 255)
    len = 255;
  else if (len)
    len--;

  if (!(fld->string = zone_malloc(par, 1 + (size_t)len)))
    return ZONE_OUT_OF_MEMORY;

  memcpy(fld->string + 1, buf, (size_t)len);
  *fld->string = (uint8_t)len;
  return ZONE_RDATA | ZONE_STRING;
}

static inline zone_return_t parse_binary(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)ptr;
  assert(fld);
  assert(fld->descriptor.rdata);
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  const char *str = tok->string.data;
  const size_t len = tok->string.length;

  const char *name = fld->descriptor.rdata->name;
  const size_t off = !(fld->descriptor.rdata->qualifiers & ZONE_UNBOUNDED);
  const ssize_t cnt = zone_decode(str, len, NULL, 0);

  if (cnt < 0)
    SYNTAX_ERROR(par, "Invalid %s, non-hexadecimal string or bad escape sequence", name);
  if (off && cnt > 1 + 255)
    SEMANTIC_ERROR(par, "Invalid %s, length exceeds maximum", name);

  uint8_t *octs;
  if (!(octs = zone_malloc(par, off + (size_t)cnt)))
    return ZONE_OUT_OF_MEMORY;
  if (off)
    octs[0] = (size_t)cnt;
  zone_decode(str, len, &octs[off], (size_t)cnt);
  fld->binary.length = off + (size_t)cnt;
  fld->binary.octets = octs;
  return 0;
}

static inline zone_return_t parse_generic_binary(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_NOT_IMPLEMENTED;
}

#endif // ZONE_BASE_H
