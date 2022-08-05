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
static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

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

  (void)fld;
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if ((ret = zone_parse_ttl(par, tok, &ttl)) < 0)
    return ret;
  assert(ttl <= INT32_MAX);
  par->rdata.int32 = htonl(ttl);
  par->rdata.length = sizeof(par->rdata.int32);
  return ZONE_RDATA | ZONE_INT32;
}

zone_return_t parse_time(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char buf[] = "YYYYmmddHHMMSS";
  const char *end = NULL;
  ssize_t len = -1;
  struct tm tm;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)fld;
  (void)ptr;
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || !(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    SYNTAX_ERROR(par, "{l}: Invalid time in %s", tok, desc->name);
  par->rdata.int32 = htonl(mktime_from_utc(&tm));
  par->rdata.length = sizeof(par->rdata.int32);
  return ZONE_RDATA | ZONE_INT32;
}

zone_return_t parse_int8(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t u64;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)fld;
  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT8_MAX, &u64)) < 0)
    return ret;
  assert(u64 <= UINT8_MAX);
  par->rdata.int8 = (uint8_t)u64;
  par->rdata.length = sizeof(par->rdata.int8);
  return ZONE_RDATA | ZONE_INT8;
}

zone_return_t parse_int16(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t u64;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)fld;
  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT16_MAX, &u64)) < 0)
    return ret;
  assert(u64 <= UINT16_MAX);
  par->rdata.int16 = htons((uint16_t)u64);
  par->rdata.length = sizeof(par->rdata.int16);
  return ZONE_RDATA | ZONE_INT16;
}

zone_return_t parse_int32(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint64_t u64;
  zone_return_t ret;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)fld;
  (void)ptr;
  if ((ret = zone_parse_int(par, desc, tok, UINT32_MAX, &u64)) < 0)
    return ret;
  assert(u64 <= UINT32_MAX);
  par->rdata.int32 = htonl((uint32_t)u64);
  par->rdata.length = sizeof(par->rdata.int32);
  return ZONE_RDATA | ZONE_INT32;
}

zone_return_t parse_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char buf[INET_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)fld;
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    SYNTAX_ERROR(par, "Invalid IPv4 address");
  buf[len] = '\0';
  if (inet_pton(AF_INET, buf, &par->rdata.ip4) != 1)
    SYNTAX_ERROR(par, "Invalid IPv4 address");
  par->rdata.length = sizeof(par->rdata.ip4);
  return ZONE_RDATA | ZONE_IP4;
}

zone_return_t parse_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char buf[INET6_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)fld;
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    SYNTAX_ERROR(par, "Invalid IPv6 address");
  buf[len] = '\0';
  if (inet_pton(AF_INET6, buf, &par->rdata.ip6) != 1)
    SYNTAX_ERROR(par, "Invalid IPv6 address");
  par->rdata.length = sizeof(par->rdata.ip6);
  return ZONE_RDATA | ZONE_IP6;
}

zone_return_t parse_name(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  zone_return_t ret;

  (void)fld;
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if ((ret = zone_parse_name(par, fld->descriptor.rdata, tok, par->rdata.name, &par->rdata.length)) < 0)
    return ret;
  return ZONE_RDATA | ZONE_NAME;
}

zone_return_t parse_type(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  int32_t id;
  uint32_t flags = ZONE_ESCAPED | ZONE_STRICT | ZONE_GENERIC;

  (void)fld;
  (void)ptr;
  id = zone_is_type(tok->string.data, tok->string.length, flags);
  if (id < 0)
    SYNTAX_ERROR(par, "{l}: Invalid escape sequence", tok);
  if (id == 0)
    SEMANTIC_ERROR(par, "{l}: Invalid type in %s", tok, fld->descriptor.rdata->name);
  par->rdata.int16 = htons((uint16_t)id);
  par->rdata.length = sizeof(par->rdata.int16);
  return 0;
}


zone_return_t parse_generic_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t cnt;
  struct in_addr *ip4 = &par->rdata.ip4;

  (void)fld;
  (void)ptr;
  cnt = zone_decode(tok->string.data, tok->string.length, (uint8_t*)ip4, sizeof(*ip4));
  if (cnt != (ssize_t)sizeof(*ip4))
    SEMANTIC_ERROR(par, "Invalid IP4 address");
  par->rdata.length = sizeof(*ip4);
  return 0;
}

zone_return_t parse_generic_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t cnt;
  struct in6_addr *ip6 = &par->rdata.ip6;

  (void)fld;
  (void)ptr;
  cnt = zone_decode(tok->string.data, tok->string.length, (uint8_t*)ip6, sizeof(*ip6));
  if (cnt != (ssize_t)sizeof(*ip6))
    SEMANTIC_ERROR(par, "Invalid IPv6 address");
  par->rdata.length = sizeof(*ip6);
  return 0;
}

zone_return_t parse_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t cnt = 0;
  const char *name = fld->descriptor.rdata->name;
  static const ssize_t max = 255;

  (void)fld;
  (void)ptr;
  cnt = zone_unescape(tok->string.data, tok->string.length,
                      (char *)&par->rdata.string[1], max, 0);
  if (cnt < 0)
    SEMANTIC_ERROR(par, "Invalid escape sequence in %s", name);
  if (cnt > max)
    SEMANTIC_ERROR(par, "Invalid %s, length exceeds maximum", name);
  par->rdata.string[0] = (uint8_t)cnt;
  par->rdata.length = 1 + (size_t)cnt;
  return 0;
}

zone_return_t parse_generic_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  ssize_t len;
  const char *name = fld->descriptor.rdata->name;

  (void)fld;
  (void)ptr;
  len = zone_decode(tok->string.data, tok->string.length,
                    &par->rdata.string[0], 1+255);
  if (len < 0)
    SYNTAX_ERROR(par, "Invalid hexadecimal string or escape sequence in %s", name);
  if (len > 1 + 255)
    SEMANTIC_ERROR(par, "Invalid %s, length exceeds maximum", name);
  if (len > 0 && par->rdata.string[0] != len - 1)
    SEMANTIC_ERROR(par, "Invalid %s, length does not match string length", name);

  // fixup length if maximum (or minimum) is exceeded
  if (len > 1 + 255)
    len = 255;
  else if (len)
    len--;

  par->rdata.length = (size_t)len;
  return ZONE_RDATA | ZONE_STRING;
}

#endif // ZONE_BASE_H
