/*
 * parser.c -- recursive descent parser for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#define _XOPEN_SOURCE
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "parser.h"
#include "lookup.h"

static inline uint64_t multiply(uint64_t lhs, uint64_t rhs, uint64_t max)
{
  return (max < lhs || (lhs && max / lhs < rhs)) ? max + 1 : lhs * rhs;
}

static inline uint64_t add(uint64_t lhs, uint64_t rhs, uint64_t max)
{
  return (max < lhs ||  max - lhs < rhs) ? max + 1 : lhs + rhs;
}

static inline uint32_t is_unit(char c)
{
  static const uint32_t s = 1u, m = 60u*s, h = 60u*m, d = 24u*h, w = 7u*d;

  switch (c) {
    case 's':
    case 'S':
      return s;
    case 'm':
    case 'M':
      return m;
    case 'h':
    case 'H':
      return h;
    case 'd':
    case 'D':
      return d;
    case 'w':
    case 'W':
      return w;
  }

  return 0;
}

static inline zone_return_t lex_ttl(
  zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc,
  zone_token_t *__restrict tok,
  uint32_t *__restrict ttl)
{
  uint64_t num = 0, sum = 0, fact = 0;
  enum { INITIAL, NUMBER, UNIT } state = INITIAL;

  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  // FIXME: assert dsc refers to TTL!

  for (zone_char_t c; ; ) {
    if ((c = zone_get(par, tok)) < 0)
      return c;
    if (!c)
      break;
    c &= 0xff;
    uint64_t u;

    switch (state) {
      case INITIAL:
        // ttls must start with a number
        if (c < '0' || c > '9') {
          if (par->state.scanner & ZONE_RR)
            return ZONE_SEMANTIC_ERROR;
          SEMANTIC_ERROR(par, "Invalid ttl in %s", dsc->name);
        }
        state = NUMBER;
        num = (c & 0xff) - '0';
        break;
      case NUMBER:
        if (c >= '0' && c <= '9') {
          num = add(multiply(num, 10, INT32_MAX), c - '0', INT32_MAX);
        } else if ((u = is_unit(c))) {
          // units must not be repeated e.g. 1m1m
          if (fact == u) {
            if (par->state.scanner & ZONE_RR)
              return ZONE_SEMANTIC_ERROR;
            SYNTAX_ERROR(par, "Invalid ttl in %s, reuse of unit %c", dsc->name, c);
          }
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (fact && fact < u) {
            if (par->state.scanner & ZONE_RR)
              return ZONE_SEMANTIC_ERROR;
            SYNTAX_ERROR(par, "Invalid ttl in %s, unit %c follows smaller unit", dsc->name, c);
          }
          num = multiply(num, (fact = u), INT32_MAX);
          state = UNIT;
        } else {
          if (par->state.scanner & ZONE_RR)
            return ZONE_SEMANTIC_ERROR;
          SYNTAX_ERROR(par, "Invalid ttl in %s, invalid unit %c", dsc->name, c);
        }
        break;
      case UNIT:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (c < '0' || c > '9') {
          if (par->state.scanner & ZONE_RR)
            return ZONE_SEMANTIC_ERROR;
          SYNTAX_ERROR(par, "Invalid ttl in %s, non-digit follows unit", dsc->name);
        }
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (fact == 1) {
          if (par->state.scanner & ZONE_RR)
            return ZONE_SEMANTIC_ERROR;
          SYNTAX_ERROR(par, "Invalid ttl in %s, seconds already specified", dsc->name);
        }
        sum = add(sum, num, INT32_MAX);
        num = c - '0';
        state = NUMBER;
        break;
    }
  }

  sum = add(sum, num, (uint64_t)INT32_MAX);
  // FIXME: comment RFC2308 msb
  if (sum > (uint64_t)INT32_MAX) {
    if (par->state.scanner & ZONE_RR)
      return ZONE_SEMANTIC_ERROR;
    SEMANTIC_ERROR(par, "Invalid ttl at {l}, most significant bit set");
  }
  *ttl = sum;
  return 0;
}

static inline zone_return_t lex_int(
  zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc,
  zone_token_t *__restrict tok,
  uint64_t *__restrict num)
{
  uint64_t sum = 0u, max;

  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  assert(!dsc->labels.sorted || dsc->labels.length);

  switch (zone_type(dsc->type)) {
    case ZONE_STRING:
      assert(dsc->qualifiers & ZONE_BASE16);
      // fall through
    case ZONE_INT8:
      max = UINT8_MAX;
      break;
    case ZONE_INT16:
      max = UINT16_MAX;
      break;
    default:
      assert(zone_type(dsc->type) == ZONE_INT32);
      max = UINT32_MAX;
      break;
  }

  for (;;) {
    zone_char_t chr = zone_get(par, tok);
    switch (chr & 0xff) {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        sum *= 10;
        sum += (chr & 0xff) - '0';
        if (sum > max)
          SEMANTIC_ERROR(par, "Value for %s exceeds maximum", dsc->name);
        break;
      case '\0':
        *num = sum;
        return 0;
      default:
        if (chr < 0)
          return chr;
        if (!dsc->labels.sorted)
          SEMANTIC_ERROR(par, "Invalid integer in %s", dsc->name);
        
      {
        zone_return_t ret;
        zone_key_value_t *lab;

        if ((ret = zone_lex(par, tok)) < 0)
          return ret;
        if (!(lab = zone_lookup(&dsc->labels, &tok->string)))
          SEMANTIC_ERROR(par, "Expected an integer value for %s", dsc->name);
        if (lab->value > max)
          SEMANTIC_ERROR(par, "Value for %s exceeds maximum", dsc->name);
        *num = lab->value;
        return 0;
      }
    }
  }

  abort();
}

static zone_return_t lex_name(
  zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc,
  zone_token_t *__restrict tok,
  const void **ref,
  uint8_t str[255],
  size_t *len)
{
  size_t lab = 0, oct = 1;
  zone_token_t at = *tok;

  // a freestanding "@" denotes the current origin
  if (zone_get(par, &at) == '@' && !zone_get(par, &at)) {
    memcpy(str, par->file->origin.name.octets, *len);
    *len = par->file->origin.name.length;
    *ref = par->file->origin.domain;
    *tok = at;
    return 0;
  }

  for (zone_char_t chr; (chr = zone_get(par, tok)) >= 0;) {
    if (oct >= 255)
      SYNTAX_ERROR(par, "Invalid name in %s, length exceeds maximum", dsc->name);

    if (chr == '.' || chr == '\0') { // << not based on length anymore, so don't need the == '\0'
      if (oct - 1 == lab && chr == '.')
        SYNTAX_ERROR(par, "Invalid name in %s, empty label", dsc->name);
      else if ((oct - lab) - 1 > 63)
        SYNTAX_ERROR(par, "Invalid name in %s, label length exceeds maximum", dsc->name);
      str[lab] = (oct - lab) - 1;
      if (chr != '.')
        break;
      lab = oct++;
      str[lab] = 0;
    } else {
      str[oct++] = chr & 0xff;
    }
  }

  if (str[lab] != 0) {
    if (oct >= 255 - par->file->origin.name.length)
      SYNTAX_ERROR(par, "Invalid name in %s, name length exceeds maximum", dsc->name);
    memcpy(&str[oct], par->file->origin.name.octets, par->file->origin.name.length);
    oct += par->file->origin.name.length;
  }

  *ref = NULL;
  *len = oct;
  return 0;
}

#include "types.h"

static inline zone_return_t lex_type(
  zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc,
  zone_token_t *__restrict tok,
  uint16_t *type)
{
  zone_return_t ret;
  const zone_key_value_t *ent;
  static const zone_map_t map = { types, sizeof(types)/sizeof(types[0]) };

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;

  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if ((ent = zone_lookup(&map, &tok->string)) && (*type = (uint16_t)ent->value))
    return 0;

  // support unknown DNS record types (rfc3597)
  char buf[32];
  size_t len;
  uint32_t num = 0;
  len = zone_unescape(&tok->string, buf, sizeof(buf));

  if (len <= 4 || strncasecmp(buf, "TYPE", 4) != 0)
    goto bad_type;

  for (size_t cnt=0; cnt < len; cnt++) {
    if (buf[cnt] < '0' || buf[cnt] > '9')
      goto bad_type;
    num *= 10;
    num += (uint32_t)buf[cnt] - '0';
    if (num > UINT16_MAX)
      goto bad_type;
  }

  *type = (uint16_t)num;
  return 0;
bad_type:
  if (par->state.scanner & ZONE_RR)
    return ZONE_SEMANTIC_ERROR;
  SEMANTIC_ERROR(par, "Invalid type in %s", dsc->name);
}

static inline zone_return_t lex_class(
  zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc,
  zone_token_t *__restrict tok,
  uint16_t *class)
{
  char buf[32];
  ssize_t len;
  zone_return_t ret;

  if ((ret = zone_lex(par, tok)) < 0)
    return ret;

  len = zone_unescape(&tok->string, buf, sizeof(buf));
  if (len < 2)
    goto bad_class;
  else if (len > 2)
    goto generic_class;
  else if (strncasecmp(buf, "IN", 2) == 0)
    *class = 1;
  else if (strncasecmp(buf, "CH", 2) == 0)
    *class = 2;
  else if (strncasecmp(buf, "CS", 2) == 0)
    *class = 3;
  else if (strncasecmp(buf, "HS", 2) == 0)
    *class = 4;
  else
    goto bad_class;

  return ZONE_INT32;
generic_class:
  // support unknown DNS class (rfc 3597)
  if (len <= 5 || strncasecmp(buf, "CLASS", 5) != 0)
    goto bad_class;

  uint32_t num = 0;
  for (size_t cnt = 5; cnt < (size_t)len; cnt++) {
    if (buf[cnt] < '0' || buf[cnt] > '9')
      goto bad_class;
    num *= 10;
    num += (uint32_t)(buf[cnt] - '0');
    if (num >= UINT16_MAX)
      goto bad_class;
  }

  *class = (uint16_t)num;
  return ZONE_INT32;
bad_class:
  if (par->state.scanner & ZONE_CLASS)
    return ZONE_SEMANTIC_ERROR;
  SEMANTIC_ERROR(par, "Invalid class in %s", dsc->name);
}

static zone_return_t parse_ttl(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint32_t ttl = 0;
  zone_return_t ret;

  if ((ret = lex_ttl(par, par->rr.descriptors.rdata, tok, &ttl)) < 0)
    return ret;
  assert(ttl <= INT32_MAX);
  par->rdata.int32 = htonl(ttl);
  par->rdata.length = sizeof(par->rdata.int32);
  return 0;
}

static zone_return_t parse_type(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint16_t type;
  zone_return_t ret;

  if ((ret = lex_type(par, par->rr.descriptors.rdata, tok, &type)) < 0)
    return ret;
  par->rdata.int16 = htons((uint16_t)type);
  par->rdata.length = sizeof(par->rdata.int16);
  return 0;
}

/* Number of days per month (except for February in leap years). */
static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static int is_leap_year(int year)
{
  return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int leap_days(int y1, int y2)
{
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
static time_t mktime_from_utc(const struct tm *tm)
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

static zone_return_t parse_time(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  char buf[] = "YYYYmmddHHMMSS";
  size_t len = 0;
  zone_char_t chr;

  while ((chr = zone_get(par, tok)) > 0) {
    buf[len++] = chr & 0xff;
    if (len == sizeof(buf))
      goto bad_time;
  }

  if (chr < 0)
    return chr;
  buf[len] = '\0';

  const char *end = NULL;
  struct tm tm;
  if (!(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    goto bad_time;
  par->rdata.int32 = htonl(mktime_from_utc(&tm));
  par->rdata.length = sizeof(par->rdata.int32);
  return 0;
bad_time:
  SEMANTIC_ERROR(par, "Invalid time in %s", par->rr.descriptors.rdata->name);
}

static zone_return_t parse_int8(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint64_t num;
  zone_return_t ret;

  if ((ret = lex_int(par, par->rr.descriptors.rdata, tok, &num)) < 0)
    return ret;
  assert(num <= INT8_MAX);
  par->rdata.int8 = (uint8_t)num;
  par->rdata.length = sizeof(par->rdata.int8);
  return 0;
}

static zone_return_t parse_int16(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint64_t num;
  zone_return_t ret;

  if ((ret = lex_int(par, par->rr.descriptors.rdata, tok, &num)) < 0)
    return ret;
  assert(num <= UINT16_MAX);
  par->rdata.int16 = htons((uint16_t)num);
  par->rdata.length = sizeof(par->rdata.int16);
  return 0;
}

static zone_return_t parse_int32(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint64_t num;
  zone_return_t ret;

  if ((ret = lex_int(par, par->rr.descriptors.rdata, tok, &num)) < 0)
    return ret;
  assert(num <= UINT32_MAX);
  par->rdata.int32 = htonl((uint32_t)num);
  par->rdata.length = sizeof(par->rdata.int32);
  return 0;
}

static zone_return_t parse_ip4(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  char buf[INET_ADDRSTRLEN + 1];
  size_t len = 0;

  for (zone_char_t chr; (chr = zone_get(par, tok));) {
    if (chr < 0)
      return chr;
    buf[len++] = chr & 0xff;
    if (len == sizeof(buf))
      goto bad_ip;
  }
  buf[len] = '\0';
  if (inet_pton(AF_INET, buf, &par->rdata.ip4) != 1)
    goto bad_ip;
  par->rdata.length = sizeof(par->rdata.ip4);
  return 0;
bad_ip:
  SYNTAX_ERROR(par, "Invalid IPv4 address in %s", par->rr.descriptors.rdata->name);
}

static zone_return_t parse_ip6(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  char buf[INET6_ADDRSTRLEN + 1];
  size_t len = 0;

  for (zone_char_t chr; (chr = zone_get(par, tok));) {
    if (chr < 0)
      return chr;
    buf[len++] = chr & 0xff;
    if (len == sizeof(buf))
      goto bad_ip;
  }
  buf[len] = '\0';
  if (inet_pton(AF_INET6, buf, &par->rdata.ip6) != 1)
    goto bad_ip;
  par->rdata.length = sizeof(par->rdata.ip6);
  return 0;
bad_ip:
  SYNTAX_ERROR(par, "Invalid IPv6 address in %s", par->rr.descriptors.rdata->name);
}

#define OWNER (0)
#define TTL (1)
#define CLASS (2)
#define TYPE (3)
#define RDATA (4)

static zone_return_t parse_name(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  const zone_field_descriptor_t *dsc = par->rr.descriptors.rdata;
  return lex_name(par, dsc, tok, &par->rr.fields[RDATA].domain, par->rdata.name, &par->rdata.length);
}

static zone_return_t parse_string(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  zone_char_t chr;
  size_t len = 1;

  while ((chr = zone_get(par, tok)) > 0) {
    if (len == sizeof(par->rdata.string))
      SEMANTIC_ERROR(par, "String is too large!");
    par->rdata.string[len++] = chr & 0xff;
  }

  if (chr < 0)
    return chr;
  par->rdata.string[0] = len - 1;
  par->rdata.length = len;
  return 0;
}

#include "base16.h"
#include "base32.h"
#include "base64.h"
#include "nsec.h"
#include "wks.h"
#include "grammar.h"

static inline zone_return_t parse_generic_rdata(
  zone_parser_t *__restrict par,
  zone_token_t *__restrict tok,
  void *__restrict ptr)
{
  (void)par;
  (void)tok;
  (void)ptr;
  return ZONE_NOT_IMPLEMENTED;
}

static inline bool is_last_rdata(
  const zone_parser_t *__restrict par,
  const zone_field_descriptor_t *__restrict dsc)
{
  (void)par;
  if (!dsc->type)
    return true;
  else switch (dsc->type) {
    case ZONE_NSEC:
    case ZONE_WKS:
    case ZONE_SVC_PARAM:
      return true;
    default:
      if (dsc->qualifiers & (ZONE_OPTIONAL|ZONE_SEQUENCE))
        return true;
      break;
  }

  return false;
}

static inline zone_return_t accept_rdata(
  zone_parser_t *__restrict par,
  zone_field_t *__restrict fld,
  void *__restrict ptr)
{
  zone_return_t ret;
  const struct rdata_descriptor *dsc;

  dsc = (const struct rdata_descriptor *)par->rr.descriptors.rdata;
  assert(dsc);

  // FIXME: call accept name here if type is ZONE_NAME
  fld->domain = NULL;

  if (dsc->accept)
    ret = dsc->accept(par, fld, ptr);
  else
    ret = par->options.accept.rdata(par, fld, ptr);

  par->rdata.length = 0;

  if (ret < 0)
    return ret;
  par->state.scanner &= ~ZONE_DEFERRED_RDATA;
  // forward descriptor unless the current descriptor is known to be last
  if (!is_last_rdata(par, (const void *)dsc))
    par->rr.descriptors.rdata = (const void *)(dsc+1);

  return 0;
}

static inline zone_return_t parse_rdata(
  zone_parser_t *__restrict par,
  zone_token_t *__restrict tok,
  void *__restrict ptr)
{
  zone_return_t ret;

  for (;;) {
    if ((ret = zone_scan(par, tok)) < 0)
      return ret;

    if (ret == '\n' || ret == '\0') {
      zone_field_t fld;

      if (par->state.scanner & ZONE_DEFERRED_RDATA) {
        fld = par->rr.fields[RDATA];
        assert(!fld.wire.octets && !fld.wire.length);
        fld.wire.octets = par->rdata.base64;
        fld.wire.length = par->rdata.length;
        if ((ret = accept_rdata(par, &fld, ptr)) < 0)
          return ret;
      }

      fld = (zone_field_t){
        .location = tok->location,
        .code = ZONE_RDATA | ZONE_INT8,
        .int8 = (uint8_t)ret & 0xff
      };
      const struct rdata_descriptor *dsc = (const void *)par->rr.descriptors.rdata;
      if (!is_last_rdata(par, (const void *)dsc))
        SEMANTIC_ERROR(par, "Missing rdata field %s", dsc->base.name);
      if ((ret = par->options.accept.delimiter(par, &fld, ptr)) < 0)
        return ret;

      zone_flush(par, tok);
      par->rr.descriptors.type = NULL;
      par->rr.descriptors.rdata = NULL;
      break;
    } else {
      const struct rdata_descriptor *dsc = (const void *)par->rr.descriptors.rdata;
      zone_field_t fld;

      assert((ret & ZONE_STRING));

      if (!dsc->base.type)
        SEMANTIC_ERROR(par, "Too much rdata fields");

      if (par->state.scanner & ZONE_DEFERRED_RDATA)
        fld = par->rr.fields[RDATA];
      else
        fld = (zone_field_t){
          .location = tok->location,
          .code = ZONE_RDATA | zone_type(dsc->base.type),
          .descriptor.rdata = (const void *)dsc,
          .wire = { .length = 0, .octets = NULL }
        };

      assert((uintptr_t)fld.descriptor.rdata == (uintptr_t)dsc);

      if ((ret = dsc->typed(par, tok)) == ZONE_DEFER_ACCEPT) {
        fld.location.end = tok->location.end;
        par->rr.fields[RDATA] = fld;
        par->state.scanner |= ZONE_DEFERRED_RDATA;
      } else if (ret < 0) {
        return ret;
      } else {
        fld.location.end = tok->location.end;
        assert(!fld.wire.octets && !fld.wire.length);
        fld.wire.octets = par->rdata.base64;
        fld.wire.length = par->rdata.length;
        if ((ret = accept_rdata(par, &fld, ptr)) < 0)
          return ret;
      }
      zone_flush(par, tok);
    }
  }

  return 0;
}

static inline zone_return_t parse_owner(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  static const zone_field_descriptor_t dsc =
    { "owner", 5, ZONE_OWNER|ZONE_NAME, 0, { 0 }, NULL };
  zone_return_t ret;

  if ((ret = lex_name(
    par, &dsc, tok,
   &par->file->owner.domain,
    par->file->owner.name.octets,
   &par->file->owner.name.length)) < 0)
    return ret;
  par->rr.fields[OWNER] = (zone_field_t){
    .location = tok->location,
    .code = ZONE_OWNER|ZONE_NAME,
    .domain = par->file->owner.domain,
    .wire = {
      .length = par->file->owner.name.length,
      .octets = par->file->owner.name.octets }};
  return 0;
}

static inline zone_return_t have_ttl(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  static const zone_field_descriptor_t dsc =
    { "ttl", 3, ZONE_TTL|ZONE_INT32, 0, { 0 }, NULL };
  uint32_t ttl;

  if (lex_ttl(par, &dsc, tok, &ttl) < 0)
    return 0;
  assert(par->rr.fields[TTL].code == (ZONE_TTL|ZONE_INT32));
  par->rr.fields[TTL].location = tok->location;
  par->rr.fields[TTL].int32 = ttl;
  return ZONE_TTL|ZONE_INT32;
}

static inline zone_return_t have_class(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint16_t class;
  static const zone_field_descriptor_t dsc =
    { "class", 5, ZONE_CLASS|ZONE_INT16, 0, { 0 }, NULL };

  if (lex_class(par, &dsc, tok, &class) < 0)
    return 0;
  assert(par->rr.fields[CLASS].code == (ZONE_CLASS|ZONE_INT16));
  par->rr.fields[CLASS].location = tok->location;
  par->rr.fields[CLASS].int16 = class;
  return 1;
}

static inline zone_return_t have_type(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  uint16_t type;
  static const zone_field_descriptor_t dsc =
    { "type", 4, ZONE_TYPE|ZONE_INT16, 0, { 0 }, NULL };

  if (lex_type(par, &dsc, tok, &type) < 0)
    return 0;
  assert(par->rr.fields[TYPE].code == (ZONE_TYPE|ZONE_INT16));
  par->rr.fields[TYPE].location = tok->location;
  par->rr.fields[TYPE].int16 = type;
  if (type < sizeof(descriptors)/sizeof(descriptors[0]))
    par->rr.fields[TYPE].descriptor.type = (const void *)&descriptors[type];
  else
    par->rr.fields[TYPE].descriptor.type = (const void *)&descriptors[0];
  return 1;
}

static inline zone_return_t accept_rr(
  zone_parser_t *par,
  zone_field_t *owner,
  zone_field_t *ttl,
  zone_field_t *class,
  zone_field_t *type,
  void *ptr)
{
  assert(zone_type(owner->code) == ZONE_NAME);

  if (!par->options.accept.name || owner->domain)
    return par->options.accept.rr(par, owner, ttl, class, type, ptr);
  if (!(owner->domain = par->options.accept.name(par, owner, ptr)))
    return ZONE_OUT_OF_MEMORY;
  return par->options.accept.rr(par, owner, ttl, class, type, ptr);
}

static inline zone_return_t parse_rr(
  zone_parser_t *__restrict par,
  zone_token_t *__restrict tok,
  void *__restrict ptr)
{
  zone_return_t ret;

  par->state.scanner = ZONE_OWNER;
  switch ((ret = zone_quick_peek(par, par->file->buffer.offset))) {
    case ' ':
    case '\t':
      break;
    default:
      if (ret < 0)
        return ret;
      if ((ret = zone_scan(par, tok)) < 0)
        return ret;
      if (tok->code == '\n' || tok->code == '\0') {
        zone_flush(par, tok);
        return 0;
      }
      if ((ret = parse_owner(par, tok)) < 0)
        return ret;
      zone_flush(par, tok);
      break;
  }

  par->state.scanner = ZONE_RR | (par->state.scanner & ZONE_GROUPED);
  while (par->state.scanner & ZONE_TYPE) {
    int got_this = 0;
    if ((ret = zone_scan(par, tok)) < 0)
      return ret;

    if (tok->code & ZONE_STRING) {
      if ((zone_quick_peek(par, tok->cursor) & 0xff) > '9') {
        if ((par->state.scanner & ZONE_TYPE) && (got_this = have_type(par, tok))) {
          par->state.scanner &= ~ZONE_TYPE;
          par->rr.descriptors.type = par->rr.fields[TYPE].descriptor.type;
          par->rr.descriptors.rdata = (const void *)&((const struct type_descriptor *)par->rr.descriptors.type)->rdata[0];
          assert(par->options.accept.rr);
          if ((ret = accept_rr(
            par,
           &par->rr.fields[OWNER],
           &par->rr.fields[TTL],
           &par->rr.fields[CLASS],
           &par->rr.fields[TYPE],
            ptr)) < 0)
            return ret;
        } else if ((par->state.scanner & ZONE_CLASS) && (got_this = have_class(par, tok))) {
          par->state.scanner &= ~ZONE_CLASS;
        }
      } else if ((par->state.scanner & ZONE_TTL) && (got_this = have_ttl(par, tok))) {
        par->state.scanner &= ~ZONE_TTL;
      }
    }

    if (!got_this) {

      const char *expect = "type";
      if ((par->state.scanner & (ZONE_CLASS|ZONE_TTL)) == (ZONE_CLASS|ZONE_TTL))
        expect = "ttl, class or type";
      else if ((par->state.scanner & ZONE_TTL) == ZONE_TTL)
        expect = "ttl or type";
      else if ((par->state.scanner & ZONE_CLASS) == ZONE_CLASS)
        expect = "class or type";
      SYNTAX_ERROR(par, "Invalid item at {l}, expected %s", expect);
    }

    zone_flush(par, tok);
  }

  // fallback to default TTL if unspecified
  if (par->state.scanner & ZONE_TTL) {
    par->rr.fields[TTL].location = par->file->ttl.location;
    par->rr.fields[TTL].int32 = par->file->ttl.seconds;
  }

  par->state.scanner = ZONE_RDATA | (par->state.scanner & ZONE_GROUPED);
  if ((ret = zone_scan(par, tok)) < 0 || (ret = zone_lex(par, tok)) < 0)
    return ret;
  if (!(tok->code & ZONE_STRING) || zone_compare(&tok->string, "\\#", 2) != 0)
    return parse_rdata(par, tok, ptr);
  zone_flush(par, tok);
  return parse_generic_rdata(par, tok, ptr);
}

static inline zone_return_t parse_dollar_include(
  zone_parser_t *__restrict par,
  zone_token_t *__restrict tok,
  void *__restrict ptr)
{
  (void)par;
  (void)tok;
  (void)ptr;
  fprintf(stderr, "$INCLUDE directive not implemented yet\n");
  return ZONE_NOT_IMPLEMENTED;
}

static zone_return_t lex_origin(
  zone_parser_t * par,
  const zone_field_descriptor_t *dsc,
  zone_token_t *tok,
  uint8_t str[255],
  size_t *len)
{
  size_t lab = 0, oct = 1;

  (void)dsc;

  for (zone_char_t chr; (chr = zone_get(par, tok)) >= 0;) {
    if (oct >= 255)
      SYNTAX_ERROR(par, "Invalid name in $ORIGIN, name exceeds maximum");

    if (chr == '.' || chr == '\0') {
      if (oct - 1 == lab && chr == '.')
        SYNTAX_ERROR(par, "Invalid name in $ORIGIN, empty label");
      else if ((oct - lab) - 1 > 63)
        SYNTAX_ERROR(par, "Invalid name in $ORIGIN, label exceeds maximum");
      str[lab] = (oct - lab) - 1;
      if (chr != '.')
        break;
      lab = oct++;
      str[lab] = 0;
    } else {
      str[oct++] = chr & 0xff;
    }
  }

  if (str[lab] != 0)
    SEMANTIC_ERROR(par, "Invalid name in $ORIGIN, name not fully qualified");

  *len = oct;
  return 0;
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
static inline zone_return_t parse_dollar_origin(
  zone_parser_t *par, zone_token_t *tok, void *ptr)
{
  static const zone_field_descriptor_t dsc =
    { "origin", 6, ZONE_DOLLAR_ORIGIN|ZONE_NAME, 0, { 0 }, NULL };
  zone_return_t ret;
  zone_name_t *name = &par->file->origin.name;
  zone_field_t fld;

  assert(par);
  assert(tok);

  if ((ret = zone_scan(par, tok)) < 0)
    return ret;
  if (!(tok->code & ZONE_STRING))
    SYNTAX_ERROR(par, "$ORIGIN directive takes a domain name");
  if ((ret = lex_origin(par, &dsc, tok, name->octets, &name->length)) < 0)
    return ret;
  zone_flush(par, tok);
  par->file->origin.domain = NULL;
  par->file->origin.location = tok->location;

  if ((ret = zone_scan(par, tok)) < 0)
    return ret;
  if (tok->code != '\n' && tok->code != '\0')
    SYNTAX_ERROR(par, "$ORIGIN directive takes just a single argument");
  zone_flush(par, tok);

  if (!par->options.accept.name)
    return 0;
  fld = (zone_field_t){
    .location = tok->location,
    .code = ZONE_DOLLAR_ORIGIN|ZONE_NAME,
    .wire = { .octets = name->octets, .length = name->length }};
  if (!(par->file->origin.domain = par->options.accept.name(par, &fld, ptr)))
    return ZONE_OUT_OF_MEMORY;
  return 0;
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
static inline zone_return_t parse_dollar_ttl(
  zone_parser_t *par, zone_token_t * tok, void *ptr)
{
  static const zone_field_descriptor_t dsc =
    { "ttl", 3, ZONE_DOLLAR_TTL|ZONE_INT32, 0, { 0 }, NULL };
  zone_return_t ret;

  (void)ptr;
  if ((ret = zone_scan(par, tok)) < 0)
    return ret;
  if (!(tok->code & ZONE_STRING))
    SYNTAX_ERROR(par, "$TTL directive takes a time-to-live");
  if ((ret = lex_ttl(par, &dsc, tok, &par->file->ttl.seconds)) < 0)
    return ret;
  zone_flush(par, tok);
  par->file->ttl.location = tok->location;

  if ((ret = zone_scan(par, tok)) < 0)
    return ret;
  if (tok->code != '\n' && tok->code != '\0')
    SYNTAX_ERROR(par, "$TTL directive takes just a single argument");
  zone_flush(par, tok);
  return 0;
}

zone_return_t zone_parse(
  zone_parser_t *__restrict par, void *__restrict ptr)
{
  static const char ttl[] = "$TTL";
  static const char origin[] = "$ORIGIN";
  static const char include[] = "$INCLUDE";

  zone_token_t tok;
  zone_return_t ret = 0;

  for (zone_char_t chr; ret == 0 && (chr = zone_quick_peek(par, par->file->buffer.offset)); ) {
    // control directives must start at the beginning of the line
    if (chr != '$')
      ret = parse_rr(par, &tok, ptr);
    else switch ((ret = zone_scan(par, &tok))) {
      case ZONE_STRING|ZONE_ESCAPED:
      case ZONE_STRING:
        if ((ret = zone_lex(par, &tok)) < 0) {
          return ret;
        } else if (zone_compare(&tok.string, include, sizeof(include) - 1) == 0) {
          zone_flush(par, &tok);
          ret = parse_dollar_include(par, &tok, ptr);
        } else if (zone_compare(&tok.string, origin, sizeof(origin) - 1) == 0) {
          zone_flush(par, &tok);
          ret = parse_dollar_origin(par, &tok, ptr);
        } else if (zone_compare(&tok.string, ttl, sizeof(ttl) - 1) == 0) {
          zone_flush(par, &tok);
          ret = parse_dollar_ttl(par, &tok, ptr);
        } else {
          ret = parse_rr(par, &tok, ptr);
        }
        break;
      case '\n':
        zone_flush(par, &tok);
        break;
      case '\0':
        return 0;
    }
  }

  // FIXME: set state to return on error!

  return ret;
}
