#define _XOPEN_SOURCE
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "parser.h"

extern int b64_pton(char const *src, uint8_t *target, size_t targsize);

/* A general purpose lookup table */
typedef struct lookup_table lookup_table_type;
struct lookup_table {
  int id;
  const char *name;
};

static lookup_table_type *
lookup_by_name(lookup_table_type *table, const zone_string_t *str)
{
  while (table->name != NULL) {
    if (strlen(table->name) == str->length && strncasecmp(str->data, table->name, str->length) == 0)
      return table;
    table++;
  }
  return NULL;
}

/* Taken from RFC 4398, section 2.1.  */
lookup_table_type dns_certificate_types[] = {
/*  0   Reserved */
  { 1, "PKIX" },  /* X.509 as per PKIX */
  { 2, "SPKI" },  /* SPKI cert */
  { 3, "PGP" }, /* OpenPGP packet */
  { 4, "IPKIX" }, /* The URL of an X.509 data object */
  { 5, "ISPKI" }, /* The URL of an SPKI certificate */
  { 6, "IPGP" },  /* The fingerprint and URL of an OpenPGP packet */
  { 7, "ACPKIX" },  /* Attribute Certificate */
  { 8, "IACPKIX" }, /* The URL of an Attribute Certificate */
  { 253, "URI" }, /* URI private */
  { 254, "OID" }, /* OID private */
/*  255     Reserved */
/*  256-65279 Available for IANA assignment */
/*  65280-65534 Experimental */
/*  65535   Reserved */
  { 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
lookup_table_type dns_algorithms[] = {
  { 1, "RSAMD5" },  /* RFC 2537 */
  { 2, "DH" },    /* RFC 2539 */
  { 3, "DSA" },   /* RFC 2536 */
  { 4, "ECC" },
  { 5, "RSASHA1" }, /* RFC 3110 */
  { 6, "DSA-NSEC3-SHA1" },  /* RFC 5155 */
  { 7, "RSASHA1-NSEC3-SHA1" },  /* RFC 5155 */
  { 8, "RSASHA256" },   /* RFC 5702 */
  { 10, "RSASHA512" },    /* RFC 5702 */
  { 12, "ECC-GOST" },   /* RFC 5933 */
  { 13, "ECDSAP256SHA256" },  /* RFC 6605 */
  { 14, "ECDSAP384SHA384" },  /* RFC 6605 */
  { 15, "ED25519" },    /* RFC 8080 */
  { 16, "ED448" },    /* RFC 8080 */
  { 252, "INDIRECT" },
  { 253, "PRIVATEDNS" },
  { 254, "PRIVATEOID" },
  { 0, NULL }
};

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

zone_return_t zone_parse_period(
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

zone_return_t zone_parse_time(
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

zone_return_t zone_parse_int8(
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

zone_return_t zone_parse_int16(
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

zone_return_t zone_parse_int32(
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

zone_return_t zone_parse_ip4(
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

zone_return_t zone_parse_ip6(
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

zone_return_t zone_parse_domain_name(
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

zone_return_t zone_parse_algorithm(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  const lookup_table_type *alg;

  (void)ptr;
  if ((alg = lookup_by_name(dns_algorithms, &tok->string))) {
    fld->int8 = (uint8_t)alg->id;
  } else {
    uint64_t u64;
    zone_return_t ret;
    if ((ret = zone_parse_int(par, fld->descriptor.rdata, tok, UINT8_MAX, &u64)) < 0)
      return ret;
    assert(u64 <= UINT8_MAX);
    fld->int8 = (uint8_t)u64;
  }

  return ZONE_RDATA;
}

zone_return_t zone_parse_certificate(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  const lookup_table_type *row;

  (void)ptr;
  if ((row = lookup_by_name(dns_certificate_types, &tok->string))) {
    fld->int16 = htons((uint16_t)row->id);
  } else {
    uint64_t u64;
    zone_return_t ret;
    if ((ret = zone_parse_int(par, fld->descriptor.rdata, tok, UINT16_MAX, &u64)) < 0)
      return ret;
    assert(u64 <= UINT16_MAX);
    fld->int16 = htons((uint16_t)u64);
  }

  return ZONE_RDATA;
}

zone_return_t zone_parse_type(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  // FIXME: accept TYPExx too!
  // FIXME: unencode first!
  uint16_t t;
  (void)ptr;
  if (!(t = zone_is_type(tok->string.data, tok->string.length)))
    SYNTAX_ERROR(par, "{l}: Invalid type in %s", tok, fld->descriptor.rdata->name);
  fld->int16 = t;
  return ZONE_RDATA;
}

#define B64BUFSIZE 65536

zone_return_t zone_parse_base64(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  char unesc[B64BUFSIZE*2];
  uint8_t dec[B64BUFSIZE];
  ssize_t len = -1;
  const zone_rdata_descriptor_t *desc = fld->descriptor.rdata;

  (void)ptr;
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, unesc, sizeof(unesc), 0);
  else if (tok->string.length < sizeof(unesc))
    memcpy(unesc, tok->string.data, (len = tok->string.length));

  if (len < 0)
    SYNTAX_ERROR(par, "{l}: Invalid base64 data in %s", tok, desc->name);
  unesc[len] = '\0';

  int declen = b64_pton(unesc, dec, sizeof(dec));
  if (declen == -1)
    SYNTAX_ERROR(par, "{l}: Invalid base64 data in %s", tok, desc->name);

  if (!(fld->b64.octets = zone_malloc(par, (size_t)len)))
    return ZONE_OUT_OF_MEMORY;
  memcpy(fld->b64.octets, dec, (size_t)declen);
  return ZONE_RDATA;
}

zone_return_t zone_parse_generic_ip4(
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
}

zone_return_t zone_parse_generic_ip6(
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
}
