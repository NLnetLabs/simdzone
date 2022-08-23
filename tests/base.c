/*
 * base.c -- Basic record tests
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>

#include "zone.h"

typedef struct {
  zone_code_t code;
  uint32_t options;
  union {
    uint8_t int8;
    uint16_t int16;
    uint32_t int32;
    struct in_addr ip4;
    struct in6_addr ip6;
    struct { size_t length; uint8_t *octets; } name, b64, string, binary;
  };
} field_t;

typedef struct {
  size_t count;
  size_t length;
  const field_t *fields;
} test_t;

static zone_return_t accept_rr(
  const zone_parser_t *par,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  void *user_data)
{
  (void)par;
  (void)owner;
  (void)ttl;
  (void)class;
  (void)type;
  (void)user_data;
  return 0;
}

static zone_return_t accept_rdata(
  const zone_parser_t *par,
  const zone_field_t *rdata,
  void *user_data)
{
  int eq = 0;
  test_t *test = user_data;

  (void)par;
  if (test->count == test->length)
    return ZONE_SYNTAX_ERROR;
  if ((test->fields[test->count].code | ZONE_RDATA) != rdata->code)
    return ZONE_SYNTAX_ERROR;
  switch (test->fields[test->count].code) {
    case ZONE_INT8:
      eq = test->fields[test->count].int8 == *rdata->int8;
      break;
    case ZONE_INT16:
      eq = test->fields[test->count].int16 == ntohs(*rdata->int16);
      break;
    case ZONE_INT32:
      eq = test->fields[test->count].int32 == ntohl(*rdata->int32);
      break;
    case ZONE_IP4:
      if (sizeof(test->fields[test->count].ip4.s_addr) == rdata->length)
        eq = !memcmp(&test->fields[test->count].ip4.s_addr,
                     rdata->octets, rdata->length);
      break;
    case ZONE_IP6:
      if (sizeof(test->fields[test->count].ip6.s6_addr) == rdata->length)
        eq = !memcmp(&test->fields[test->count].ip6.s6_addr,
                     rdata->octets, rdata->length);
      break;
    case ZONE_NAME:
      if (test->fields[test->count].name.length == rdata->length)
        eq = !memcmp(test->fields[test->count].name.octets,
                     rdata->octets, rdata->length);
      break;
    case ZONE_BLOB:
      if (test->fields[test->count].b64.length == rdata->length)
        eq = !memcmp(test->fields[test->count].b64.octets,
                     rdata->octets, rdata->length);
      break;
    case ZONE_STRING:
    {
      size_t len = (size_t)*rdata->octets;
      const uint8_t *str = rdata->octets + 1;
      if (test->fields[test->count].string.length == len)
        eq = !memcmp(test->fields[test->count].string.octets, str, len);
    }
      break;
    case ZONE_NSEC:
    {
      eq = !memcmp(test->fields[test->count].string.octets,
                   rdata->octets,
                   rdata->length);
    }
      break;
    default:
      break;
  }

  test->count++;
  return eq ? ZONE_SUCCESS : ZONE_SYNTAX_ERROR;
}

static zone_return_t accept_delimiter(
  const zone_parser_t *par,
  const zone_field_t *fld,
  const uint8_t *rdata,
  size_t rdlength,
  void *user_data)
{
  (void)par;
  (void)fld;
  (void)rdata;
  (void)rdlength;
  (void)user_data;
  return 0;
}

#define I1(x) { .code = ZONE_INT8, .options = 0, .int8 = x }
#define I2(x) { .code = ZONE_INT16, .options = 0, .int16 = x }
#define I4(o, x) { .code = ZONE_INT32, .options = o, .int32 = x }
#define A(x) { .code = ZONE_IP4, .options = 0, .ip4 = { .s_addr = x } }
#define AAAA(...) { .code = ZONE_IP6, .options = 0, .ip6 = { .s6_addr = { __VA_ARGS__ } } }
#define N(o, ...) { .code = ZONE_NAME, .options = o, .name = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }
#define B32(...) { .code = ZONE_BLOB, .options = 0, .b64 = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }
#define B64(...) { .code = ZONE_BLOB, .options = 0, .b64 = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }
#define S(x) { .code = ZONE_STRING, .options = 0, .string = { .length = sizeof(x) - 1, .octets = (uint8_t *)x } }
#define X(...) { .code = ZONE_BLOB, .options = 0, .binary = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }
#define XC(...) { .code = ZONE_STRING, .options = 0, .binary = \
                  { .length = sizeof((uint8_t[]){__VA_ARGS__}), \
                    .octets = (uint8_t[]){ __VA_ARGS__ } } }

#define RL(...) { .code = ZONE_NSEC, .options = 0, .binary = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }

static const field_t a[] = {
  A(16908480)
};

static const field_t ns[] = {
  N(ZONE_COMPRESSED,
    0x04, 0x68, 0x6f, 0x73, 0x74, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00
  )
};

static const field_t soa[] = {
  N(0,
    0x02, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
    0x63, 0x6f, 0x6d, 0x00),
  N(ZONE_MAILBOX,
    0x03, 0x6e, 0x6f, 0x63, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00),
  I4(0, 2022072501),
  I4(ZONE_TTL, 1),
  I4(ZONE_TTL, 2),
  I4(ZONE_TTL, 3),
  I4(ZONE_TTL, 4)
};

static const field_t txt[] = {
  S("v=spf1"),
  S("ip4:192.0.2.0/24"),
  S("ip6:2001:DB8::/32"),
  S("a"),
  S("-all")
};

static const field_t aaaa[] = {
  AAAA(
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01)
};

static const field_t ds[] = {
  I2(60485u),
  I1(5u),
  I1(1u),
  X(
    0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a,
    0x98, 0x63, 0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18)
};

static const field_t rrsig[] = {
  I2(1u),
  I1(5u),
  I1(3u),
  I4(ZONE_TTL, 86400),
  I4(ZONE_TIME, 1048354263),
  I4(ZONE_TIME, 1048354263),
  I2(2642),
  N(0,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00
  ),
  B64(
    0xa0, 0x90, 0x75, 0x5b, 0xa5, 0x8d, 0x1a, 0xff, 0xa5, 0x76, 0xf4, 0x37,
    0x58, 0x31, 0xb4, 0x31, 0x09, 0x20, 0xe4, 0x81, 0x21, 0x8d, 0x18, 0xa9,
    0xf1, 0x64, 0xeb, 0x3d, 0x81, 0xaf, 0xd3, 0xb8, 0x75, 0xd3, 0xc7, 0x54,
    0x28, 0x63, 0x1e, 0x0c, 0xf2, 0xa2, 0x8d, 0x50, 0x87, 0x5f, 0x70, 0xc3,
    0x29, 0xd7, 0xdb, 0xfa, 0xfe, 0xa8, 0x07, 0xdc, 0x1f, 0xba, 0x1d, 0xc3,
    0x4c, 0x95, 0xd4, 0x01, 0xf2, 0x3f, 0x33, 0x4c, 0xe6, 0x3b, 0xfc, 0xf3,
    0xf1, 0xb5, 0xb4, 0x47, 0x39, 0xe5, 0xf0, 0xed, 0xed, 0x18, 0xd6, 0xb3,
    0x3f, 0x04, 0x0a, 0x91, 0x13, 0x76, 0xd1, 0x73, 0xd7, 0x57, 0xa9, 0xf0,
    0xc1, 0xfa, 0x17, 0x98, 0x94, 0x1b, 0xb0, 0xb3, 0x6b, 0x2d, 0xf9, 0x06,
    0x27, 0x90, 0xfa, 0x7f, 0x01, 0x66, 0xf2, 0x73, 0x7e, 0xea, 0x90, 0x73,
    0x78, 0x34, 0x1f, 0xb1, 0x2d, 0xc0, 0xa7, 0x7a
  )
};

static const field_t dnskey[] = {
  I2(256),
  I1(3),
  I1(5),
  B64(
    0x01, 0x03, 0x9e, 0x8a, 0x24, 0x74, 0x18, 0xe3, 0x18, 0x90, 0x3b, 0x21,
    0x5a, 0x84, 0x8a, 0xcf, 0xd5, 0xf3, 0x7f, 0x02, 0x6b, 0xd4, 0x06, 0x2d,
    0xb2, 0x6c, 0x77, 0x4c, 0x69, 0x09, 0x68, 0xd5, 0xd5, 0x6d, 0xf8, 0xbf,
    0xda, 0x91, 0xe6, 0xf3, 0x6d, 0x9a, 0x27, 0x98, 0x88, 0xf4, 0x13, 0x33,
    0x35, 0x7c, 0x5e, 0x60, 0x29, 0x99, 0x0d, 0x10, 0xfd, 0xf5, 0x66, 0x30,
    0x62, 0xa5, 0x12, 0x76, 0x33, 0x26, 0x98, 0x0a, 0x61, 0x5d, 0xdb, 0xf1,
    0x7a, 0x05, 0xdd, 0xfc, 0xce, 0x7e, 0x5f, 0xb3, 0xab, 0xcc, 0xa0, 0x5a,
    0x31, 0xb0, 0x95, 0x74, 0x52, 0xd4, 0x52, 0x1e, 0x83, 0x87, 0x07, 0x89,
    0x06, 0x31, 0x15, 0xbf, 0x97, 0xf6, 0xc3, 0x08, 0xcc, 0xf5, 0x7c, 0xdc,
    0x9c, 0xe7, 0xfe, 0x10, 0xf6, 0xed, 0x1b, 0xd0, 0xcc, 0x06, 0x60, 0x03,
    0x8c, 0x50, 0xdc, 0xdb, 0x0f, 0xeb, 0x96, 0x3c, 0x2f, 0x17
  )
};

static const field_t nsec3[] = {
  I1(1),
  I1(1),
  I2(12),
  XC(0xaa, 0xbb, 0xcc, 0xdd),
  B32(
    0x2f, 0x48, 0xb0, 0xac, 0xf9, 0x51, 0x03, 0x61, 0x2f, 0x5f, 0xfe, 0xb5,
    0x33, 0xfd, 0x04, 0xff, 0x93, 0x2d, 0xbb, 0x3f
  ),
  RL(
    0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01
  )
};

static const field_t nsec3param[] = {
  I1(1),
  I1(0),
  I2(12),
  XC(0xaa, 0xbb, 0xcc, 0xdd)
};

#define RDATA(x) x, sizeof(x)/sizeof(x[0])

struct {
  const uint16_t type;
  const char *text;
  const field_t *rdata;
  const size_t count;
} tests[] = {
  { 1,  "host.example.com. 1 IN A 192.0.2.1",
        RDATA(a) },
  { 2,  "example.com. 1 IN NS host.example.com.",
        RDATA(ns) },
  { 6,  "example.com. 1 IN SOA "
        "ns.example.com. noc.example.com. 2022072501 1 2 3 4",
        RDATA(soa) },
  { 16, "host.example.com. 1 IN TXT "
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:DB8::/32 a -all",
        RDATA(txt) },
  { 28, "host.example.com. 1 IN AAAA 2001:DB8::1",
        RDATA(aaaa) },
  { 43, "dskey.example.com. 86400 IN DS 60485 5 1 (\n"
        "2BB183AF5F22588179A53B0A\n"
        "98631FAD1A292118\n"
        ")",
        RDATA(ds) },
  { 46, "host.example.com. 1 IN RRSIG A "
        "RSASHA1 3 86400 20030322173103 20030322173103 2642 example.com. (\n"
        "oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr\n"
        "PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o\n"
        "B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t\n"
        "GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG\n"
        "J5D6fwFm8nN+6pBzeDQfsS3Ap3o=\n"
        ")",
        RDATA(rrsig) },
  { 48, "dskey.example.com. 86400 IN DNSKEY 256 3 5 (\n"
        "AQOeiiR0GOMYkDshWoSKz9Xz\n"
        "fwJr1AYtsmx3TGkJaNXVbfi/\n"
        "2pHm822aJ5iI9BMzNXxeYCmZ\n"
        "DRD99WYwYqUSdjMmmAphXdvx\n"
        "egXd/M5+X7OrzKBaMbCVdFLU\n"
        "Uh6DhweJBjEVv5f2wwjM9Xzc\n"
        "nOf+EPbtG9DMBmADjFDc2w/r\n"
        "ljwvFw==\n"
        ") ;  key id = 60485",
        RDATA(dnskey) },
  { 50, "example.com. 1 IN NSEC3 "
        "1 1 12 aabbccdd (\n"
        "5t4b1b7pa41m2bqvvqqj7v84vu9irepv A NSEC )",
        RDATA(nsec3) },
  { 51, "example.com. 1 IN NSEC3PARAM "
        "1 0 12 aabbccdd",
        RDATA(nsec3param) },
};

/*!cmocka */
void supported_types(void **state)
{
  (void)state;
  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t par = { 0 };
    zone_options_t opts = { 0 };
    zone_return_t ret;
    test_t test = { 0, tests[i].count, tests[i].rdata };

    opts.accept.rr = accept_rr;
    opts.accept.rdata = accept_rdata;
    opts.accept.delimiter = accept_delimiter;

    ret = zone_open_string(&par, &opts, tests[i].text, strlen(tests[i].text));
    assert_int_equal(ret, ZONE_SUCCESS);
    ret = zone_parse(&par, &test);
    assert_int_equal(ret, ZONE_SUCCESS);
    assert_int_equal(tests[i].count, test.count);

    zone_close(&par);
  }
}
