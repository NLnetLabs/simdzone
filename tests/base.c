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

// this test will basically verify that all records are supported...
//   >> might turn that into more than one function too... if that makes sense...
//   >> we start out with the records below
// SOA
// RRSIG
// DNSKEY
// TXT
// DS
// NS

typedef struct {
  zone_code_t code;
  uint32_t options;
  union {
    uint8_t int8;
    uint16_t int16;
    uint32_t int32;
    struct { size_t length; uint8_t *octets; } name, b64;
  };
} field_t;

typedef struct {
  size_t count;
  size_t length;
  const field_t *fields;
} test_t;

static zone_return_t accept_rr(
  const zone_parser_t *par,
  zone_field_t *owner,
  zone_field_t *ttl,
  zone_field_t *class,
  zone_field_t *type,
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
  zone_field_t *fld,
  void *user_data)
{
  int eq;
  test_t *test = user_data;

  (void)par;
  if (test->count == test->length)
    return ZONE_SYNTAX_ERROR;
  if ((test->fields[test->count].code | ZONE_RDATA) != fld->code)
    return ZONE_SYNTAX_ERROR;
  switch (test->fields[test->count].code) {
    case ZONE_INT8:
      eq = test->fields[test->count].int8 == fld->int8;
      break;
    case ZONE_INT16:
      eq = test->fields[test->count].int16 == ntohs(fld->int16);
      break;
    case ZONE_INT32:
      eq = test->fields[test->count].int32 == ntohl(fld->int32);
      break;
    case ZONE_NAME:
      if (test->fields[test->count].name.length == fld->name.length)
        eq = !memcmp(test->fields[test->count].name.octets,
                    fld->name.octets, fld->name.length);
      else
        eq = 0;
      break;
    case ZONE_BASE64:
      if (test->fields[test->count].b64.length == fld->b64.length)
        eq = !memcmp(test->fields[test->count].b64.octets,
                    fld->b64.octets, fld->b64.length);
      else
        eq = 0;
      break;
    default:
      eq = 0;
      break;
  }

  test->count++;
  return eq ? ZONE_SUCCESS : ZONE_SYNTAX_ERROR;
}

static zone_return_t accept_delimiter(
  const zone_parser_t *par,
  zone_field_t *fld,
  void *user_data)
{
  (void)par;
  (void)fld;
  (void)user_data;
  return 0;
}

#define I1(x) { .code = ZONE_INT8, .options = 0, .int8 = x }
#define I2(x) { .code = ZONE_INT16, .options = 0, .int16 = x }
#define I4(x) { .code = ZONE_INT32, .options = 0, .int32 = x }
#define T(x)  { .code = ZONE_INT32, .options = 0, .int32 = x }
#define N(o, ...) { .code = ZONE_NAME, .options = o, .name = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }
#define B64(...) { .code = ZONE_BASE64, .options = 0, .b64 = { .length = sizeof((uint8_t[]){__VA_ARGS__}), .octets = (uint8_t[]){__VA_ARGS__} } }

static const field_t soa_fields[] = {
  N(0, 0x02, 0x6e, 0x73, 0x03, 0x66, 0x6f, 0x6f, 0x00),
  N(ZONE_QUALIFIER_MAILBOX, 0x03, 0x6e, 0x6f, 0x63, 0x03, 0x66, 0x6f, 0x6f, 0x00),
  I4(2022072501),
  I4(1),
  I4(2),
  I4(3),
  I4(4)
};

static const field_t rrsig_fields[] = {
  I2(1u),
  I1(5u),
  I1(3u),
  I4(86400),
  T(1048354263),
  T(1048354263),
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

struct {
  const uint16_t type;
  const char *text;
  const field_t *rdata;
  const size_t count;
} tests[] = {
  { 6,  "foo. 1 IN SOA ns.foo. noc.foo. 2022072501 1 2 3 4",
    soa_fields, sizeof(soa_fields)/sizeof(soa_fields[0]) },
  { 46, "host.example.com. 1 IN RRSIG "
        "A RSASHA1 3 86400 20030322173103 20030322173103 2642 example.com. "
        "oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr"
        "PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o"
        "B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t"
        "GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG"
        "J5D6fwFm8nN+6pBzeDQfsS3Ap3o=",
    rrsig_fields, sizeof(rrsig_fields)/sizeof(rrsig_fields[0]) }
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

    zone_close(&par);
  }
}
