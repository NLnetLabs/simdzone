/*
 * types.c -- Happy path tests to demonstrate supported types
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "zone.h"

// automatically pad string literal
#define PAD(literal) \
  literal \
  "\0\0\0\0\0\0\0\0" /*  0 -  7 */ \
  "\0\0\0\0\0\0\0\0" /*  8 - 15 */ \
  "\0\0\0\0\0\0\0\0" /* 16 - 23 */ \
  "\0\0\0\0\0\0\0\0" /* 24 - 31 */ \
  "\0\0\0\0\0\0\0\0" /* 32 - 39 */ \
  "\0\0\0\0\0\0\0\0" /* 40 - 47 */ \
  "\0\0\0\0\0\0\0\0" /* 48 - 55 */ \
  "\0\0\0\0\0\0\0\0" /* 56 - 63 */ \
  ""

#define RDATA(...) \
 { sizeof( (const uint8_t[]){ __VA_ARGS__ } )/sizeof(uint8_t), (const uint8_t[]){ __VA_ARGS__ } }

typedef struct rdata rdata_t;
struct rdata {
  size_t length;
  const uint8_t *octets;
};

/* RFC9460 Appendix D. Test Vectors */


// D.1. AliasMode

// Figure 2: AliasMode
static const char d1_text[] =
  PAD("example.com.   HTTPS   0 foo.example.com.");
static const rdata_t d1_rdata = RDATA(
  // priority
  0x00, 0x00,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00);


// D.2. ServiceMode

// Figure 3: TargetName is "."
static const char d2_f3_text[] =
  PAD("example.com.   SVCB   1 .");
static const rdata_t d2_f3_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target (root label)
  0x00);

// Figure 4: Specifies a Port
static const char d2_f4_text[] =
  PAD("example.com.   SVCB   16 foo.example.com. port=53");
static const rdata_t d2_f4_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 3
  0x00, 0x03,
  // length 2
  0x00, 0x02,
  // value
  0x00, 0x35);

// Figure 5: A Generic Key and Unquoted Value
static const char d2_f5_text[] =
  PAD("example.com.   SVCB   1 foo.example.com. key667=hello");
static const rdata_t d2_f5_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 667
  0x02, 0x9b,
  // length 9
  0x00, 0x05,
  // value
  0x68, 0x65, 0x6c, 0x6c, 0x6f);

// Figure 6: A Generic Key and Quoted Value with a Decimal Escape
static const char d2_f6_text[] =
  PAD("example.com.   SVCB   1 foo.example.com. key667=\"hello\\210qoo\"");
static const rdata_t d2_f6_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 667
  0x02, 0x9b,
  // length 9
  0x00, 0x09,
  // value
  0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd2, 0x71, 0x6f,
  0x6f);

// Figure 7: Two Quoted IPv6 Hints
static const char d2_f7_text[] =
  PAD("example.com.   SVCB   1 foo.example.com. (\n"
      "                        ipv6hint=\"2001:db8::1,2001:db8::53:1\"\n"
      "                        )\n");
static const rdata_t d2_f7_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 6
  0x00, 0x06,
  // length 32
  0x00, 0x20,
  // first address
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  // second address
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x01);

// Figure 8: An IPv6 Hint Using the Embedded IPv4 Syntax
static const char d2_f8_text[] =
  PAD("example.com.   SVCB   1 example.com. (\n"
      "                        ipv6hint=\"2001:db8:122:344::192.0.2.33\"\n"
      "                        )");
static const rdata_t d2_f8_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x03, 0x63, 0x6f, 0x6d, 0x00,
  // key 6
  0x00, 0x06,
  // length 16
  0x00, 0x10,
  // address
  0x20, 0x01, 0x0d, 0xb8, 0x01, 0x22, 0x03, 0x44,
  0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x21);

// Figure 9: SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format
static const char d2_f9_text[] =
  PAD("example.com.   SVCB   16 foo.example.org. (\n"
      "                         alpn=h2,h3-19 mandatory=ipv4hint,alpn\n"
      "                         ipv4hint=192.0.2.1\n"
      "                         )");

static const rdata_t d2_f9_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
  0x00,
  // key 0
  0x00, 0x00,
  // param length 4
  0x00, 0x04,
  // value: key 1
  0x00, 0x01,
  // value: key 4
  0x00, 0x04,
  // key 1
  0x00, 0x01,
  // param length 9
  0x00, 0x09,
  // alpn length 2
  0x02,
  // alpn value
  0x68, 0x32,
  // alpn length 5
  0x05,
  // alpn value
  0x68, 0x33, 0x2d, 0x31, 0x39,
  // key 4
  0x00, 0x04,
  // param length 4
  0x00, 0x04,
  // param value
  0xc0, 0x00, 0x02, 0x01);

#if 0
// No Application-Layer Protocol Negotiation (ALPN) protocol identifiers that
// contain a "\" (backslash) exist. To simplify parsing, in accordance with
// RFC9460 appendix A.1, simdzone prohibits item lists containing backslashes
// (for now).
//
// Figure 10: An "alpn" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats
static const char d2_f10_1_text[] =
  PAD("example.com.   SVCB   16 foo.example.org. alpn=\"f\\\\oo\\,bar,h2\"");

static const char d2_f10_2_text[] =
  PAD("example.com.   SVCB   16 foo.example.org. alpn=f\\\092oo\092,bar,h2");

static const rdata_t d2_f10_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
  0x00,
  // key 1
  0x00, 0x01,
  // length 12
  0x00, 0x0c,
  // alpn length 8
  0x08,
  // alpn value
  0x66, 0x5c, 0x6f, 0x6f, 0x2c, 0x62, 0x61, 0x72,
  // alpn length 2
  0x02,
  // alpn value
  0x68, 0x32);
#endif

typedef struct test test_t;
struct test {
  const uint16_t type;
  const char *text;
  const rdata_t *rdata;
};

static const test_t tests[] = {
  { ZONE_HTTPS, d1_text, &d1_rdata },
  { ZONE_SVCB, d2_f3_text, &d2_f3_rdata },
  { ZONE_SVCB, d2_f4_text, &d2_f4_rdata },
  { ZONE_SVCB, d2_f5_text, &d2_f5_rdata },
  { ZONE_SVCB, d2_f6_text, &d2_f6_rdata },
  { ZONE_SVCB, d2_f7_text, &d2_f7_rdata },
  { ZONE_SVCB, d2_f8_text, &d2_f8_rdata },
  { ZONE_SVCB, d2_f9_text, &d2_f9_rdata },
#if 0
  { ZONE_SVCB, d2_f10_1_text, &d2_f10_rdata },
  { ZONE_SVCB, d2_f10_2_text, &d2_f10_rdata }
#endif
};

static int32_t add_rr(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  const test_t *test = user_data;
  (void)parser;
  (void)owner;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  assert_int_equal(type, test->type);
  assert_int_equal(rdlength, test->rdata->length);
  assert_memory_equal(rdata, test->rdata->octets, rdlength);
  return ZONE_SUCCESS;
}

/*!cmocka */
void rfc9460_test_vectors(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    test_t test = tests[i];
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    options.accept.callback = add_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    fprintf(stderr, "INPUT: '%s'\n", tests[i].text);

    result = zone_parse_string(&parser, &options, &buffers, tests[i].text, strlen(tests[i].text), &test);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
