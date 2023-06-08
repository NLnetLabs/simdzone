/*
 * types.c -- Test supported record types work as advertised
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

typedef struct field field_t;
struct field {
  zone_type_t type;
  size_t length;
  const uint8_t *octets;
};

#define IP4(options, rdata) \
  { ZONE_IP4, sizeof(struct in_addr), (const uint8_t *)&(struct in_addr){ .s_addr = rdata } }

#define NAME(options, ...) \
  { ZONE_NAME, sizeof((uint8_t[]){ __VA_ARGS__ }), (const uint8_t[]){ __VA_ARGS__ } }

#define RDATA(x) x, sizeof(x)/sizeof(x[0])


static const char a_text[] = PAD("host.example.com. 1 IN A 192.0.2.1");

static const field_t a[] = {
  IP4(0, 16908480)
};


static const char ns_text[] = PAD("example.com. 1 IN NS host.example.com.");

static const field_t ns[] = {
  NAME(ZONE_COMPRESSED,
       0x04, 0x68, 0x6f, 0x73, 0x74, 0x07, 0x65, 0x78,
       0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
       0x6d, 0x00)
};


typedef struct test test_t;
struct test {
  const uint16_t type;
  const char *text;
  const field_t *fields;
  const size_t count;
};

static const test_t tests[] = {
  { ZONE_A, a_text, RDATA(a) },
  { ZONE_NS, ns_text, RDATA(ns) }
};

static zone_return_t add_rr(
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
  return ZONE_SUCCESS;
}

/*!cmocka */
void supported_types(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    test_t test = tests[i];
    zone_parser_t parser = { 0 };
    zone_name_block_t name;
    zone_rdata_block_t rdata;
    zone_cache_t cache = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    zone_return_t result;

    options.accept.add = add_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(&parser, &options, &cache, tests[i].text, strlen(tests[i].text), &test);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
