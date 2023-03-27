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
#define TEXT(literal) \
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


#define IP4(options, rdata) \
  { ZONE_IP4,  { NULL }, sizeof(struct in_addr), { (const uint8_t *)&(struct in_addr){ .s_addr = rdata } } }

#define NAME(options, ...) \
  { ZONE_NAME, { NULL }, sizeof((uint8_t[]){ __VA_ARGS__ }), { (const uint8_t[]){ __VA_ARGS__ } } }

#define RDATA(x) x, sizeof(x)/sizeof(x[0])


static const char a_text[] = TEXT("host.example.com. 1 IN A 192.0.2.1");

static const zone_field_t a[] = {
  IP4(0, 16908480)
};


static const char ns_text[] = TEXT("example.com. 1 IN NS host.example.com.");

static const zone_field_t ns[] = {
  NAME(ZONE_COMPRESSED,
       0x04, 0x68, 0x6f, 0x73, 0x74, 0x07, 0x65, 0x78,
       0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
       0x6d, 0x00)
};


typedef struct test test_t;
struct test {
  const uint16_t type;
  const char *text;
  const zone_field_t *fields;
  const size_t count;
};

static const test_t tests[] = {
  { ZONE_A, a_text, RDATA(a) },
  { ZONE_NS, ns_text, RDATA(ns) }
};

static zone_return_t accept_rr(
  zone_parser_t *parser,
  const zone_field_t *owner,
  const zone_field_t *type,
  const zone_field_t *class,
  const zone_field_t *ttl,
  const zone_field_t *rdatas,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  const test_t *test = user_data;
  (void)parser;
  (void)owner;
  (void)class;
  (void)ttl;
  (void)rdatas;
  (void)rdlength;
  (void)rdata;
  assert_int_equal(*type->data.int16, test->type);
  return ZONE_SUCCESS;
}

/*!cmocka */
void supported_types(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    test_t test = tests[i];
    zone_parser_t parser = { 0 };
    zone_options_t options = { 0 };
    zone_rdata_t rdata;
    zone_return_t result;

    options.accept = accept_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(&parser, &options, rdata, tests[i].text, strlen(tests[i].text), &test);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
