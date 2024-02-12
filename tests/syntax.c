/*
 * syntax.c -- presentation format syntax test cases
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "zone.h"

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

struct newline_test {
  const char *input;
  size_t line[2];
};

static int32_t newline_test_accept_rr(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  struct newline_test *test;

  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;

  assert(user_data);
  test = (struct newline_test *)user_data;

  if (owner->octets[1] == '1')
    return parser->file->line == test->line[0] ? 0 : ZONE_SYNTAX_ERROR;
  else if (owner->octets[1] == '2')
    return parser->file->line == test->line[1] ? 0 : ZONE_SYNTAX_ERROR;
  else
    return ZONE_SYNTAX_ERROR;
}

/*!cmocka */
void newlines(void **state)
{
#if 0
  static const char embedded_lf_text[] =
    PAD("1. TXT \"foo\nbar\n\"\n2. TXT \"foobar\"");
#endif
  static const char grouped_lf_text[] =
    PAD("1. TXT (\nfoo\nbar\n)\"\n2. TXT \"foobar\"");
  static const char plain_lf_text[] =
    PAD("1. TXT \"foo bar\"\n2. TXT \"foo baz\"");
  static const char control_lf_text[] =
    PAD("$TTL 3600\n1. TXT \"foo bar\"\n2. TXT \"foo baz\"");

  static const uint8_t origin[] = { 0 };

  static const struct newline_test tests[] = {
#if 0
    { embedded_lf_text, { 1, 4 } },
#endif
    { grouped_lf_text, { 1, 5 } },
    { plain_lf_text, { 1, 2 } },
    { control_lf_text, { 2, 3 } }
  };

  (void)state;

  for (size_t i=0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    options.accept.callback = newline_test_accept_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(
      &parser, &options, &buffers, tests[i].input, strlen(tests[i].input), (void*)&tests[i]);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
