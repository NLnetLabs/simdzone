/*
 * types.c -- basic type availability tests
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

#include "parser.h"

struct str_test {
  struct { size_t length; uint8_t octets[255]; } owner;
  uint32_t ttl;
  uint16_t class;
  uint16_t type;
  size_t rdcount;
  uint8_t rdata[2][256];
};

static zone_return_t accept_rr(
  const zone_parser_t *par,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  void *user_data)
{
  struct str_test *test = user_data;

  (void)par;
  assert(test);
  test->owner.length = owner->length;
  memcpy(test->owner.octets, owner->octets, owner->length);
  if (zone_type(ttl->code) == ZONE_INT32)
    test->ttl = *ttl->int32;
  if (zone_type(class->code) == ZONE_INT16)
    test->class = *class->int16;
  if (zone_type(type->code) == ZONE_INT16)
    test->type = *type->int16;

  return 0;
}

static zone_return_t accept_rdata(
  const zone_parser_t *par,
  const zone_field_t *rdata,
  void *user_data)
{
  struct str_test *test = user_data;

  (void)par;
  assert(test);
  if (test->rdcount < 2)
    memcpy(test->rdata[test->rdcount], rdata->octets, rdata->length);
  test->rdcount++;

  return 0;
}

static zone_return_t accept_delimiter(
  const zone_parser_t *par,
  const zone_field_t *delimiter,
  void *user_data)
{
  (void)par;
  (void)delimiter;
  (void)user_data;
  return 0;
}

/*!cmocka */
void str_type_max_len(void **state)
{
  zone_return_t ret;
  zone_options_t opts = { 0 };
  char rr[512], os[512];

  (void)state;

  opts.accept.rr = accept_rr;
  opts.accept.rdata = accept_rdata;
  opts.accept.delimiter = accept_delimiter;

  const struct {
    size_t length;
    zone_return_t expect;
    bool leanient;
  } tests[] = {
    { 254, 0, false },
    { 255, 0, false },
    { 256, ZONE_SEMANTIC_ERROR, false },
    { 257, ZONE_SEMANTIC_ERROR, false },
    // FIXME: re-enable once leanient mode is implemented properly
    //{ 256, 0, true },
    //{ 257, 0, true }
  };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t par = { 0 };
    struct str_test test = { 0 };
    ssize_t rrlen;

    opts.flags = tests[i].leanient ? ZONE_LENIENT : 0;

    for (size_t j=0; j < tests[i].length; j++)
      os[j] = 'x';
    os[ tests[i].length ] = '\0';
    rrlen = snprintf(rr, sizeof(rr), "foo. 1 HINFO %zu %s", tests[i].length, os);

    ret = zone_open_string(&par, &opts, rr, (size_t)rrlen);
    assert_int_equal(ret, 0);
    ret = zone_parse(&par, &test);
    assert_int_equal(ret, tests[i].expect);

    if (tests[i].expect == 0) {
      size_t len = strlen(os);
      if (len > 255)
        len = 255;
      assert_int_equal(test.rdata[1][0], len);
      assert_memory_equal(&test.rdata[1][1], os, test.rdata[1][0]);
    }

    zone_close(&par);
  }
}

/*!cmocka */
void str_type_min_len(void **state)
{
  zone_return_t ret;
  zone_options_t opts = { 0 };

  (void)state;

  opts.accept.rr = accept_rr;
  opts.accept.rdata = accept_rdata;
  opts.accept.delimiter = accept_delimiter;

  struct {
    zone_return_t expect;
    const char *zone;
    const char *cpu;
    const char *os;
  } tests[] = {
    { 0, "foo. 1 HINFO f oo", "f", "oo" },
    { 0, "foo. 1 HINFO fo o", "fo", "o" },
    { 0, "foo. 1 HINFO foo bar", "foo", "bar" },
    { 0, "foo. 1 HINFO \"\" bar", "", "bar" },
    { 0, "foo. 1 HINFO foo \"\"", "foo", "" }
  };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t par = { 0 };
    struct str_test test = { 0 };

    ret = zone_open_string(&par, &opts, tests[i].zone, strlen(tests[i].zone));
    assert_int_equal(ret, 0);
    ret = zone_parse(&par, &test);
    assert_int_equal(ret, tests[i].expect);

    assert_int_equal(test.rdcount, 2);
    assert_non_null(test.owner.octets);
    assert_non_null(test.rdata[0]);
    assert_non_null(test.rdata[1]);

    assert_int_equal(test.rdata[0][0], strlen(tests[i].cpu));
    assert_memory_equal(&test.rdata[0][1], tests[i].cpu, test.rdata[0][0]);
    assert_int_equal(test.rdata[1][0], strlen(tests[i].os));
    assert_memory_equal(&test.rdata[1][1], tests[i].os, test.rdata[1][0]);

    zone_close(&par);
  }
}

/* !cmocka */
//void max_generic_str_len(void **state)
//{
//  //
//  // x. ensure string cannot exceed 255 octets (mind length octet)
//  // x. ensure length octet matches actual length
//  //
//}
