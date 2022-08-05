/*
 * nsec.c -- NSEC record tests
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

struct nsec_test {
  uint8_t count;
  uint16_t type;
  struct { size_t length; uint8_t *octets; } records;
};

static zone_return_t accept_rr(
  const zone_parser_t *par,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  void *user_data)
{
  struct nsec_test *test = user_data;

  (void)par;
  (void)owner;
  (void)ttl;
  (void)class;

  if (zone_type(type->code) == ZONE_INT16)
    test->type = type->int16;

  return 0;
}

static zone_return_t accept_rdata(
  const zone_parser_t *par,
  const zone_field_t *rdata,
  void *user_data)
{
  struct nsec_test *test = user_data;

  (void)par;
  assert(test);
  test->count++;

  if (test->count == 1) { // expect name
    if (zone_type(rdata->code) != ZONE_NAME)
      return ZONE_SYNTAX_ERROR;
    return 0;
  } else if (test->count == 2) { // expect nsec
    if (zone_type(rdata->code) != ZONE_NSEC)
      return ZONE_SYNTAX_ERROR;
    test->records.length = rdata->wire.length;
    test->records.octets = malloc(rdata->wire.length);
    memcpy(test->records.octets, rdata->wire.octets, rdata->wire.length);
    return 0;
  }

  return ZONE_SYNTAX_ERROR;
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
void nsec_happy_go_lucky(void **state)
{
  zone_return_t ret;
  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  static const char zone[] = "bar.foo. 1s IN NSEC baz.foo. A NSEC";
  struct nsec_test test = { 0 };
  uint8_t records[] = { 0x00u, 0x06u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u };

  (void)state;

  opts.accept.rr = accept_rr;
  opts.accept.rdata = accept_rdata;
  opts.accept.delimiter = accept_delimiter;

  ret = zone_open_string(&par, &opts, zone, strlen(zone));
  assert_int_equal(ret, 0);
  ret = zone_parse(&par, &test);
  assert_int_equal(ret, ZONE_SUCCESS);

  assert_int_equal(test.type, 47);
  assert_int_equal(test.count, 2);
  assert_int_equal(test.records.length, 8);
  assert_int_equal(test.records.length, sizeof(records));
  assert_memory_equal(test.records.octets, records, sizeof(records));
  free(test.records.octets);

  zone_close(&par);
}
