/*
 * wks.c -- WKS record tests
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

// x. protocol in mnemonic form
// x. protocol in decimal form
// x. unknown protocol in decimal form
// x. missing protocol
// x. service in mnemonic form
// x. service in decimal form
// x. service in decimal form that exceeds 65535
// x. unknown service in decimal form
// x. no service at all (what's the expected result?)
// x. multiple of the same services (no error, just one bit set)
// x. mixed use of mnemonic and decimal form
// x. test with bit on octet boundary
// x. test with bit just before octet boundary
// x. test with bit just over octet boundary
//
// x. test if all the right bits are set
// x. test that other bits are explicitly NOT set

struct wks_test {
  uint8_t count;
  uint16_t type;
  uint8_t protocol;
  struct { size_t length; uint8_t *octets; } services;
};

static zone_return_t accept_rr(
  const zone_parser_t *par,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  void *user_data)
{
  struct wks_test *test = user_data;

  (void)par;
  (void)owner;
  (void)ttl;
  (void)class;

  if (zone_type(type->code) == ZONE_INT16)
    test->type = *type->int16;

  return 0;
}

static zone_return_t accept_rdata(
  const zone_parser_t *par,
  const zone_field_t *rdata,
  void *user_data)
{
  struct wks_test *test = user_data;

  (void)par;
  assert(test);
  test->count++;

  if (test->count == 1) { // expect address
    if (zone_type(rdata->code) != ZONE_IP4)
      return ZONE_SYNTAX_ERROR;
    return 0;
  } else if (test->count == 2) { // expect protocol
    if (zone_type(rdata->code) != ZONE_INT8)
      return ZONE_SYNTAX_ERROR;
    test->protocol = *rdata->int8;
    return 0;
  } else if (test->count == 3) { // expect bitmask
    if (zone_type(rdata->code) != ZONE_WKS)
      return ZONE_SYNTAX_ERROR;
    test->services.octets = malloc(rdata->length);
    memcpy(test->services.octets, rdata->octets, rdata->length);
    test->services.length = rdata->length;
    return 0;
  }

  return ZONE_SYNTAX_ERROR;
}

static zone_return_t accept_delimiter(
  const zone_parser_t *par,
  const zone_field_t *delimiter,
  const uint8_t *rdata,
  size_t rdlength,
  void *user_data)
{
  (void)par;
  (void)delimiter;
  (void)rdata;
  (void)rdlength;
  (void)user_data;
  return 0;
}

/*!cmocka */
void wks_happy_go_lucky(void **state)
{
  zone_return_t ret;
  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  static const char zone[] = "foo. 1s IN WKS 192.168.0.1 TCP smtp\n";
  struct wks_test test = { 0 };
  uint8_t services[] = { 0x00u, 0x00u, 0x00u, 0x40u };

  (void)state;

  opts.accept.rr = accept_rr;
  opts.accept.rdata = accept_rdata;
  opts.accept.delimiter = accept_delimiter;

  ret = zone_open_string(&par, &opts, zone, strlen(zone));
  assert_int_equal(ret, 0);
  ret = zone_parse(&par, &test);
  assert_int_equal(ret, ZONE_SUCCESS);

  assert_int_equal(test.type, 11);
  assert_int_equal(test.count, 3);
  assert_int_equal(test.protocol, 6);
  assert_int_equal(test.services.length, 4);
  assert_int_equal(test.services.length, sizeof(services));
  assert_memory_equal(test.services.octets, services, sizeof(services));

  zone_close(&par);
}
