/*
 * svcb.c -- SVCB record tests
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

// x. out of order keys
//     section 2.1 states:
//     SvcParams in presentation format MAY appear in any order, but keys MUST NOT be repeated.
//     section 2.2 states:
//     SvcParamKeys SHALL appear in increasing numeric order. (edited)
// x. duplicate keys
// x. all tests from nsd

struct svcb_test {
  size_t count;
  uint16_t type;
  zone_field_t port;
  zone_field_t mandatory;
};

static zone_return_t accept_rr(
  const zone_parser_t *par,
  zone_field_t *owner,
  zone_field_t *ttl,
  zone_field_t *class,
  zone_field_t *type,
  void *user_data)
{
  struct svcb_test *test = user_data;

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
  zone_field_t *rdata,
  void *user_data)
{
  struct svcb_test *test = user_data;

  (void)par;
  assert(test);
  test->count++;

  if (test->count == 1) {
    return 0;
  } else if (test->count == 2) { // target name
    return 0;
  } else if (test->count == 3) { // expect port
    if (zone_type(rdata->code) != ZONE_SVC_PARAM)
      return ZONE_SYNTAX_ERROR;
    test->port = *rdata;
    return 0;
  } else if (test->count == 4) { // expect mandatory
    if (zone_type(rdata->code) != ZONE_SVC_PARAM)
      return ZONE_SYNTAX_ERROR;
    test->mandatory = *rdata;
    return 0;
  }

  return ZONE_SYNTAX_ERROR;
}

static zone_return_t accept_delimiter(
  const zone_parser_t *par,
  zone_field_t *delimiter,
  void *user_data)
{
  (void)par;
  (void)delimiter;
  (void)user_data;
  return 0;
}

/*!cmocka */
void svcb_happy_go_lucky(void **state)
{
  zone_return_t ret;
  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  static const char zone[] = "foo. 1s IN SVCB 0 foo. port=853 mandatory=port\n";
  struct svcb_test test = { 0 };

  (void)state;

  opts.accept.rr = accept_rr;
  opts.accept.rdata = accept_rdata;
  opts.accept.delimiter = accept_delimiter;

  ret = zone_open_string(&par, &opts, zone, strlen(zone));
  assert_int_equal(ret, 0);
  ret = zone_parse(&par, &test);
  assert_int_equal(ret, ZONE_SUCCESS);

  assert_int_equal(test.type, 64);
  assert_int_equal(test.port.code, ZONE_RDATA | ZONE_SVC_PARAM);
  if (test.port.code == ZONE_SVC_PARAM) {
    uint16_t x;
    assert_int_equal(test.port.svc_param.length, 3*sizeof(uint16_t));
    assert_non_null(test.port.svc_param.octets);
    x = ntohs(*(uint16_t *)&test.port.svc_param.octets[0]);
    assert_int_equal(x, 3);
    x = ntohs(*(uint16_t *)&test.port.svc_param.octets[2]);
    assert_int_equal(x, sizeof(uint16_t));
    x = ntohs(*(uint16_t *)&test.port.svc_param.octets[4]);
    assert_int_equal(x, 853);
    free(test.port.svc_param.octets);
  }
  assert_int_equal(test.mandatory.code, ZONE_RDATA | ZONE_SVC_PARAM);
  if (test.port.code == ZONE_SVC_PARAM) {
    uint16_t x;
    assert_int_equal(test.port.svc_param.length, 3*sizeof(uint16_t));
    assert_non_null(test.mandatory.svc_param.octets);
    x = ntohs(*(uint16_t *)&test.mandatory.svc_param.octets[0]);
    assert_int_equal(x, 0);
    x = ntohs(*(uint16_t *)&test.mandatory.svc_param.octets[2]);
    assert_int_equal(x, sizeof(uint16_t));
    x = ntohs(*(uint16_t *)&test.mandatory.svc_param.octets[4]);
    assert_int_equal(x, 3);
    free(test.mandatory.svc_param.octets);
  }

  zone_close(&par);
}
