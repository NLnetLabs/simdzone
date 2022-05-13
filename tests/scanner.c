/*
 * scanner.c -- basic tests for scanner
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

#include "zone.h"

/*!cmocka */
void happy_go_lucky(void **state)
{
#define OWNER "example.com"
#define RDATA "1.2.3.4"
  int32_t code;
  zone_token_t tok = { 0 };
  zone_parser_t par = { 0 };
  static const char zone[] = OWNER " 1s IN A " RDATA;

  (void)state;

  code = zone_open_string(&par, zone, strlen(zone));
  assert_int_equal(code, 0);

  // expect owner
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_OWNER);
  assert_true(tok.code == ZONE_OWNER);
  assert_int_equal(tok.string.length, strlen(OWNER));
  assert_memory_equal(tok.string.data, OWNER, strlen(OWNER));

  // expect ttl
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TTL);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.ttl, 1);

  // expect class
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_CLASS);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.class, 1);

  // expect type
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TYPE);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.type, 1);

  // expect string
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen(RDATA));
  assert_memory_equal(tok.string.data, RDATA, strlen(RDATA));

  // expect end-of-file
  code = zone_scan(&par, &tok);
  assert_int_equal(code, 0);

  // expect end-of-file (again)
  code = zone_scan(&par, &tok);
  assert_int_equal(code, 0);
#undef RDATA
#undef OWNER
}
