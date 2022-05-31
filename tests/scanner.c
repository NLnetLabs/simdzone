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
  assert_int_equal(code, ZONE_OWNER | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen(OWNER));
  assert_memory_equal(tok.string.data, OWNER, strlen(OWNER));

  // expect ttl
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TTL | ZONE_INT32);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.int32, 1);

  // expect class
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_CLASS | ZONE_INT16);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.int16, 1);

  // expect type
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TYPE | ZONE_INT16);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.int16, 1);

  // expect string
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_STRING);
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

#define OWNER "example.com."

/*!cmocka */
void service_mode_figure_1(void **state)
{
  int32_t code;
  zone_token_t tok = { 0 };
  zone_parser_t par = { 0 };
  static const char zone[] = OWNER " SVCB 1 .";

  (void)state;

  code = zone_open_string(&par, zone, strlen(zone));
  assert_int_equal(code, 0);

  // expect owner
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_OWNER | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen(OWNER));
  assert_memory_equal(tok.string.data, OWNER, strlen(OWNER));

  // expect type
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TYPE | ZONE_INT16);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.int16, 64);

  // expect priority
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen("1"));
  assert_memory_equal(tok.string.data, "1", strlen("1"));

  // expect targetname
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen("."));
  assert_memory_equal(tok.string.data, ".", strlen("."));

  // expect end-of-file
  code = zone_scan(&par, &tok);
  assert_int_equal(code, 0);
}

/*!cmocka */
void service_mode_figure_2(void **state)
{
  int32_t code;
  zone_token_t tok = { 0 };
  zone_parser_t par = { 0 };
  static const char zone[] = OWNER " SVCB   16 foo.example.com. port=53";

  (void)state;

  code = zone_open_string(&par, zone, strlen(zone));
  assert_int_equal(code, 0);

  // expect owner
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_OWNER | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen(OWNER));
  assert_memory_equal(tok.string.data, OWNER, strlen(OWNER));

  // expect type
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_TYPE | ZONE_INT16);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.int16, 64);

  // expect priority
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen("16"));
  assert_memory_equal(tok.string.data, "16", strlen("16"));

  // expect targetname
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_STRING);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.string.length, strlen("foo.example.com."));
  assert_memory_equal(tok.string.data, "foo.example.com.", strlen("foo.example.com."));

  // expect svcparam
  code = zone_scan(&par, &tok);
  assert_int_equal(code, ZONE_RDATA | ZONE_SVC_PARAM);
  assert_int_equal(tok.code, code);
  assert_int_equal(tok.svc_param.key.length, strlen("port"));
  assert_memory_equal(tok.svc_param.key.data, "port", strlen("port"));
  assert_int_equal(tok.svc_param.value.length, strlen("53"));
  assert_memory_equal(tok.svc_param.value.data, "53", strlen("53"));

  // expect end-of-file
  code = zone_scan(&par, &tok);
  assert_int_equal(code, 0);
}
