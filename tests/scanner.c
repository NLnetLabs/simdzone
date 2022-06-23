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
#include <arpa/inet.h>

#include "zone.h"
#include "scanner.h"

static const char *dummy_domain = "foobarbaz!";

static const void *accept_name(const zone_parser_t *par, const zone_field_t *fld, void *user_data)
{
  (void)par;
  (void)fld;
  (void)user_data;
  printf("got name!\n");
  return dummy_domain;
}

static zone_return_t accept_rr(
  const zone_parser_t *par,
  zone_field_t *owner,
  zone_field_t *ttl,
  zone_field_t *class,
  zone_field_t *type,
  void *user_data)
{
  (void)par;
  (void)owner;
  (void)ttl;
  (void)class;
  (void)type;
  (void)user_data;
  printf("got rr!\n");
  if (owner->format != ZONE_DOMAIN) {
    printf("owner was not a domain!\n");
    return ZONE_SYNTAX_ERROR; // switch type of code later on!
  }
  return 0;
}

static zone_return_t accept_rdata(
  const zone_parser_t *par,
  zone_field_t *rdata,
  void *user_data)
{
  (void)par;
  (void)user_data;

  assert(rdata);

  if (rdata->format == ZONE_IP4) {
    char buf[INET_ADDRSTRLEN + 1];
    if (!inet_ntop(AF_INET, rdata->ip4, buf, sizeof(buf)))
      return ZONE_SYNTAX_ERROR;
    printf("ip4: %s\n", buf);
  } else if (rdata->format == ZONE_IP6) {
    char buf[INET6_ADDRSTRLEN + 1];
    if (!inet_ntop(AF_INET6, rdata->ip6, buf, sizeof(buf)))
      return ZONE_SYNTAX_ERROR;
    printf("ip6: %s\n", buf);
  } else {
    printf("<rdata>\n");
  }
  return 0;
}

static zone_return_t accept_terminator(
  const zone_parser_t *par,
  zone_field_t *term,
  void *user_data)
{
  (void)par;
  (void)term;
  (void)user_data;
  printf("got terminator!\n");
  return 0;
}

/*!cmocka */
void basic_parse_test(void **state) // to be moved to separate file later
{
  int32_t code;
  static const char zone[] = "foo.bar. 3s IN A 1.2.3.4\n"
                             "foo.bar.baz. 45s IN AAAA ::1";
  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  opts.accept.name = &accept_name;
  opts.accept.rr = &accept_rr;
  opts.accept.rdata = &accept_rdata;
  opts.accept.terminator = &accept_terminator;

  (void)state;

  code = zone_open_string(&par, &opts, zone, strlen(zone));
  assert_int_equal(code, 0);
  code = zone_parse(&par, NULL);
  assert_int_equal(code, 0);
}

/*!cmocka */
void basic_generic_parse_test(void **state)
{
  zone_return_t code;
  static const char zone[] = "foo.bar. 5s IN TYPE1 \\# 4 7F000001\n"
                             "foo.bar.baz. 75s IN AAAA \\# 16 00000000000000000000000000000001";

  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  opts.accept.name = &accept_name;
  opts.accept.rr = &accept_rr;
  opts.accept.rdata = &accept_rdata;
  opts.accept.terminator = &accept_terminator;

  (void)state;

  code = zone_open_string(&par, &opts, zone, strlen(zone));
  assert_int_equal(code, 0);
  code = zone_parse(&par, NULL);
  assert_int_equal(code, 0);
}

static const zone_options_t dummy_opts = {
  .default_class = 0,
  .default_ttl = 0,
  .allocator = { 0, 0, 0, NULL },
  .accept = { 0, &accept_rr, &accept_rdata, &accept_terminator }
};

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

  code = zone_open_string(&par, &dummy_opts, zone, strlen(zone));
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

  code = zone_open_string(&par, &dummy_opts, zone, strlen(zone));
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

  code = zone_open_string(&par, &dummy_opts, zone, strlen(zone));
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
