/*
 * ttl.c -- Test $TTL works as advertised
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <stdint.h>
#include <stdlib.h>

#include "zone.h"
#include "tools.h"

struct rr_ttl {
  size_t rr;
  size_t ttl_count;
  uint32_t *ttls;
};

static int32_t accept_rr(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)rdlength;
  (void)rdata;

  struct rr_ttl *rr_ttl = user_data;

  if (rr_ttl->rr >= rr_ttl->ttl_count)
    return ZONE_SYNTAX_ERROR;
  if (rr_ttl->ttls[rr_ttl->rr++] != ttl)
    return ZONE_SYNTAX_ERROR;
  return ZONE_SUCCESS;
}

/*!cmocka */
void correct_ttl_is_used(void **state)
{

  (void)state;

  struct {
    const char *str;
    struct rr_ttl ttls;
  } tests[] = {
    {
      "$ORIGIN com.\n"
      "example 300 IN SOA ns hostmaster 2024081901 3600 600 86400 3600\n"
      "example     IN NS  ns\n",
      { 0, 2, (uint32_t[]){ 300, 300 } }
    },
    {
      "$ORIGIN com.\n"
      "$TTL 350\n"
      "example 300 IN SOA ns hostmaster 2024081901 3600 600 86400 3600\n"
      "example     IN NS  ns\n",
      { 0, 2, (uint32_t[]){ 300, 350 } }
    }
  };

  for (int i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    size_t len = strlen(tests[i].str);
    char *str = malloc(len + ZONE_BLOCK_SIZE + 1);
    assert_non_null(str);
    memcpy(str, tests[i].str, len + 1);

    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    const uint8_t origin[1] = { 0 };
    int32_t code;

    memset(&options, 0, sizeof(options));
    options.accept.callback = accept_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = 1;

    code = zone_parse_string(&parser, &options, &buffers, str, (size_t)len, &tests[i].ttls);
    free(str);
    assert_int_equal(code, ZONE_SUCCESS);
    assert_int_equal(tests[i].ttls.rr, tests[i].ttls.ttl_count);
  }
}

/*!cmocka */
void correct_ttl_is_used_in_include(void **state)
{
  (void)state;

  struct {
    const char *fmt;
    const char *str;
    struct rr_ttl ttls;
  } tests[] = {
    { "$ORIGIN com.\n"
      "example 300 IN SOA ns hostmaster 2024081901 3600 600 86400 3600\n"
      "$INCLUDE \"%s\"\n"
      "example     IN A 192.0.2.1\n",
      "example 600 IN A 192.0.2.2\n"
      "example     IN A 192.0.2.3\n",
      { 0, 4, (uint32_t[]){ 300, 600, 600, 300 } }
    },
    { "$ORIGIN com.\n"
      "$TTL 350\n"
      "example 300 IN SOA ns hostmaster 2024081901 3600 600 86400 3600\n"
      "$INCLUDE \"%s\"\n"
      "example     IN A 192.0.2.1\n",
      "$TTL 650\n"
      "example 600 IN A 192.0.2.2\n"
      "example     IN A 192.0.2.3\n",
      { 0, 4, (uint32_t[]){ 300, 600, 650, 350 } }
    }
  };

  for (int i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    char *inc = get_tempnam(NULL, "zone");
    assert_non_null(inc);

    char buf[32];
    int len = snprintf(buf, sizeof(buf), tests[i].fmt, inc);
    assert_false(len < 0);
    char *str = malloc((size_t)len + ZONE_BLOCK_SIZE + 1);
    assert_non_null(str);
    (void)snprintf(str, (size_t)len + 1, tests[i].fmt, inc);

    FILE *handle = fopen(inc, "wb");
    assert_non_null(handle);
    int count = fputs(tests[i].str, handle);
    assert_int_not_equal(count, EOF);
    (void)fflush(handle);
    (void)fclose(handle);

    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    const uint8_t origin[1] = { 0 };
    int32_t code;

    memset(&options, 0, sizeof(options));
    options.accept.callback = accept_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = 1;

    code = zone_parse_string(&parser, &options, &buffers, str, (size_t)len, &tests[i].ttls);
    remove(inc);
    free(inc);
    free(str);
    assert_int_equal(code, ZONE_SUCCESS);
    assert_int_equal(tests[i].ttls.rr, tests[i].ttls.ttl_count);
  }
}
