/*
 * ip4.c -- test IPv4 support
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "zone.h"

static int32_t add_rr(
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
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;
  return ZONE_SUCCESS;
}

static const uint8_t address_192_0_2_1[] = { 192, 0, 2, 1 };

/*!cmocka */
void ipv4_syntax(void **state)
{
  static const struct {
    int32_t result;
    const char *address;
    const uint8_t *octets;
  } tests[] = {
    // bad number of digits in octet
    { ZONE_SYNTAX_ERROR, "1111.1.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1111.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1111.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1.1111", NULL },
    // bad number of octets
    { ZONE_SYNTAX_ERROR, "1.1.1.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1", NULL },
    // bad number of dots
    { ZONE_SYNTAX_ERROR, ".1.1.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "..1.1.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1..1.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1..1.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1..1", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1.1.", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.1.1..", NULL },
    // bad number of octets, right number of dots
    { ZONE_SYNTAX_ERROR, "1.1.1.", NULL },
    { ZONE_SYNTAX_ERROR, ".1.1.1", NULL },
    // bad octets
    { ZONE_SYNTAX_ERROR, "1.1.1.256", NULL },
    { ZONE_SYNTAX_ERROR, "1.1.256.1", NULL },
    { ZONE_SYNTAX_ERROR, "1.256.1.1", NULL },
    { ZONE_SYNTAX_ERROR, "256.1.1.1", NULL },
    // leading zeroes
    { ZONE_SYNTAX_ERROR, "192.00.2.1", NULL },
    { ZONE_SYNTAX_ERROR, "192.0.02.1", NULL },
    { ZONE_SYNTAX_ERROR, "192.0.2.01", NULL },
    { ZONE_SUCCESS, "192.0.2.1", address_192_0_2_1 }
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    char rr[128];
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    (void)snprintf(rr, sizeof(rr), " A %s", tests[i].address);

    options.accept.callback = add_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(&parser, &options, &buffers, rr, strlen(rr), NULL);
    assert_int_equal(result, tests[i].result);
    if (tests[i].octets)
      assert_memory_equal(rdata.octets, tests[i].octets, 4);
  }
}
