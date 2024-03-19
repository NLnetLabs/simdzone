/*
 * base32.c -- test base32 support
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
#include "generic/endian.h"

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

static const uint8_t foobar[] =
  { 6, 'f', 'o', 'o', 'b', 'a', 'r' };

static uint8_t origin[] =
  { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

/*!cmocka */
void base32_syntax(void **state)
{
  static const struct {
    int32_t result;
    const char *base32;
    const uint8_t *octets;
    const size_t length;
  } tests[] = {
    // FIXME: add tests to ensure padding is not allowed
    // bad character in contiguous set
    { ZONE_SYNTAX_ERROR, "2t7b4g4vsa5zmi47k61mv5bv1a22bojr", NULL, 0 },
    //                               ^ (not in base32 alphabet)
    // bad character after contiguous set
    { ZONE_SYNTAX_ERROR, "2t7b4g4vsa5smi47k61mv5bv1a22bojz", NULL, 0 },
    //                          (not in base32 alphabet) ^
    // upper case
    { ZONE_SUCCESS, "CPNMUOJ1E8", foobar, sizeof(foobar) },
    // lower case
    { ZONE_SUCCESS, "cpnmuoj1e8", foobar, sizeof(foobar) },
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    char rr[256];
    const char rrfmt[] = "foo. NSEC3 1 1 12 aabbccdd ( %s A NS )";
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    (void)snprintf(rr, sizeof(rr), rrfmt, tests[i].base32);

    fprintf(stderr, "INPUT: '%s'\n", rr);

    options.accept.callback = add_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(&parser, &options, &buffers, rr, strlen(rr), NULL);
    assert_int_equal(result, tests[i].result);
    if (tests[i].result == ZONE_SUCCESS)
      assert_memory_equal(rdata.octets+9, tests[i].octets, tests[i].length);
  }
}
