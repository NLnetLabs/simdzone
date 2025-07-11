/*
 * time.c -- test RRSIG time stamp support
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>

#include "zone.h"
#include "attributes.h"
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
  return 0;
}

static uint8_t origin[] =
  { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

/*!cmocka */
void time_stamp_syntax(void **state)
{
  static const struct {
    const char *timestamp;
    uint32_t seconds;
    int32_t result;
  } tests[] = {
    // Time specified in seconds since epoch
    { "4294967295", 4294967295, ZONE_SUCCESS },
    // one second over maximum value
    { "4294967296", 0, ZONE_SYNTAX_ERROR },
    // starts with zero
    { "01", 1, ZONE_SUCCESS },
    // Time specified as YYYYMMDDHHmmSS
    // bad number of digits
    { "202301010101", 0, ZONE_SYNTAX_ERROR },
    { "202301010101010", 0, ZONE_SYNTAX_ERROR },
    // year before 1970
    { "19690101010101", 0, ZONE_SYNTAX_ERROR },
    // year after 2106
    { "21070101010101", 28319565, ZONE_SUCCESS },
    // month 0
    { "20230001010101", 0, ZONE_SYNTAX_ERROR },
    // month 13
    { "20231301010101", 0, ZONE_SYNTAX_ERROR },
    // february 29 non-leap year
    { "20230229010101", 0, ZONE_SYNTAX_ERROR },
    // february 29 leap year
    { "20240229010101", 1709168461, ZONE_SUCCESS },
    // hour 24
    { "20230101240101", 0, ZONE_SYNTAX_ERROR },
    // minute 60
    { "20230101016001", 0, ZONE_SYNTAX_ERROR },
    // correct time stamp
    { "20230704160000", 1688486400, ZONE_SUCCESS }
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    int32_t result;

#define FORMAT "host.example.com. 86400 IN RRSIG A 5 3 86400 %s (\n"      \
               "                  20030220173103 2642 example.com.\n"     \
               "                  oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr\n" \
               "                  PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o\n" \
               "                  B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t\n" \
               "                  GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG\n" \
               "                  J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )"

    size_t size = strlen(FORMAT) + strlen(tests[i].timestamp) + ZONE_BLOCK_SIZE + 1;
    char *rr = calloc((size_t)size + 1, 1);
    (void)snprintf(rr, size, FORMAT, tests[i].timestamp);

    fprintf(stderr, "INPUT: %s\n", rr);
    memset(&options, 0, sizeof(options));
    options.accept.callback = add_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_CLASS_IN;

    result = zone_parse_string(&parser, &options, &buffers, rr, strlen(rr), NULL);
    free(rr);
    assert_int_equal(result, tests[i].result);
    if (tests[i].result != ZONE_SUCCESS)
      continue;
    uint32_t seconds;
    memcpy(&seconds, rdata.octets+8, sizeof(seconds));
    seconds = be32toh(seconds);
    assert_int_equal(seconds, tests[i].seconds);
  }
}
