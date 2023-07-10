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
#include <cmocka.h>
#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

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
  return 0;
}

/*!cmocka */
void time_stamp_syntax(void **state)
{
  static const struct {
    int32_t result;
    const char *timestamp;
    uint32_t seconds;
  } tests[] = {
    // bad number of digits
    { ZONE_SYNTAX_ERROR, "202301010101", 0 },
    { ZONE_SYNTAX_ERROR, "202301010101010", 0 },
    // year before 1970
    { ZONE_SYNTAX_ERROR, "19690101010101", 0 },
    // year after 2106
    { ZONE_SYNTAX_ERROR, "21070101010101", 0 },
    // month 0
    { ZONE_SYNTAX_ERROR, "20230001010101", 0 },
    // month 13
    { ZONE_SYNTAX_ERROR, "20231301010101", 0 },
    // february 29 non-leap year
    { ZONE_SYNTAX_ERROR, "20230229010101", 0 },
    // february 29 leap year
    { ZONE_SUCCESS, "20240229010101", 1709168461 },
    // hour 24
    { ZONE_SYNTAX_ERROR, "20230101240101", 0 },
    // minute 60
    { ZONE_SYNTAX_ERROR, "20230101016001", 0 },
    // correct time stamp
    { ZONE_SUCCESS, "20230704160000", 1688486400 }
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser = { 0 };
    zone_name_block_t name;
    zone_rdata_block_t rdata;
    zone_cache_t cache = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

#define FORMAT "host.example.com. 86400 IN RRSIG A 5 3 86400 %s (\n"      \
               "                  20030220173103 2642 example.com.\n"     \
               "                  oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr\n" \
               "                  PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o\n" \
               "                  B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t\n" \
               "                  GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG\n" \
               "                  J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )"

    size_t size = strlen(FORMAT) + ZONE_BLOCK_SIZE + 1;
    char *rr = malloc((size_t)size + 1);
    (void)snprintf(rr, size, FORMAT, tests[i].timestamp);

    options.accept.add = add_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    result = zone_parse_string(&parser, &options, &cache, rr, strlen(rr), NULL);
    free(rr);
    assert_int_equal(result, tests[i].result);
    if (tests[i].result != ZONE_SUCCESS)
      continue;
    uint32_t seconds;
    memcpy(&seconds, rdata.octets+8, sizeof(seconds));
    seconds = ntohl(seconds);
    assert_int_equal(seconds, tests[i].seconds);
  }
}
