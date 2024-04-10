/*
 * eui.c -- test EUI support
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

struct eui_test {
  int32_t code;
  uint16_t type;
  const char *text;
  const uint8_t *rdata;
};

static int32_t accept_eui48_and_eui64(
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

  const struct eui_test *test = (void *)user_data;

  if (test->code != 0)
    return ZONE_SYNTAX_ERROR;
  if (test->type == ZONE_TYPE_EUI48 && rdlength != 6)
    return ZONE_SYNTAX_ERROR;
  if (test->type == ZONE_TYPE_EUI64 && rdlength != 8)
    return ZONE_SYNTAX_ERROR;
  if (memcmp(rdata, test->rdata, rdlength) != 0)
    return ZONE_SYNTAX_ERROR;
  return 0;
}

#define PAD(literal) \
  literal \
  "\0\0\0\0\0\0\0\0" /*  0 -  7 */ \
  "\0\0\0\0\0\0\0\0" /*  8 - 15 */ \
  "\0\0\0\0\0\0\0\0" /* 16 - 23 */ \
  "\0\0\0\0\0\0\0\0" /* 24 - 31 */ \
  "\0\0\0\0\0\0\0\0" /* 32 - 39 */ \
  "\0\0\0\0\0\0\0\0" /* 40 - 47 */ \
  "\0\0\0\0\0\0\0\0" /* 48 - 55 */ \
  "\0\0\0\0\0\0\0\0" /* 56 - 63 */ \
  ""

/*!cmocka */
void eui48_and_eui64(void **state)
{
  static uint8_t origin[] =
    { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
  static const uint8_t eui48_address[] =
    { 0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a };
  static const uint8_t eui64_address[] =
    { 0x00, 0x00, 0x5e, 0xef, 0x10, 0x00, 0x00, 0x2a };

  static const struct eui_test tests[] = {
    // EUI48
    { 0, ZONE_TYPE_EUI48, PAD("host.example. 86400 IN EUI48 00-00-5e-00-53-2a"), eui48_address },
    // missing rdata
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48"), NULL },
    // trailing rdata
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 00-00-5e-00-53-2a foobar"), NULL },
    // quoted address
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 \"00-00-5e-00-53-2a\""), NULL },
    // bad addresses
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 00-00-5e-00-53-2"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 00-00-5e-00-53-2a-"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 00.00.5e.00.53.2a"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 0--00-5e-00-53-2a"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI48, PAD("@ EUI48 foobar"), NULL },
    // EUI64
    { 0, ZONE_TYPE_EUI64, PAD("host.example. 86400 IN EUI64 00-00-5e-ef-10-00-00-2a"), eui64_address },
    // missing rdata
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64"), NULL },
    // trailing rdata
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 00-00-5e-ef-10-00-00-2a foobar"), NULL },
    // quoted address
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 \"00-00-5e-ef-10-00-00-2a\""), NULL },
    // bad addresses
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 00-00-5e-ef-10-00-00-2"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 00-00-5e-ef-10-00-00-2a-"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 00.00.5e.ef.10.00.00.2a"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 0--00-5e-ef-10-00-00-2a"), NULL },
    { ZONE_SYNTAX_ERROR, ZONE_TYPE_EUI64, PAD("@ EUI64 foobar"), NULL },
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    int32_t code;
    const struct eui_test *test = &tests[i];

    fprintf(stderr, "INPUT: %s\n", test->text);

    memset(&options, 0, sizeof(options));
    options.accept.callback = accept_eui48_and_eui64;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = 1;

    code = zone_parse_string(&parser, &options, &buffers, test->text, strlen(test->text), (void*)test);
    assert_int_equal(code, test->code);
  }
}
