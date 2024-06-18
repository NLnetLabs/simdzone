/*
 * syntax.c -- presentation format syntax test cases
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>
#if !_WIN32
#include <unistd.h>
#endif

#include "zone.h"
#include "diagnostic.h"

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

// FIXME: test for unterminated string here too!

struct newline_test {
  const char *input;
  size_t line[2];
};

static int32_t newline_test_accept_rr(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  struct newline_test *test;

  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;

  assert(user_data);
  test = (struct newline_test *)user_data;

  if (owner->octets[1] == '1')
    return parser->file->line == test->line[0] ? 0 : ZONE_SYNTAX_ERROR;
  else if (owner->octets[1] == '2')
    return parser->file->line == test->line[1] ? 0 : ZONE_SYNTAX_ERROR;
  else
    return ZONE_SYNTAX_ERROR;
}

/*!cmocka */
void newlines(void **state)
{
  static const char quoted_lf_text[] =
    PAD("1. TXT \"foo\nbar\n\"\n2. TXT \"foobar\"");
  static const char escaped_lf_text[] =
    PAD("1. TXT foo\\\nbar\\\n\n2. TXT \"foobar\"");
  static const char grouped_lf_text[] =
    PAD("1. TXT (\nfoo\nbar\n)\n2. TXT \"foobar\"");
  static const char plain_lf_text[] =
    PAD("1. TXT \"foo bar\"\n2. TXT \"foo baz\"");
  static const char control_lf_text[] =
    PAD("$TTL 3600\n1. TXT \"foo bar\"\n2. TXT \"foo baz\"");
  static const char blank_lf_text[] =
    PAD("\n1. TXT \"foo bar\"\n\n2. TXT \"foo baz\"");

  static const uint8_t origin[] = { 0 };

  static const struct newline_test tests[] = {
    { quoted_lf_text, { 1, 4 } },
    { escaped_lf_text, { 1, 4 } },
    { grouped_lf_text, { 1, 5 } },
    { plain_lf_text, { 1, 2 } },
    { control_lf_text, { 2, 3 } },
    { blank_lf_text, { 2, 4 } }
  };

  (void)state;

  for (size_t i=0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    int32_t result;

    memset(&options, 0, sizeof(options));
    options.accept.callback = newline_test_accept_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_CLASS_IN;

    fprintf(stderr, "INPUT: \"%s\"\n", tests[i].input);
    result = zone_parse_string(
      &parser, &options, &buffers, tests[i].input, strlen(tests[i].input), (void*)&tests[i]);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}

struct strings_test {
  const char *text;
  int32_t code;
  struct {
    size_t length;
    const uint8_t *octets;
  } rdata;
};

static int32_t strings_callback(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  struct strings_test *test = (struct strings_test *)user_data;

  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  if (rdlength != test->rdata.length)
    return ZONE_SYNTAX_ERROR;
  if (memcmp(rdata, test->rdata.octets, rdlength) != 0)
    return ZONE_SYNTAX_ERROR;
  return 0;
}

#define RDATA(...) (const uint8_t[]){ __VA_ARGS__ }

#define TEXT16 \
  "0123456789abcdef"

#define TEXT256 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16 TEXT16

#define TEXT255 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16 TEXT16 \
  TEXT16 TEXT16 TEXT16        \
  "0123456789abcde"

#define RDATA16 \
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'

#define RDATA255 \
  RDATA16, RDATA16, RDATA16, RDATA16, \
  RDATA16, RDATA16, RDATA16, RDATA16, \
  RDATA16, RDATA16, RDATA16, RDATA16, \
  RDATA16, RDATA16, RDATA16,          \
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e'

/*!cmocka */
void strings(void **state)
{
  (void)state;

  static const uint8_t rdata_maximum[] = { 255, RDATA255 };

  static const uint8_t rdata_empty[] = { 0 };

  static const uint8_t rdata_0[] = { 1, 0 };

  static const uint8_t rdata_0foo[] = { 4, 0, 'f', 'o', 'o' };

  static const uint8_t rdata_foo0[] = { 4, 'f', 'o', 'o', 0 };

  static const uint8_t rdata_0f0o[] = { 4, 0, 'f', 0, 'o' };

  static const uint8_t rdata_foo_bar[] = { 7, 'f', 'o', 'o', ' ', 'b', 'a', 'r' };

  static const struct strings_test tests[] = {
    // contiguous too long
    { TEXT256, ZONE_SYNTAX_ERROR, { 0, NULL } },
    // quoted too long
    { "\"" TEXT256 "\"", ZONE_SYNTAX_ERROR, { 0, NULL } },
    // contiguous maximum length
    { TEXT255, 0, { 256, rdata_maximum } },
    // quoted maximum length
    { TEXT255, 0, { 256, rdata_maximum } },
    // quoted empty
    { "\"\"", 0, { 1, rdata_empty } },
    // contiguous null
    { "\\000", 0, { 2, rdata_0 } },
    // quoted null
    { "\"\\000\"", 0, { 2, rdata_0 } },
    // contiguous starting with null
    { "\\000foo", 0, { 5, rdata_0foo } },
    // quoted staring with null
    { "\"\\000foo\"", 0, { 5, rdata_0foo } },
    // contiguous ending with null
    { "foo\\000", 0, { 5, rdata_foo0 } },
    // quoted ending with null
    { "\"foo\\000\"", 0, { 5, rdata_foo0 } },
    // contiguous with multiple nulls
    { "\\000f\\000o", 0, { 5, rdata_0f0o } },
    // quoted with multiple nulls
    { "\"\\000f\\000o\"", 0, { 5, rdata_0f0o } },
    // contiguous with escaped space
    { "foo\\ bar", 0, { 8, rdata_foo_bar } },
    // quoted with space
    { "\"foo bar\"", 0, { 8, rdata_foo_bar } }
  };

  static const uint8_t origin[] = { 3, 'f', 'o', 'o', 0 };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    char input[512] = { 0 };
    size_t length;
    int32_t code;

    (void)snprintf(input, sizeof(input), "foo. TXT %s", tests[i].text);
    length = strlen(input);

    memset(&options, 0, sizeof(options));
    options.accept.callback = strings_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_CLASS_IN;

    fprintf(stderr, "INPUT: '%s'\n", input);
    code = zone_parse_string(&parser, &options, &buffers, input, length, (void *)&tests[i]);
    assert_int_equal(code, tests[i].code);
  }
}

struct names_test {
  const char *input;
  int32_t code;
  struct {
    size_t length;
    const uint8_t *octets;
  } owner;
};

static int32_t names_callback(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  struct names_test *test = (struct names_test *)user_data;

  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  if (owner->length != test->owner.length)
    return ZONE_SYNTAX_ERROR;
  if (memcmp(owner->octets, test->owner.octets, owner->length) != 0)
    return ZONE_SYNTAX_ERROR;
  return 0;
}

/*!cmocka */
void names(void **state)
{
  (void)state;

  static const char only_rel_label_too_long[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  static const char only_abs_label_too_long[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.";

  static const char first_label_too_long[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.foo.";

  static const char last_rel_label_too_long[] =
    "foo.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  static const char last_abs_label_too_long[] =
    "foo.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.";

  static const char rel_name_max_len[] =
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef012345678";

  static const char rel_name_too_long[] =
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789";

  static const char abs_name_max_len[] =
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abc.";

  static const char abs_name_too_long[] =
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcde."
    "0123456789abcdef0123456789abcd.";

  static const char only_null_labels[] = "..";
  static const char last_label_is_null[] = "foo..";
  static const char first_label_is_null[] = "..foo";
  static const char star_dot_3[] = "\\042.\\042.\\042.wcent.nlnetlabs.nl.";

  static const uint8_t owner_abs_0[] = { 1, 0, 0 };
  static const uint8_t owner_abs_spc[] = { 1, ' ', 0 };
  static const uint8_t owner_abs_0foo[] = { 4, 0, 'f', 'o', 'o', 0 };
  static const uint8_t owner_abs_00foo[] = { 5, 0, 0, 'f', 'o', 'o', 0 };
  static const uint8_t owner_abs_foo0[] = { 4, 'f', 'o', 'o', 0, 0 };
  static const uint8_t owner_abs_foo00[] = { 5, 'f', 'o', 'o', 0, 0, 0 };
  static const uint8_t owner_abs_foodot[] = { 4, 'f', 'o', 'o', '.', 0 };
  static const uint8_t owner_rel_foodot[] = { 4, 'f', 'o', 'o', '.', 3, 'f', 'o', 'o', 0 };
  static const uint8_t owner_rel_max_len[] = {
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    25,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8',
     3,'f','o','o',
     0 };
  static const uint8_t owner_abs_max_len[] = {
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    31,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e',
    29,'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
       '0','1','2','3','4','5','6','7','8','9','a','b','c',
    0 };
  static const uint8_t owner_star_dot_3[] = {
    1, '*', 1, '*', 1, '*', 5, 'w', 'c', 'e', 'n', 't', 9, 'n', 'l', 'n', 'e', 't', 'l', 'a', 'b', 's', 2, 'n', 'l', 0
  };

  static struct names_test tests[] = {
    { only_rel_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { only_abs_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { first_label_too_long,     ZONE_SYNTAX_ERROR, { 0, NULL } },
    { last_rel_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { last_abs_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { rel_name_max_len,         0, { 255, owner_rel_max_len } },
    { rel_name_too_long,        ZONE_SYNTAX_ERROR, { 0, NULL } },
    { abs_name_max_len,         0, { 255, owner_abs_max_len } },
    { abs_name_too_long,        ZONE_SYNTAX_ERROR, { 0, NULL } },
    { only_null_labels,         ZONE_SYNTAX_ERROR, { 0, NULL } },
    { last_label_is_null,       ZONE_SYNTAX_ERROR, { 0, NULL } },
    { first_label_is_null,      ZONE_SYNTAX_ERROR, { 0, NULL } },
    { "\\0.",                   ZONE_SYNTAX_ERROR, { 0, NULL } },
    { "\\00.",                  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { "\\000.",                 0, { 3, owner_abs_0 } },
    { "\\ .",                   0, { 3, owner_abs_spc } },
    { "\\000foo. ",             0, { 6, owner_abs_0foo } },
    { "\\000\\000foo.",         0, { 7, owner_abs_00foo } },
    { "foo\\000.",              0, { 6, owner_abs_foo0 } },
    { "foo\\000\\000.",         0, { 7, owner_abs_foo00 } },
    { "foo\\..",                0, { 6, owner_abs_foodot } },
    { "foo\\.",                 0, { 10, owner_rel_foodot } },
    { star_dot_3,               0, { sizeof(owner_star_dot_3), owner_star_dot_3 } }
  };

  static const uint8_t origin[] = { 3, 'f', 'o', 'o', 0 };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    char input[512] = { 0 };
    size_t length;
    int32_t code;

    (void)snprintf(input, sizeof(input), "%s A 192.168.0.1", tests[i].input);
    length = strlen(input);

    memset(&options, 0, sizeof(options));
    options.accept.callback = names_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_CLASS_IN;

    fprintf(stderr, "INPUT: '%s'\n", input);
    code = zone_parse_string(&parser, &options, &buffers, input, length, &tests[i]);
    assert_int_equal(code, tests[i].code);
  }
}

struct ttls_test {
  const char *text;
  bool non_strict;
  bool pretty_ttls;
  int32_t code;
  uint32_t ttl;
};

static int32_t tests_callback(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  const struct ttls_test *test = (const struct ttls_test *)user_data;

  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  if (ttl != test->ttl)
    return ZONE_SYNTAX_ERROR;
  return 0;
}

/*!cmocka */
void ttls(void **state)
{
  (void)state;

  static const struct ttls_test tests[] = {
    { PAD("foo. 0 A 192.168.0.1"), false, false, ZONE_SUCCESS, 0 },
    { PAD("foo. 1 A 192.168.0.1"), false, false, ZONE_SUCCESS, 1 },
    { PAD("foo. 2147483647 A 192.168.0.1"), false, false, ZONE_SUCCESS, 2147483647 },
    { PAD("foo. 2147483648 A 192.168.0.1"), false, false, ZONE_SEMANTIC_ERROR, 0 },
    { PAD("foo. 2147483648 A 192.168.0.1"), true, false, ZONE_SUCCESS, 2147483648 },
    { PAD("foo. 4294967295 A 192.168.0.1"), true, false, ZONE_SUCCESS, 4294967295 },
    { PAD("foo. 4294967296 A 192.168.0.1"), true, false, ZONE_SYNTAX_ERROR, 0 },
    { PAD("foo. 1d A 192.168.0.1"), false, false, ZONE_SYNTAX_ERROR, 0 },
    { PAD("foo. 1d A 192.168.0.1"), false, true, ZONE_SUCCESS, 86400 }
  };

  static const uint8_t origin[] = { 3, 'f', 'o', 'o', 0 };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    const char *str = tests[i].text;
    size_t len = strlen(str);
    int32_t code;

    memset(&options, 0, sizeof(options));
    options.accept.callback = tests_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_CLASS_IN;
    options.secondary = tests[i].non_strict;
    options.pretty_ttls = tests[i].pretty_ttls;

    fprintf(stderr, "INPUT: '%s'\n", str);
    code = zone_parse_string(&parser, &options, &buffers, str, len, (void*)&tests[i]);
    assert_int_equal(code, tests[i].code);
  }
}

static int32_t dummy_callback(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  size_t *count = (size_t *)user_data;

  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  (*count)++;

  return 0;
}

static int32_t parse(const char *text, size_t *count)
{
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  const uint8_t origin[] = { 0 };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &dummy_callback;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  fprintf(stderr, "INPUT: '%s'\n", text);
  return zone_parse_string(&parser, &options, &buffers, text, strlen(text), count);
}

static char *generate_include(const char *text)
{
  char *path = tempnam(NULL, "zone");
  if (path) {
    FILE *handle = fopen(path, "wbx");
    if (handle) {
      int result = fputs(text, handle);
      (void)fclose(handle);
      if (result != EOF)
        return path;
    }
    free(path);
  }
  return NULL;
}

diagnostic_push()
msvc_diagnostic_ignored(4996)
static void remove_include(const char *path)
{
  unlink(path);
}
diagnostic_pop()

static int32_t parse_as_include(const char *text, size_t *count)
{
  int32_t code;
  char *path = generate_include(text);
  assert_non_null(path);
  char dummy[16];
  int length = snprintf(dummy, sizeof(dummy), "$INCLUDE \"%s\"\n", path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\"\n", path);
  code = parse(include, count);
  free(include);
  remove_include(path);
  free(path);
  return code;
}

/*!cmocka */
void who_dis(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;
  static const char *dat = PAD(" TXT \"dat\"");
  static const char *dis_n_dat = PAD("dis. TXT \"dis\"\n"
                                     "     TXT \"dat\"");

  code = parse(dat, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(dis_n_dat, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 2);
}

/*!cmocka */
void quote_no_unquote(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;
  static const char *no_unquote = PAD("foo. TXT \"unterminated string");

  code = parse(no_unquote, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);

  code = parse_as_include(no_unquote, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
}

/*!cmocka */
void not_so_famous_last_words(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;
  static const char *last_words = PAD("; not so famous last words");

  code = parse(last_words, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 0);

  code = parse_as_include(last_words, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 0);
}

/*!cmocka */
void no_famous_last_words(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;
  static const char *empty = PAD(" ");

  code = parse(empty, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 0);

  code = parse_as_include(empty, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 0);
}

/*!cmocka */
void bad_a_rrs(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;
  static const char *no_a = PAD("foo. A ; no-address");
  static const char *double_a = PAD("foo. A 192.168.0.1 192.168.0.2");
  static const char *bad_a = PAD("foo. A 192.168.0.256");

  code = parse(no_a, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(double_a, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(bad_a, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
}

/*!cmocka */
void bad_ttls(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;

  static const char *too_little = PAD("$TTL ; no time");
  static const char *too_late = PAD("$TTL 2147483648"); // one second too much
  static const char *too_much = PAD("$TTL 1 2"); // trailing data

  code = parse(too_little, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(too_late, &count);
  assert_int_equal(code, ZONE_SEMANTIC_ERROR);
  code = parse(too_much, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
}

/*!cmocka */
void bad_origins(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;

  static const char *no_origin = PAD("$ORIGIN ; no origin");
  static const char *extra_origin = PAD("$ORIGIN a. b.");
  static const char *relative_origin = PAD("$ORIGIN foo");

  code = parse(no_origin, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(extra_origin, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
  code = parse(relative_origin, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
}

/*!cmocka */
void bad_includes(void **state)
{
  (void)state;

  int32_t code;
  size_t count = 0;

  static const char *no_include = PAD("$INCLUDE ; no include");

  code = parse(no_include, &count);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);

  char *path = generate_include(" ");
  assert_non_null(path);
  FILE* handle = fopen(path, "wb");
  assert_non_null(handle);
  char dummy[32];
  int length = snprintf(dummy, sizeof(dummy), "$INCLUDE \"%s\" foo. bar\n", path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\" foo. bar.\n", path);
  int result = fputs(include, handle);
  assert_true(result >= 0);
  (void)fclose(handle);
  free(path);
  code = parse(include, &count);
  free(include);
  assert_int_equal(code, ZONE_SYNTAX_ERROR);
}

static int32_t include_origin_callback(
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
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;

  static const uint8_t foobaz[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'z', 0 };

  assert(owner);
  if (owner->length != 9 || memcmp(owner->octets, foobaz, 9) != 0)
    return ZONE_SEMANTIC_ERROR;

  return 0;
}

/*!cmocka */
void include_with_origin(void **state)
{
  (void)state;

  char *path = generate_include("foo TXT bar");
  assert_non_null(path);
  char dummy[32];
  int length = snprintf(dummy, sizeof(dummy), "$INCLUDE \"%s\" baz.", path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\" baz.", path);

  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  static const uint8_t origin[] = { 3, 'b', 'a', 'r',  0 };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &include_origin_callback;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  int32_t code = zone_parse_string(&parser, &options, &buffers, include, strlen(include), NULL);

  remove_include(path);
  free(path);
  free(include);

  assert_int_equal(code, ZONE_SUCCESS);
}

static int32_t no_origin_callback(
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
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;

  static const uint8_t foobar[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };

  assert(owner);
  if (owner->length != 9 || memcmp(owner->octets, foobar, 9) != 0)
    return ZONE_SEMANTIC_ERROR;

  return 0;
}

/*!cmocka */
void include_without_origin(void **state)
{
  (void)state;

  char *path = generate_include("foo TXT bar");
  assert_non_null(path);
  char dummy[32];
#define FMT "$INCLUDE \"%s\""
  int length = snprintf(dummy, sizeof(dummy), "$INCLUDE \"%s\"", path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\"", path);
#undef FMT

  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  static const uint8_t origin[] = { 3, 'b', 'a', 'r',  0 };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &no_origin_callback;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  int32_t code = zone_parse_string(&parser, &options, &buffers, include, strlen(include), NULL);

  remove_include(path);
  free(path);
  free(include);

  assert_int_equal(code, ZONE_SUCCESS);
}

static int32_t reinstate_callback(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  size_t *count = (size_t *)user_data;

  static const uint8_t foobar[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
  static const uint8_t foobaz[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'z', 0 };

  (void)parser;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  switch (*count) {
    case 0:
      if (owner->length != 9 || memcmp(owner->octets, foobar, 9) != 0)
        return ZONE_SYNTAX_ERROR;
      break;
    case 1: // include
      if (owner->length != 9 || memcmp(owner->octets, foobaz, 9) != 0)
        return ZONE_SYNTAX_ERROR;
      break;
    case 2:
      if (owner->length != 9 || memcmp(owner->octets, foobar, 9) != 0)
        return ZONE_SYNTAX_ERROR;
      break;
  }

  (*count)++;
  return 0;
}

/*!cmocka */
void owner_is_reinstated(void **state)
{
  // check closing of include reinstates owner

  (void)state;
  char *path = generate_include("foo.baz. TXT foobar");
  assert_non_null(path);
  char dummy[64];
#define FMT \
  "foo.bar. TXT foobar\n" \
  "$INCLUDE \"%s\" baz.\n" \
  " TXT foobar"
  int length = snprintf(dummy, sizeof(dummy), FMT, path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, FMT, path);
#undef FMT

  size_t count = 0;
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  static const uint8_t origin[] = { 3, 'b', 'a', 'r',  0 };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &reinstate_callback;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  int32_t code = zone_parse_string(&parser, &options, &buffers, include, strlen(include), &count);
  remove_include(path);
  free(path);
  free(include);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 3);
}

/*!cmocka */
void origin_is_reinstated(void **state)
{
  // check closing of include reinstates origin

  (void)state;
  char *path = generate_include("foo.baz. TXT foobar");
  assert_non_null(path);
  char dummy[64];
#define FMT \
  "foo.bar. TXT foobar\n" \
  "$INCLUDE \"%s\" baz.\n" \
  "foo TXT foobar"
  int length = snprintf(dummy, sizeof(dummy), FMT, path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, FMT, path);
#undef FMT

  size_t count = 0;
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  static const uint8_t origin[] = { 3, 'b', 'a', 'r',  0 };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &reinstate_callback;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  int32_t code = zone_parse_string(&parser, &options, &buffers, include, strlen(include), &count);
  remove_include(path);
  free(path);
  free(include);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(count == 3);
}

static int32_t contiguous_escaped_start_cb(
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

/*!cmocka */
void contiguous_escaped_start(void** state)
{
  /* Check that the fallback parser handles a scan of a contiguous segment
   * that starts with is_escaped. */
  char* zone =
"$ORIGIN example.\n"
"$TTL 3600\n"
"@	IN	SOA	ns postmaster.mail 2147483647 3600 900 1814400 900\n"
"	IN	NS	ns\n"
"ns	IN	A	203.0.113.53\n"
"ns	IN	AAAA	2001:db8:feed:beef::53\n"
"\n"
"0000000	IN	A	192.0.2.0\n"
"0000000	IN	TYPE994	\\# 10 30313233343536373839\n"
"0000001	IN	A	192.0.2.1\n"
"0000001	IN	TYPE994	\\# 11 3031323334353637383961\n"
"0000002	IN	A	192.0.2.2\n"
"0000002	IN	TYPE994	\\# 12 303132333435363738396162\n"
"0000003	IN	A	192.0.2.3\n"
"0000003	IN	TYPE994	\\# 13 30313233343536373839616263\n"
"0000004	IN	A	192.0.2.4\n"
"0000004	IN	TYPE994	\\# 14 3031323334353637383961626364\n"
"0000005	IN	A	192.0.2.5\n"
"0000005	IN	TYPE994	\\# 15 303132333435363738396162636465\n"
"0000006	IN	A	192.0.2.6\n"
"0000006	IN	TYPE994	\\# 16 30313233343536373839616263646566\n"
	;
  static uint8_t origin[] = { 0 };
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  int32_t result;
  (void) state;

  memset(&options, 0, sizeof(options));
  options.accept.callback = contiguous_escaped_start_cb;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = ZONE_CLASS_IN;

  result = zone_parse_string(&parser, &options, &buffers, zone, strlen(zone),
    NULL);
  assert_int_equal(result, ZONE_SUCCESS);
}
