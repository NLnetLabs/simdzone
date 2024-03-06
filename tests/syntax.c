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
#if 0
  static const char embedded_lf_text[] =
    PAD("1. TXT \"foo\nbar\n\"\n2. TXT \"foobar\"");
  // >> do the same thing for contiguous
#endif
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
#if 0
    { embedded_lf_text, { 1, 4 } },
#endif
    { grouped_lf_text, { 1, 5 } },
    { plain_lf_text, { 1, 2 } },
    { control_lf_text, { 2, 3 } },
    { blank_lf_text, { 2, 4 } }
  };

  (void)state;

  for (size_t i=0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    options.accept.callback = newline_test_accept_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

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
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    char input[512] = { 0 };
    size_t length;
    int32_t code;

    (void)snprintf(input, sizeof(input), "foo. TXT %s", tests[i].text);
    length = strlen(input);

    options.accept.callback = strings_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

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

  static const char rel_name_too_long[] =
    "0123456789abcdef0123456789abcde."   /*  32 */
    "0123456789abcdef0123456789abcde."   /*  64 */
    "0123456789abcdef0123456789abcde."   /*  96 */
    "0123456789abcdef0123456789abcde."   /* 128 */
    "0123456789abcdef0123456789abcde."   /* 160 */
    "0123456789abcdef0123456789abcde."   /* 192 */
    "0123456789abcdef0123456789abcde."   /* 224 */
    "0123456789abcdef0123456789a"; /* .foo. 256 */

  static const char abs_name_too_long[] =
    "0123456789abcdef0123456789abcde."  /*  32 */
    "0123456789abcdef0123456789abcde."  /*  64 */
    "0123456789abcdef0123456789abcde."  /*  96 */
    "0123456789abcdef0123456789abcde."  /* 128 */
    "0123456789abcdef0123456789abcde."  /* 160 */
    "0123456789abcdef0123456789abcde."  /* 192 */
    "0123456789abcdef0123456789abcde."  /* 224 */
    "0123456789abcdef0123456789abcde."; /* 256 */

  static const char only_null_labels[] = "..";
  static const char last_label_is_null[] = "foo..";
  static const char first_label_is_null[] = "..foo";

  static const uint8_t owner_abs_0[] = { 1, 0, 0 };
  static const uint8_t owner_abs_spc[] = { 1, ' ', 0 };
  static const uint8_t owner_abs_0foo[] = { 4, 0, 'f', 'o', 'o', 0 };
  static const uint8_t owner_abs_00foo[] = { 5, 0, 0, 'f', 'o', 'o', 0 };
  static const uint8_t owner_abs_foo0[] = { 4, 'f', 'o', 'o', 0, 0 };
  static const uint8_t owner_abs_foo00[] = { 5, 'f', 'o', 'o', 0, 0, 0 };
  static const uint8_t owner_abs_foodot[] = { 4, 'f', 'o', 'o', '.', 0 };
  static const uint8_t owner_rel_foodot[] = { 4, 'f', 'o', 'o', '.', 3, 'f', 'o', 'o', 0 };

  static struct names_test tests[] = {
    { only_rel_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { only_abs_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { first_label_too_long,     ZONE_SYNTAX_ERROR, { 0, NULL } },
    { last_rel_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { last_abs_label_too_long,  ZONE_SYNTAX_ERROR, { 0, NULL } },
    { rel_name_too_long,        ZONE_SYNTAX_ERROR, { 0, NULL } },
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
    { "foo\\.",                 0, { 10, owner_rel_foodot } }
  };

  static const uint8_t origin[] = { 3, 'f', 'o', 'o', 0 };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    char input[512] = { 0 };
    size_t length;
    int32_t code;

    (void)snprintf(input, sizeof(input), "%s A 192.168.0.1", tests[i].input);
    length = strlen(input);

    options.accept.callback = names_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

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
    { "foo. 0 A 192.168.0.1", false, false, ZONE_SUCCESS, 0 },
    { "foo. 1 A 192.168.0.1", false, false, ZONE_SUCCESS, 1 },
    { "foo. 2147483647 A 192.168.0.1", false, false, ZONE_SUCCESS, 2147483647 },
    { "foo. 2147483648 A 192.168.0.1", false, false, ZONE_SEMANTIC_ERROR, 0 },
    { "foo. 2147483648 A 192.168.0.1", true, false, ZONE_SUCCESS, 2147483648 },
    { "foo. 4294967295 A 192.168.0.1", true, false, ZONE_SUCCESS, 4294967295 },
    { "foo. 4294967296 A 192.168.0.1", true, false, ZONE_SYNTAX_ERROR, 0 },
    { "foo. 1d A 192.168.0.1", false, false, ZONE_SYNTAX_ERROR, 0 },
    { "foo. 1d A 192.168.0.1", false, true, ZONE_SUCCESS, 86400 }
  };

  static const uint8_t origin[] = { 3, 'f', 'o', 'o', 0 };

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    const char *str = tests[i].text;
    size_t len = strlen(str);
    int32_t code;

    options.accept.callback = tests_callback;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;
    options.non_strict = tests[i].non_strict;
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
  zone_options_t options = { 0 };
  const uint8_t origin[] = { 0 };

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
  assert_true(length > 0 && length < INT_MAX - ZONE_PADDING_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_PADDING_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\"\n", path);
  code = parse(include, count);
  free(include);
  remove_include(path);
  free(path);
  return code;
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
