/*
 * include.c -- Test $INCLUDE works as advertised
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#if _WIN32
#include <process.h>
#include <direct.h>
#else
#include <unistd.h>
#endif

#include "zone.h"
#include "diagnostic.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct input input_t;
struct input {
  struct {
    char *path;
    char *content;
    FILE *handle;
  } includer, include;
};

diagnostic_push()
msvc_diagnostic_ignored(4996)

/*!cmocka */
int teardown(void **state)
{
  input_t *input = *(input_t **)state;

  if (!input)
    return 0;

  if (input->includer.handle) {
    (void)fclose(input->includer.handle);
    assert(input->includer.path);
    unlink(input->includer.path);
  }

  if (input->include.handle) {
    (void)fclose(input->include.handle);
    assert(input->include.path);
    unlink(input->include.path);
  }

  if (input->includer.path)
    free(input->includer.path);
  if (input->includer.content)
    free(input->includer.content);
  if (input->include.path)
    free(input->include.path);
  if (input->include.content)
    free(input->include.content);

  free(input);

  return 0;
}

/*!cmocka */
int setup(void **state)
{
  input_t *input;

  if (!(input = calloc(1, sizeof(*input))))
    return -1;

  for (int i=0; i < 100 && !input->includer.handle; i++) {
    if (input->includer.path)
      free(input->includer.path);
    input->includer.path = tempnam(NULL, "zone");
    if (!input->includer.path)
      goto err;
    input->includer.handle = fopen(input->includer.path, "wbx");
  }

  if (!input->includer.handle)
    goto err;

  for (int i=0; i < 100 && !input->include.handle; i++) {
    if (input->include.path)
      free(input->include.path);
    input->include.path = tempnam(NULL, "zone");
    if (!input->includer.path)
      goto err;
    input->include.handle = fopen(input->include.path, "wbx");
  }

  if (!input->include.handle)
    goto err;

  size_t len;

#define FMT "$INCLUDE %s\n"
  len = (strlen(FMT) - 2) + strlen(input->include.path);
  if (!(input->includer.content = malloc(len+1 + ZONE_BLOCK_SIZE)))
    goto err;
  (void)snprintf(input->includer.content, len+1, FMT, input->include.path);
  if (fputs(input->includer.content, input->includer.handle) == EOF)
    goto err;
  (void)fflush(input->includer.handle);

#undef FMT
#define FMT "host.example.com. 3600 IN TXT foobar\n"
  len = strlen(FMT);
  if (!(input->include.content = malloc(len+1 + ZONE_BLOCK_SIZE)))
    goto err;
  (void)snprintf(input->include.content, len+1, FMT);
  if (fputs(input->include.content, input->include.handle) == EOF)
    goto err;
  (void)fflush(input->include.handle);

  *state = input;
  return 0;
err:
  teardown((void**)&input);
  return -1;
}

static char *temporary_name(void)
{
#if _WIN32
  int pid = _getpid();
#else
  pid_t pid = getpid();
#endif

  char format[128];
  snprintf(format, sizeof(format), "zone.%d", pid);
  return tempnam(NULL, format);
}

static char *generate_include(const char *text)
{
  for (int i=0; i < 100; i++) {
    char *path = temporary_name();
    if (path) {
      FILE *handle = fopen(path, "wbx");
      if (handle) {
        int error = fputs(text, handle);
        fflush(handle);
        (void)fclose(handle);
        if (error != EOF)
          return path;
      }
      free(path);
    }
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

static int32_t parse(
  const zone_options_t *options, const char *text, void *user_data)
{
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };

  int32_t code;
  size_t length = strlen(text);
  char *string = malloc(length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(string);
  memcpy(string, text, length);
  string[length] = '\0';

  code = zone_parse_string(&parser, options, &buffers, string, length, user_data);
  free(string);
  return code;
}

diagnostic_pop()

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
  (void)type;
  (void)owner;
  (void)class;
  (void)ttl;
  (void)user_data;

  const uint8_t expect[] = { 6, 'f', 'o', 'o', 'b', 'a', 'r' };

  assert_int_equal(rdlength, sizeof(expect));
  assert_memory_equal(rdata, expect, sizeof(expect));

  return ZONE_SUCCESS;
}

static uint8_t origin[] =
  { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

/*!cmocka setup:setup teardown:teardown */
void include_from_string(void **state)
{
  input_t *input;
  zone_parser_t parser;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options;
  int32_t result;

  memset(&options, 0, sizeof(options));
  options.accept.callback = &add_rr;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = ZONE_CLASS_IN;

  input = (input_t *)*state;

  // verify $INCLUDE is denied by default when parsing strings.
  const char *str = input->includer.content;
  result = zone_parse_string(&parser, &options, &buffers, str, strlen(str), NULL);
  assert_false(options.no_includes);
  assert_int_equal(result, ZONE_SUCCESS);

  // verify $INCLUDE is allowed and works as intented if configured.
  options.no_includes = true;
  result = zone_parse_string(&parser, &options, &buffers, str, strlen(str), NULL);
  assert_int_equal(result, ZONE_NOT_PERMITTED);
}


typedef struct no_file_test no_file_test_t;
struct no_file_test {
  bool have_file;
  size_t accept_count, log_count;
};

static int32_t no_such_file_accept(
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
  no_file_test_t *test = (no_file_test_t *)user_data;
  test->accept_count++;
  return 0;
}

static void no_such_file_log(
  zone_parser_t *parser,
  uint32_t priority,
  const char *file,
  size_t line,
  const char *message,
  void *user_data)
{
  (void)parser;
  (void)priority;
  (void)line;
  if (!strstr(message, "no such file"))
    return;
  no_file_test_t *test = (no_file_test_t*)user_data;
  test->have_file = file != NULL;
  test->log_count++;
}

/*!cmocka */
void the_file_that_wasnt(void **state)
{
  // test parsing of nonexistent file is handled gracefully
  zone_parser_t parser;
  zone_options_t options;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  no_file_test_t test;
  int32_t code;

  memset(&options, 0, sizeof(options));
  options.accept.callback = &no_such_file_accept;
  options.log.callback = &no_such_file_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  (void)state;

  char *non_file = temporary_name();
  assert_non_null(non_file);

  memset(&test, 0, sizeof(test));
  code = zone_parse(&parser, &options, &buffers, non_file, &test);
  free(non_file);
  assert_int_equal(code, ZONE_NOT_A_FILE);
  assert_false(test.have_file);
  assert_true(test.log_count == 1);
  assert_true(test.accept_count == 0);
}

/*!cmocka */
void the_include_that_wasnt(void **state)
{
  // test $INCLUDE of nonexistent file is handled gracefully
  zone_options_t options;
  no_file_test_t test;
  int32_t code;

  memset(&options, 0, sizeof(options));
  options.accept.callback = &no_such_file_accept;
  options.log.callback = &no_such_file_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;

  (void)state;

  char *non_include = temporary_name();
  assert_non_null(non_include);

  char buffer[16];
  int length = snprintf(buffer, sizeof(buffer), "$INCLUDE %s", non_include);
  assert_true(length >= 0 && (size_t)length < SIZE_MAX - (ZONE_BLOCK_SIZE + 1));

  char *include = malloc((size_t)length + 1);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE %s", non_include);

  memset(&test, 0, sizeof(test));
  code = parse(&options, include, &test);
  free(include);
  free(non_include);
  assert_int_equal(code, ZONE_NOT_A_FILE);
  assert_true(test.have_file);
  assert_true(test.log_count == 1);
  assert_true(test.accept_count == 0);
}

static int32_t in_too_deep_accept(
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
  (*(size_t *)user_data)++;
  return 0;
}

static void in_too_deep_log(
  zone_parser_t *parser,
  uint32_t priority,
  const char *file,
  size_t line,
  const char *message,
  void *user_data)
{
  (void)parser;
  (void)priority;
  (void)file;
  (void)line;

  if (strstr(message, "nested too deeply"))
    *(size_t *)user_data |= 1u << 7;
}

/*!cmocka */
void in_too_deep(void **state)
{
  (void)state;

  int32_t code;
  size_t records;
  zone_options_t options;

  memset(&options, 0, sizeof(options));
  options.accept.callback = &in_too_deep_accept;
  options.log.callback = &in_too_deep_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;
  options.include_limit = 1;

#define INCLUDE "$INCLUDE %s\n"

  char *deeper = generate_include("foo. TXT \"bar\"");
  assert_non_null(deeper);
  char buffer[16];
  int length = snprintf(buffer, sizeof(buffer), INCLUDE, deeper);
  assert_true(length > 0);
  char *inception = malloc((size_t)length + 1);
  assert_non_null(inception);
  (void)snprintf(inception, (size_t)length + 1, INCLUDE, deeper);
  char *deep = generate_include(inception);
  assert_non_null(deep);
  free(inception);
  length = snprintf(buffer, sizeof(buffer), INCLUDE, deep);
  assert_true(length > 0);
  inception = malloc((size_t)length + 1);
  (void)snprintf(inception, (size_t)length + 1, INCLUDE, deep);

#undef INCLUDE

  fprintf(stderr, "INPUT: %s\n", inception);

  records = 0;
  code = parse(&options, inception, &records);
  assert_int_equal(code, ZONE_SEMANTIC_ERROR);
  assert_int_equal(records, (1u << 7));

  options.include_limit = 0;
  records = 0;
  code = parse(&options, inception, &records);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_int_equal(records, 1u);

  remove_include(deep);
  remove_include(deeper);
  free(inception);
  free(deep);
  free(deeper);
}

/*!cmocka */
void been_there_done_that(void **state)
{
  (void)state;

  zone_options_t options;
  memset(&options, 0, sizeof(options));
  options.accept.callback = &in_too_deep_accept;
  options.log.callback = &in_too_deep_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;
  options.include_limit = 1;

  int32_t code;
  size_t count = 0;

  char *path = generate_include(" ");
  assert_non_null(path);
  FILE* handle = fopen(path, "wb");
  assert_non_null(handle);
  char dummy[16];
  int length = snprintf(dummy, sizeof(dummy), "$INCLUDE \"%s\"\n", path);
  assert_true(length > 0 && length < INT_MAX - ZONE_BLOCK_SIZE);
  char *include = malloc((size_t)length + 1 + ZONE_BLOCK_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE \"%s\"\n", path);
  int result = fputs(include, handle);
  assert_true(result >= 0);
  (void)fclose(handle);
  code = parse(&options, include, &count);

  remove_include(path);
  free(path);
  free(include);
  assert_int_equal(code, ZONE_SEMANTIC_ERROR);
}

//
// x. test $INCLUDE is denied for files if disabled all together
//

/*!cmocka */
void include_relative(void **state)
{
  (void)state;
  /* Test with a $INCLUDE from a subdirectory. Is it resolved relative
   * to the working directory, and not relative to the includer file. */

  zone_parser_t parser;
  zone_options_t options;
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };

  memset(&options, 0, sizeof(options));
  options.accept.callback = &no_such_file_accept;
  options.log.callback = &no_such_file_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = 1;
  options.include_limit = 1;

#if _WIN32
  int pid = _getpid();
#else
  pid_t pid = getpid();
#endif

  char* inc1file = "content.inc";
  char* inc2file = "example.com.zone";
  char dir1[128], dir2[128];
  snprintf(dir1, sizeof(dir1), "testdir.1.%d", (int)pid);
  snprintf(dir2, sizeof(dir2), "testdir.2.%d", (int)pid);

  if(
#if _WIN32
    _mkdir(dir1)
#else
    mkdir(dir1, 0755)
#endif
    != 0) {
#if _WIN32
    printf("mkdir %s failed\n", dir1);
#else
    printf("mkdir %s failed: %s\n", dir1, strerror(errno));
#endif
    fail();
  }
  if(
#if _WIN32
    _mkdir(dir2)
#else
    mkdir(dir2, 0755)
#endif
    != 0) {
#if _WIN32
    printf("mkdir %s failed\n", dir2);
#else
    printf("mkdir %s failed: %s\n", dir2, strerror(errno));
#endif
    fail();
  }

  char fname1[PATH_MAX], fname2[PATH_MAX];
  snprintf(fname1, sizeof(fname1), "%s/%s", dir1, inc1file);
  snprintf(fname2, sizeof(fname2), "%s/%s", dir2, inc2file);

  FILE* handle = fopen(fname1, "wb");
  assert_non_null(handle);
  int result = fputs(
"www A 1.2.3.4\n",
    handle);
  assert_true(result >= 0);
  (void)fclose(handle);

  FILE* handle2 = fopen(fname2, "wb");
  assert_non_null(handle2);
  char zonetext[1024+PATH_MAX];
  snprintf(zonetext, sizeof(zonetext),
"; perform relative include\n"
"example.com. IN SOA ns host 1 3600 300 7200 3600\n"
"$INCLUDE %s\n"
"mail A 1.2.3.5\n",
    fname1);
  result = fputs(zonetext, handle2);
  assert_true(result >= 0);
  (void)fclose(handle2);

  no_file_test_t test;
  memset(&test, 0, sizeof(test));
  int32_t code;
  code = zone_parse(&parser, &options, &buffers, fname2, &test);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_true(test.log_count == 0);
  assert_true(test.accept_count == 3);

  remove_include(fname1);
  remove_include(fname2);
#if _WIN32
  (void)_rmdir(dir1);
  (void)_rmdir(dir2);
#else
  (void)rmdir(dir1);
  (void)rmdir(dir2);
#endif
}
