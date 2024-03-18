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
#if !_WIN32
#include <unistd.h>
#endif

#include "zone.h"
#include "diagnostic.h"

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
  zone_parser_t parser = { 0 };
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options = { 0 };
  int32_t result;

  options.accept.callback = &add_rr;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = ZONE_IN;

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
  uint32_t category,
  const char *message,
  void *user_data)
{
  (void)parser;
  (void)category;
  if (!strstr(message, "no such file"))
    return;
  no_file_test_t *test = (no_file_test_t*)user_data;
  test->log_count++;
}

/*!cmocka */
void the_include_that_wasnt(void **state)
{
  // test $INCLUDE of nonexistent file is handled gracefully
  zone_parser_t parser = { 0 };
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &name, &rdata };
  zone_options_t options = { 0 };
  no_file_test_t test = { 0 };
  int32_t code;

  options.accept.callback = &no_such_file_accept;
  options.log.callback = &no_such_file_log;
  options.origin.octets = origin;
  options.origin.length = sizeof(origin);
  options.default_ttl = 3600;
  options.default_class = ZONE_IN;

  (void)state;

  char *non_include = tempnam(NULL, "zone");
  assert_non_null(non_include);

  char buffer[16];
  int length = snprintf(buffer, sizeof(buffer), "$INCLUDE %s", non_include);
  assert_true(length >= 0 && (size_t)length < SIZE_MAX - (ZONE_PADDING_SIZE + 1));

  char *include = malloc((size_t)length + 1 + ZONE_PADDING_SIZE);
  assert_non_null(include);
  (void)snprintf(include, (size_t)length + 1, "$INCLUDE %s", non_include);

  code = zone_parse_string(&parser, &options, &buffers, include, (size_t)length, &test);
  assert_int_equal(code, ZONE_NOT_A_FILE);
  assert_true(test.log_count == 1);
  assert_true(test.accept_count == 0);
  free(include);
  free(non_include);
}

//
// x. test $INCLUDE is denied for files if disabled all together
//

