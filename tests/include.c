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
  teardown((void **)&input);
  return -1;
}

diagnostic_pop()

static zone_return_t add_rr(
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

/*!cmocka setup:setup teardown:teardown */
void include_from_string(void **state)
{
  input_t *input;
  zone_parser_t parser = { 0 };
  zone_name_block_t name;
  zone_rdata_block_t rdata;
  zone_cache_t cache = { 1, &name, &rdata };
  zone_options_t options = { 0 };
  zone_return_t result;

  options.accept.add = &add_rr;
  options.origin = "example.com.";
  options.default_ttl = 3600;
  options.default_class = ZONE_IN;

  input = (input_t *)*state;

  // verify $INCLUDE is denied by default when parsing strings.
  const char *str = input->includer.content;
  result = zone_parse_string(&parser, &options, &cache, str, strlen(str), NULL);
  assert_false(options.no_includes);
  assert_int_equal(result, ZONE_SUCCESS);

  // verify $INCLUDE is allowed and works as intented if configured.
  options.no_includes = true;
  result = zone_parse_string(&parser, &options, &cache, str, strlen(str), NULL);
  assert_int_equal(result, ZONE_NOT_PERMITTED);
}

//
// x. test $INCLUDE of nonexistent file is handled gracefully
// x. test $INCLUDE is denied for files if disabled all together
//

