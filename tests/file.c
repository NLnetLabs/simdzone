/*
 * file.c -- file input tests
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include "parser.h"

#define BLOCK_SIZE (64)

/*!cmocka */
int touch_zone_file(void **state)
{
  int fd;
  char *tmp;
  const int mode = O_CREAT | O_EXCL | O_WRONLY | S_IRUSR | S_IWUSR;

  for (size_t i=0; i < 64; i++) {
    if (!(tmp = tempnam(NULL, "zone")))
      goto err_tempnam;
    if ((fd = open(tmp, mode)) != -1)
      break;
    free(tmp);
  }

  static const char rr[] = "example.com. 1 IN TXT ";

  if (write(fd, rr, sizeof(rr) - 1) == -1)
    goto err_write;

  for (size_t i=0, n=(BLOCK_SIZE*2)-1; i < n; i++) {
    if (write(fd, "x", 1) == -1)
      goto err_write;
  }

  close(fd);
  *state = tmp;
  return 0;
err_write:
  close(fd);
  unlink(tmp);
  free(tmp);
err_tempnam:
  return -1;
}

/*!cmocka */
int delete_zone_file(void **state)
{
  char *tmp = *state;

  if (!tmp)
    return 0;
  unlink(tmp);
  free(tmp);
  return 0;
}

struct counters {
  size_t block;
  size_t alloc_calls;
  size_t free_calls;
  size_t alloc_total;
  size_t rr_total;
  size_t rdata_total;
};

static void *mymalloc(void *arena, size_t size)
{
  struct counters *counters = arena;

  if (size % BLOCK_SIZE == 0)
    counters->block++;
  counters->alloc_calls++;
  counters->alloc_total += size;

  return malloc(size);
}

static void *myrealloc(void *arena, void *ptr, size_t size)
{
  struct counters *counters = arena;

  if (size % BLOCK_SIZE == 0)
    counters->block++;
  counters->alloc_calls++;
  counters->free_calls += (ptr != NULL);
  counters->alloc_total += size;

  return realloc(ptr, size);
}

static void myfree(void *arena, void *ptr)
{
  struct counters *counters = arena;

  counters->free_calls++;
  free(ptr);
}

static zone_return_t myaccept_rr(
  const zone_parser_t *parser,
  zone_field_t *owner,
  zone_field_t *ttl,
  zone_field_t *class,
  zone_field_t *type,
  void *user_data)
{
  struct counters *counters = user_data;

  (void)parser;
  (void)ttl;
  (void)class;
  (void)type;

  counters->rr_total += owner->name.length;
  myfree(counters, owner->name.octets);
  return 0;
}

static zone_return_t myaccept_rdata(
  const zone_parser_t *parser,
  zone_field_t *rdata,
  void *user_data)
{
  struct counters *counters = user_data;

  (void)parser;

  if (rdata->code == ZONE_STRING &&
      !(rdata->descriptor.rdata->qualifiers & ZONE_UNBOUNDED))
    counters->rdata_total += *rdata->string;
  myfree(counters, rdata->string);
  return 0;
}

static zone_return_t myaccept_delimiter(
  const zone_parser_t *parser,
  zone_field_t *delimiter,
  void *user_data)
{
  (void)parser;
  (void)delimiter;
  (void)user_data;
  return 0;
}

/*!cmocka setup:touch_zone_file teardown:delete_zone_file */
void buffer_refill(void **state)
{
  char *tmp = *state;

  assert_non_null(tmp);

  zone_return_t ret;
  zone_parser_t par = { 0 };
  zone_options_t opts = { 0 };
  struct counters counters = { 0 };

  opts.allocator.malloc = mymalloc;
  opts.allocator.realloc = myrealloc;
  opts.allocator.free = myfree;
  opts.allocator.arena = &counters;
  opts.accept.rr = myaccept_rr;
  opts.accept.rdata = myaccept_rdata;
  opts.accept.delimiter = myaccept_delimiter;
  opts.block_size = BLOCK_SIZE;

  ret = zone_open(&par, &opts, tmp);
  assert_int_equal(ret, 0);
  ret = zone_parse(&par, &counters);
  assert_int_equal(ret, 0);
  zone_close(&par);

  assert_int_equal(counters.block, 4);
  assert_int_equal(counters.alloc_calls, counters.free_calls);
}
