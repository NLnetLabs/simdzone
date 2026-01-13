/*
 * fromcb.c -- test parse from read data callback.
 *
 * Copyright (c) 2026, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "zone.h"

/* max number of chunks used in the test */
#define MAX_CHUNKS 16
/* if test should print verbosely */
static int verb = 1;

/* The size of the chunk, if set to this value, makes it use strlen. */
#define CHUNK_SIZE_STRLEN -3
/* The size of the chunk, if set to this value, makes it use strlen, and
 * pad to the requested size. */
#define CHUNK_SIZE_STRLENPAD -4

/* Chunk of string to return for the test. */
struct fromcb_chunkinfo {
  /* The string with content for the chunk, can be smaller than max len. */
  char* str;
  /* the size of the chunk, or the defines for it. */
  int size;
  /* the end of the pad, if any. Put on the end of the chunk, if padded. */
  char* padend;
  /* the retvalue for the read of the chunk. 0 means success. */
  int32_t retvalue;
};

/* The test information for a parse from callback test. Inited to values on
 * start, and contains space for counters that are updated. */
struct fromcb_testinfo {
  /* expected return value of parse */
  int32_t code;
  /* list of chunks that is read, ends with NULL */
  struct fromcb_chunkinfo chunk[MAX_CHUNKS];
  /* current chunk. */
  size_t chunknum;
  /* number of RRs read. */
  size_t num_rrs;
  /* expected number of RRs read. */
  size_t expect_num_rrs;
};

static int32_t read_data_func(
  zone_parser_t * parser,
  char *data,
  size_t len,
  size_t *outlen,
  void *user_data)
{
  struct fromcb_testinfo *test = (void *)user_data;
  struct fromcb_chunkinfo* chunk;
  int32_t retvalue;
  int chunk_size = 0;
  (void)parser;
  chunk = &test->chunk[test->chunknum];
  if(chunk->str == NULL) {
	  *outlen = 0;
	  if(verb)
	    fprintf(stderr, "read_data_func(len=%d, outlen=%d) "
	      "chunk %d returns %d\n", (int)len, (int)*outlen,
	      (int)test->chunknum, 0);
	  return 0;
  }

  chunk_size = chunk->size;
  if(chunk_size == CHUNK_SIZE_STRLEN) {
    chunk_size = strlen(chunk->str);
    if(chunk_size != 0)
      memmove(data, chunk->str, chunk_size);
  } else if(chunk_size == CHUNK_SIZE_STRLENPAD) {
    size_t padendlen = 0;
    chunk_size = strlen(chunk->str);
    if(chunk_size != 0)
      memmove(data, chunk->str, chunk_size);
    /* Pad it */
    if(chunk->padend)
	    padendlen = strlen(chunk->padend);
    if((size_t)chunk_size + padendlen < len) {
      size_t i, padlen = len - (size_t)chunk_size - padendlen;
      char padchar = ' ';
      for(i=0; i<padlen; i++) {
	      data[chunk_size+i] = padchar;
      }
    }
    if(chunk->padend) {
      memmove(data+len-padendlen, chunk->padend, padendlen);
    }
    chunk_size = len;
  } else {
    if(chunk_size != 0)
      memmove(data, chunk->str, chunk_size);
  }

  *outlen = (size_t)chunk_size;
  retvalue = chunk->retvalue;
  test->chunknum++;
  if(verb)
    fprintf(stderr, "read_data_func(len=%d, outlen=%d) chunk %d returns %d\n",
      (int)len, (int)*outlen, (int)test->chunknum-1, (int)retvalue);
  return retvalue;
}

static int32_t accept_fromcb(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  struct fromcb_testinfo *test = (void *)user_data;
  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;

  test->num_rrs++;
  if(verb)
    fprintf(stderr, "accept rr %d / %d\n",
      (int)test->num_rrs, (int)test->expect_num_rrs);
  return 0;
}

/*!cmocka */
void test_fromcb(void **state)
{
  static uint8_t origin[] =
    { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

  static struct fromcb_testinfo tests[] = {
    /* fromcb test 0: two chunks */
    { 0, {
      {"www.example.com. IN A 1.2.3.4\n", CHUNK_SIZE_STRLENPAD, "\n", 0},
      {"www2.example.com. IN A 1.2.3.4\n", CHUNK_SIZE_STRLEN, NULL, 0},
      {NULL, 0, NULL, 0}
      },
      0, 0, 2 // num rrs
    }
  };

  (void)state;

  for (size_t i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    zone_parser_t parser;
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options;
    int32_t code;
    struct fromcb_testinfo *test = &tests[i];

    fprintf(stderr, "fromcb test %d\n", (int)i);

    memset(&options, 0, sizeof(options));
    options.accept.callback = accept_fromcb;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = 1;

    code = zone_parse_from_callback(&parser, &options, &buffers,
	read_data_func, (void*)test);
    if(verb)
      fprintf(stderr, "retcode %d, num_rrs %d\n", (int)code,
	(int)test->num_rrs);
    assert_int_equal(code, test->code);
    assert_int_equal(test->num_rrs, test->expect_num_rrs);
  }
}
