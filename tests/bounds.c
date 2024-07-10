/*
 * bounds.c -- test for correct indexer operation on boundaries
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
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

// indexer(s) scans in 64-byte chunks, use white space for positioning

// terminate contiguous on last byte of block
const char contiguous_end_last[] =
  "foo. TXT                                                    bar\nfoo. TXT baz";

// terminate contiguous on first byte of next block
const char contiguous_end_first[] =
  "foo. TXT                                                     bar\nfoo. TXT baz";

// terminate quoted on last byte of the block
const char quoted_end_last[] =
  "foo. TXT                                                   \"bar\"\nfoo. TXT baz";

// terminate quoted on first byte of next block
const char quoted_end_first[] =
  "foo. TXT                                                    \"bar\"\nfoo. TXT baz";

// terminate comment on last byte of block
const char comment_end_last[] =
  "foo. TXT bar                                          ; comment\nfoo. TXT baz";

// terminate comment on first byte of next block
const char comment_end_first[] =
  "foo. TXT bar                                           ; comment\nfoo. TXT baz";

// start contiguous on last byte of block
const char contiguous_start_last[] =
  "foo. TXT                                                       bar"
  "\nfoo. TXT baz";

// start quoted on last byte of block
const char quoted_start_last[] =
  "foo. TXT                                                       \""
  "bar\"\nfoo. TXT baz";

// start quoted on last byte of block, end on first byte of next block
const char quoted_start_last_end_first[] =
  "foo. TXT                                                       \""
  "\"\nfoo. TXT baz";

// start quoted on last byte of block, end of first byte of next next block
const char quoted_start_last_end_next_first[] =
  "foo. TXT                                                       \""
  "bar                                                              "
  "\"\nfoo. TXT baz";

// start comment on last byte of block
const char comment_start_last[] =
  "foo. TXT                                                    bar;"
  " foobar\nfoo. TXT baz";

// start comment on last byte of block, end on first byte of next block
const char comment_start_last_end_first[] =
  "foo. TXT                                                    bar;"
  "\nfoo. TXT baz";

// start comment on last byte of block, end on first byte of next next block
const char comment_start_last_end_next_first[] =
  "foo. TXT                                                    bar;"
  "                                                                "
  "\nfoo. TXT baz";

// FIXME: the above can be testen on buffer boundaries too
// FIXME: add a maximum buffer size test
// FIXME: test buffer is not resized when processing a comment

static int32_t accept_bar_baz(
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
  (void)class;
  (void)ttl;

  static const uint8_t foo[5] = { 3, 'f', 'o', 'o', 0 };

  if (owner->length != 5 || memcmp(owner->octets, foo, 5) != 0)
    return ZONE_SYNTAX_ERROR;
  if (type != ZONE_TYPE_TXT)
    return ZONE_SYNTAX_ERROR;

  if (rdlength == 1 && rdata[0] == 0) {
    *((size_t *)user_data) += 1;
    return 0;
  } else if (rdlength > 3 && rdata[0] >= 3) {
    switch (*((size_t *)user_data)) {
      case 0: // expect bar
        if (memcmp(rdata+1, "bar", 3) != 0)
          return ZONE_SYNTAX_ERROR;
        break;
      case 1: // expect baz
        if (memcmp(rdata+1, "baz", 3) != 0)
          return ZONE_SYNTAX_ERROR;
        break;
      default:
        return ZONE_SYNTAX_ERROR;
    }

    *((size_t *)user_data) += 1;
    return 0;
  }

  return ZONE_SYNTAX_ERROR;
}

/*!cmocka */
void block_boundary(void **state)
{
  (void)state;

  static const uint8_t root[1] = { 0 };
  static const struct {
    const char *input; size_t length;
  } tests[] = {
    { contiguous_end_last, sizeof(contiguous_end_last) },
    { contiguous_end_first, sizeof(contiguous_end_first) },
    { quoted_end_last, sizeof(quoted_end_last) },
    { quoted_end_first, sizeof(quoted_end_first) },
    { comment_end_last, sizeof(comment_end_last) },
    { comment_end_first, sizeof(comment_end_first) },
    { contiguous_start_last, sizeof(contiguous_start_last) },
    { quoted_start_last, sizeof(quoted_start_last) },
    { quoted_start_last_end_first, sizeof(quoted_start_last_end_first) },
    { quoted_start_last_end_next_first, sizeof(quoted_start_last_end_next_first) },
    { comment_start_last, sizeof(comment_start_last) },
    { comment_start_last_end_first, sizeof(comment_start_last_end_first) },
    { comment_start_last_end_next_first, sizeof(comment_start_last_end_next_first) }
  };

  zone_parser_t parser;
  zone_options_t options;
  zone_name_buffer_t owner;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &owner, &rdata };

  for (int i=0, n=sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    // allocate memory instead of using a static buffer for asan
    char *input = malloc(tests[i].length + 64);
    assert_non_null(input);
    memcpy(input, tests[i].input, tests[i].length);
    memset(&parser, 0, sizeof(parser));
    memset(&options, 0, sizeof(options));
    options.origin.octets = root;
    options.origin.length = 1;
    options.accept.callback = &accept_bar_baz;
    options.default_ttl = 3600;
    options.default_class = 1;

    fprintf(stderr, "INPUT:\n%s\n", input);

    size_t count = 0;
    int32_t code = zone_parse_string(
      &parser, &options, &buffers, input, tests[i].length - 1, &count);
    assert_int_equal(code, ZONE_SUCCESS);
    assert_int_equal(count, 2);
    free(input);
  }
}

static int32_t count_openpgp(
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
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  if (type == ZONE_TYPE_OPENPGPKEY)
    *((size_t *)user_data) += 1;
  return 0;
}

extern unsigned char xbounds_zone[];
extern unsigned int xbounds_zone_len;

/*!cmocka */
void contiguous_on_buffer_boundary(void **state)
{
  // test if buffer is properly resized if token crosses boundary

  (void)state;

  static const uint8_t root[1] = { 0 };

  zone_parser_t parser;
  memset(&parser, 0, sizeof(parser));
  zone_options_t options;
  memset(&options, 0, sizeof(options));
  options.origin.octets = root;
  options.origin.length = 1;
  options.accept.callback = &count_openpgp;
  options.default_ttl = 3600;
  options.default_class = 1;

  zone_name_buffer_t owner;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = { 1, &owner, &rdata };

  // generate zone file to parse
  char *path = tempnam(NULL, "xbounds");
  assert_non_null(path);
  FILE *handle = fopen(path, "wb");
  assert_non_null(handle);
  size_t written = fwrite(xbounds_zone, 1, xbounds_zone_len, handle);
  assert_int_equal((int)written, xbounds_zone_len);
  (void)fclose(handle);
  size_t count = 0;
  int32_t code = zone_parse(&parser, &options, &buffers, path, &count);
  assert_int_equal(code, ZONE_SUCCESS);
  assert_int_equal(count, 3);
  free(path);
}
