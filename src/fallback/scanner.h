/*
 * scanner.h -- fallback (non-simd) lexical analyzer for (DNS) zone data
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>
#include <stdint.h>
#include <string.h>

nonnull_all
static really_inline const char *scan_comment(
  parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    if (unlikely(*start == '\n'))
      return start;
    start += 1;
  }

  parser->file->state.in_comment = 1;
  return end;
}

nonnull_all
static really_inline const char *scan_quoted(
  parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    if (*start == '\\') {
      parser->file->lines.tail[0] += *(start + 1) == '\n';
      start += 2;
    } else if (*start == '\"') {
      *parser->file->delimiters.tail++ = start;
      return start + 1;
    } else if (*start == '\n') {
      parser->file->lines.tail[0]++;
      start += 1;
    } else {
      start += 1;
    }
  }

  parser->file->lines.tail[0] -= *end == '\n';
  parser->file->state.in_quoted = 1;
  parser->file->state.is_escaped = (start > end);
  return end;
}

nonnull_all
static really_inline const char *scan_contiguous(
  parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    if (likely(classify[ (uint8_t)*start ] == CONTIGUOUS)) {
      if (likely(*start != '\\')) {
        start += 1;
      } else {
        parser->file->lines.tail[0] += *(start + 1) == '\n';
        start += 2;
      }
    } else {
      *parser->file->delimiters.tail++ = start;
      return start;
    }
  }

  parser->file->lines.tail[0] -= *end == '\n';
  parser->file->state.is_escaped = (start > end);
  parser->file->state.follows_contiguous = 1;
  return end;
}

nonnull_all
static really_inline void scan(
  parser_t *parser, const char *start, const char *end)
{
  if (parser->file->state.is_escaped) {
    parser->file->state.is_escaped = 0;
    parser->file->lines.tail[0] += (*start++ == '\n');
  }

  if (parser->file->state.follows_contiguous) {
    parser->file->state.follows_contiguous = 0;
    start = scan_contiguous(parser, start, end);
  } if (parser->file->state.in_comment) {
    parser->file->state.in_comment = 0;
    start = scan_comment(parser, start, end);
  } else if (parser->file->state.in_quoted) {
    parser->file->state.in_quoted = 0;
    start = scan_quoted(parser, start, end);
  }

  while (start < end) {
    const int32_t code = classify[(uint8_t)*start];
    if (code == BLANK) {
      start++;
    } else if (code == CONTIGUOUS) {
      *parser->file->fields.tail++ = start;
      start = scan_contiguous(parser, start, end);
    } else if (code == LINE_FEED) {
      if (parser->file->lines.tail[0])
        *parser->file->fields.tail++ = line_feed;
      else
        *parser->file->fields.tail++ = start;
      start++;
    } else if (code == QUOTED) {
      *parser->file->fields.tail++ = start;
      start = scan_quoted(parser, start+1, end);
    } else if (code == LEFT_PAREN) {
      *parser->file->fields.tail++ = start;
      start++;
    } else if (code == RIGHT_PAREN) {
      *parser->file->fields.tail++ = start;
      start++;
    } else {
      assert(code == COMMENT);
      start = scan_comment(parser, start, end);
    }
  }
}

nonnull_all
warn_unused_result
static really_inline int32_t reindex(parser_t *parser)
{
  assert(parser->file->buffer.index <= parser->file->buffer.length);
  size_t left = parser->file->buffer.length - parser->file->buffer.index;
  const char *data = parser->file->buffer.data + parser->file->buffer.index;
  const char **tape = parser->file->fields.tail;
  const char **tape_limit = parser->file->fields.tape + ZONE_TAPE_SIZE;

  if (left >= ZONE_BLOCK_SIZE) {
    const char *data_limit = parser->file->buffer.data +
                            (parser->file->buffer.length - ZONE_BLOCK_SIZE);
    while (data <= data_limit && ((uintptr_t)tape_limit - (uintptr_t)tape) >= ZONE_BLOCK_SIZE) {
      scan(parser, data, data + ZONE_BLOCK_SIZE);
      parser->file->buffer.index += ZONE_BLOCK_SIZE;
      data += ZONE_BLOCK_SIZE;
      tape = parser->file->fields.tail;
    }

    assert(parser->file->buffer.index <= parser->file->buffer.length);
    left = parser->file->buffer.length - parser->file->buffer.index;
  }

  // only scan partial blocks after reading all data
  if (parser->file->end_of_file) {
    assert(left < ZONE_BLOCK_SIZE);
    if (!left) {
      parser->file->end_of_file = ZONE_NO_MORE_DATA;
    } else if (((uintptr_t)tape_limit - (uintptr_t)tape) >= left) {
      scan(parser, data, data + left);
      parser->file->end_of_file = ZONE_NO_MORE_DATA;
      parser->file->buffer.index += left;
      parser->file->state.follows_contiguous = 0;
    }
  }

  return (parser->file->state.follows_contiguous | parser->file->state.in_quoted) != 0;
}

#endif // SCANNER_H
