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

zone_nonnull_all
static zone_really_inline const char *scan_comment(
  zone_parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    if (zone_unlikely(*start == '\n'))
      return start;
    start += 1;
  }

  parser->file->state.in_comment = 1;
  return end;
}

zone_nonnull_all
static zone_really_inline const char *scan_quoted(
  zone_parser_t *parser, const char *start, const char *end)
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

zone_nonnull_all
static zone_really_inline const char *scan_contiguous(
  zone_parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    if (zone_likely(is_contiguous((uint8_t)*start))) {
      if (zone_likely(*start != '\\')) {
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

zone_nonnull_all
static zone_really_inline void scan(
  zone_parser_t *parser, const char *start, const char *end)
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
    const int32_t code = contiguous[(uint8_t)*start];
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

zone_nonnull_all
static zone_never_inline void step(zone_parser_t *parser, token_t *token)
{
  bool start_of_line = false;
  const char *data_limit, **tape_limit;

  // start of line is initially true
  if (parser->file->fields.tail == parser->file->fields.tape)
    start_of_line = true;
  else if (parser->file->fields.tail[-1][0] == '\n')
    start_of_line = !is_blank((uint8_t)parser->file->fields.tail[-1][1]);

  // restore deferred line count
  parser->file->lines.tape[0] = parser->file->lines.tail[0];
  parser->file->lines.head = parser->file->lines.tape;
  parser->file->lines.tail = parser->file->lines.tape;
  // restore (possibly) deferred field
  parser->file->fields.tape[0] = parser->file->fields.tail[1];
  parser->file->fields.head = parser->file->fields.tape;
  parser->file->fields.tail = parser->file->fields.tape;
  if (parser->file->fields.tape[0])
    parser->file->fields.tail++;
  // delimiters are never deferred
  parser->file->delimiters.head = parser->file->delimiters.tape;
  parser->file->delimiters.tail = parser->file->delimiters.tape;

shuffle:
  // refill if required
  if (parser->file->end_of_file == ZONE_HAVE_DATA) {
    int32_t code;
    const char *data;
    if (parser->file->fields.head[0])
      data = parser->file->fields.head[0];
    else
      data = parser->file->buffer.data + parser->file->buffer.index;
    parser->file->fields.head[0] = parser->file->buffer.data;
    const size_t length =
      (size_t)((parser->file->buffer.data+parser->file->buffer.length) - data);
    const size_t index =
      (size_t)((parser->file->buffer.data+parser->file->buffer.index) - data);
    memmove(parser->file->buffer.data, data, length);
    parser->file->buffer.length = length;
    parser->file->buffer.index = index;
    parser->file->buffer.data[length] = '\0';
    if ((code = refill(parser)) < 0)
      DEFER_ERROR(parser, token, code);
  }

  data_limit = parser->file->buffer.data + parser->file->buffer.length;
  tape_limit = parser->file->fields.tape + ZONE_TAPE_SIZE;
  for (;;) {
    const char *data = parser->file->buffer.data + parser->file->buffer.index;
    if (data_limit - data < ZONE_BLOCK_SIZE)
      break;
    if (tape_limit - parser->file->fields.tail < ZONE_BLOCK_SIZE)
      goto terminate;
    scan(parser, data, data + ZONE_BLOCK_SIZE);
    parser->file->buffer.index += ZONE_BLOCK_SIZE;
  }

  const size_t length = parser->file->buffer.length - parser->file->buffer.index;
  assert(length <= ZONE_BLOCK_SIZE);
  if (parser->file->end_of_file == ZONE_HAVE_DATA)
    goto terminate;
  if (length > (size_t)(tape_limit - parser->file->fields.tail))
    goto terminate;

  const char *data = &parser->file->buffer.data[parser->file->buffer.index];
  scan(parser, data, data + length);
  parser->file->buffer.index += length;
  parser->file->end_of_file = ZONE_NO_MORE_DATA;

terminate:
  // make sure tape contains no partial tokens
  if (parser->file->end_of_file == ZONE_NO_MORE_DATA) {
    parser->file->fields.tail[1] = NULL;
  } else if (parser->file->state.follows_contiguous || parser->file->state.in_quoted) {
    parser->file->fields.tail[0] = parser->file->fields.tail[-1];
    parser->file->fields.tail--;
  } else {
    parser->file->fields.tail[1] = NULL;
  }

  parser->file->fields.tail[0] = data_limit;
  parser->file->delimiters.tail[0] = data_limit;
  if (parser->file->fields.head[0] == parser->file->buffer.data)
    parser->file->start_of_line = start_of_line;
  else
    parser->file->start_of_line = false;

  for (;;) {
    data = *parser->file->fields.head;
    token->data = data;
    token->code = (int32_t)contiguous[ (uint8_t)*data ];
    // end-of-file is idempotent
    parser->file->fields.head += (*data != '\0');
    if (zone_likely(token->code == CONTIGUOUS)) {
      const char *delimiter = *parser->file->delimiters.head++;
      assert(delimiter > token->data);
      token->length = (size_t)(delimiter - token->data);
      return;
    } else if (token->code == LINE_FEED) {
      if (zone_unlikely(token->data == line_feed))
        parser->file->span += *parser->file->lines.head++;
      parser->file->span++;
      if (parser->file->grouped)
        continue;
      parser->file->line += parser->file->span;
      parser->file->span = 0;
      parser->file->start_of_line = !is_blank((uint8_t)*(token->data+1));
      return;
    } else if (token->code == QUOTED) {
      const char *delimiter = *parser->file->delimiters.head++;
      token->data++;
      assert(delimiter > token->data);
      token->length = (size_t)(delimiter - token->data);
      return;
    } else if (token->code == END_OF_FILE) {
      zone_file_t *file;

      if (parser->file->end_of_file != ZONE_NO_MORE_DATA)
        goto shuffle;
      if (parser->file->grouped)
        DEFER_SYNTAX_ERROR(parser, token, "Missing closing brace");
      if (!parser->file->includer)
        return;
      file = parser->file;
      parser->file = parser->file->includer;
      parser->owner = &parser->file->owner;
      zone_close_file(parser, file);
      return;
    } else if (token->code == LEFT_PAREN) {
      if (parser->file->grouped)
        DEFER_SYNTAX_ERROR(parser, token, "Nested opening brace");
      parser->file->grouped = true;
    } else {
      assert(token->code == RIGHT_PAREN);
      if (!parser->file->grouped)
        DEFER_SYNTAX_ERROR(parser, token, "Missing opening brace");
      parser->file->grouped = false;
    }
  }
}

#endif // SCANNER_H
