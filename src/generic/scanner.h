/*
 * scanner.h -- fast lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "zone.h"
#include "log.h"

// Copied from simdjson under the terms of The 3-Clause BSD License.
// Copyright (c) 2018-2023 The simdjson authors
static inline uint64_t find_escaped(
  uint64_t backslash, uint64_t *is_escaped)
{
  backslash &= ~ *is_escaped;

  uint64_t follows_escape = backslash << 1 | *is_escaped;

  // Get sequences starting on even bits by clearing out the odd series using +
  const uint64_t even_bits = 0x5555555555555555ULL;
  uint64_t odd_sequence_starts = backslash & ~even_bits & ~follows_escape;
  uint64_t sequences_starting_on_even_bits;
  *is_escaped = add_overflow(odd_sequence_starts, backslash, &sequences_starting_on_even_bits);
  uint64_t invert_mask = sequences_starting_on_even_bits << 1; // The mask we want to return is the *escaped* bits, not escapes.

  // Mask every other backslashed character as an escaped character
  // Flip the mask for sequences that start on even bits, to correct them
  return (even_bits ^ invert_mask) & follows_escape;
}

// special characters in zone files cannot be identified without branching
// (unlike json) due to comments (*). no algorithm was found (so far) that
// can correctly identify quoted and comment regions where a quoted region
// includes a semicolon (or newline for that matter) and/or a comment region
// includes one (or more) quote characters. also, for comments, only newlines
// directly following a non-escaped, non-quoted semicolon must be included
static inline void find_delimiters(
  uint64_t quotes,
  uint64_t semicolons,
  uint64_t newlines,
  uint64_t in_quoted,
  uint64_t in_comment,
  uint64_t *quoted_,
  uint64_t *comment)
{
  uint64_t delimiters, starts = quotes | semicolons;
  uint64_t end;

  assert(!(quotes & semicolons));

  // carry over state from previous block
  end = (newlines & in_comment) | (quotes & in_quoted);
  end &= -end;

  delimiters = end;
  starts &= ~((in_comment | in_quoted) ^ (-end - end));

  while (starts) {
    const uint64_t start = -starts & starts;
    assert(start);
    const uint64_t quote = quotes & start;
    const uint64_t semicolon = semicolons & start;

    // FIXME: technically, this introduces a data dependency
    end = (newlines & -semicolon) | (quotes & (-quote - quote));
    end &= -end;

    delimiters |= end | start;
    starts &= -end - end;
  }

  *quoted_ = delimiters & quotes;
  *comment = delimiters & ~quotes;
}

static inline uint64_t follows(const uint64_t match, uint64_t *overflow)
{
  const uint64_t result = match << 1 | (*overflow);
  *overflow = match >> 63;
  return result;
}

static const simd_table_t blank = SIMD_TABLE(
  0x20, // 0x00 :  " " : 0x20 -- space
  0x00, // 0x01
  0x00, // 0x02
  0x00, // 0x03
  0x00, // 0x04
  0x00, // 0x05
  0x00, // 0x06
  0x00, // 0x07
  0x00, // 0x08
  0x09, // 0x09 : "\t" : 0x09 -- tab
  0x00, // 0x0a
  0x00, // 0x0b
  0x00, // 0x0c
  0x0d, // 0x0d : "\r" : 0x0d -- carriage return
  0x00, // 0x0e
  0x00  // 0x0f
);

static const simd_table_t special = SIMD_TABLE(
  0x00, // 0x00 : "\0" : 0x00 -- end-of-file
  0x00, // 0x01
  0x00, // 0x02
  0x00, // 0x03
  0x00, // 0x04
  0x00, // 0x05
  0x00, // 0x06
  0x00, // 0x07
  0x28, // 0x08 :  "(" : 0x28 -- start grouped
  0x29, // 0x09 :  ")" : 0x29 -- end grouped
  0x0a, // 0x0a : "\n" : 0x0a -- end-of-line
  0x00, // 0x0b
  0x00, // 0x0c
  0x00, // 0x0d
  0x00, // 0x0e
  0x00  // 0x0f
);

typedef struct block block_t;
struct block {
  simd_8x64_t input;
  uint64_t newline;
  uint64_t backslash;
  uint64_t escaped;
  uint64_t comment;
  uint64_t quoted;
  uint64_t semicolon;
  uint64_t in_quoted;
  uint64_t in_comment;
  uint64_t contiguous;
  uint64_t follows_contiguous;
  uint64_t blank;
  uint64_t special;
};

static zone_really_inline void scan(zone_parser_t *parser, block_t *block)
{
  // escaped newlines are classified as contiguous. however, escape sequences
  // have no meaning in comments and newlines, escaped or not, have no
  // special meaning in quoted
  block->newline = simd_find_8x64(&block->input, '\n');
  block->backslash = simd_find_8x64(&block->input, '\\');
  block->escaped = find_escaped(
    block->backslash, &parser->file->state.is_escaped);

  block->comment = 0;
  block->quoted = simd_find_8x64(&block->input, '"') & ~block->escaped;
  block->semicolon = simd_find_8x64(&block->input, ';') & ~block->escaped;

  block->in_quoted = parser->file->state.in_quoted;
  block->in_comment = parser->file->state.in_comment;

  if (block->in_comment || block->semicolon) {
    find_delimiters(
      block->quoted,
      block->semicolon,
      block->newline,
      block->in_quoted,
      block->in_comment,
     &block->quoted,
     &block->comment);

    block->in_quoted ^= prefix_xor(block->quoted);
    parser->file->state.in_quoted = (uint64_t)((int64_t)block->in_quoted >> 63);
    block->in_comment ^= prefix_xor(block->comment);
    parser->file->state.in_comment = (uint64_t)((int64_t)block->in_comment >> 63);
  } else {
    block->in_quoted ^= prefix_xor(block->quoted);
    parser->file->state.in_quoted = (uint64_t)((int64_t)block->in_quoted >> 63);
  }

  block->blank =
    simd_find_any_8x64(&block->input, blank) & ~(block->escaped | block->in_quoted | block->in_comment);
  block->special =
    simd_find_any_8x64(&block->input, special) & ~(block->escaped | block->in_quoted | block->in_comment);

  block->contiguous =
    ~(block->blank | block->special | block->quoted) & ~(block->in_quoted | block->in_comment);
  block->follows_contiguous =
    follows(block->contiguous, &parser->file->state.follows_contiguous);
}

static zone_really_inline void tokenize(zone_parser_t *parser, const block_t *block, uint64_t clear)
{
  uint64_t fields = (block->contiguous & ~block->follows_contiguous) |
                    (block->quoted & block->in_quoted) |
                    (block->special);

  // delimiters are only important for contigouos and quoted character strings
  // (all other tokens automatically have a length 1). write out both in
  // separate vectors and base logic solely on field vector, order is
  // automatically correct
  uint64_t delimiters = (~block->contiguous & block->follows_contiguous) |
                        (block->quoted & ~block->in_quoted);

  fields &= ~clear;
  delimiters &= ~clear;

  const char *base = parser->file->buffer.data + parser->file->buffer.index;
  uint64_t field_count = count_ones(fields);
  uint64_t delimiter_count = count_ones(delimiters);
  // bulk of the data are contiguous and quoted character strings. field and
  // delimiter counts are therefore (mostly) equal. select the greater number
  // and write out indexes using a single loop, (hopefully) leveraging
  // superscalar properties of modern CPUs
  uint64_t count = field_count;
  if (delimiter_count > field_count)
    count = delimiter_count;

  uint64_t newline = block->newline;
  const uint64_t in_string = block->contiguous | block->in_quoted;

  // take slow path if (escaped) newlines appear in contiguous or quoted
  // character strings. edge case, but must be supported and handled in the
  // scanner for ease of use and to accommodate for parallel processing in the
  // parser. escaped newlines may have been present in the last block
  if (zone_unlikely(parser->file->lines.tail[0] || (newline & in_string))) {
    // FIXME: test logic properly, likely eligable for simplification
    for (count=0; count < field_count; count++) {
      const uint64_t field = -fields & fields;
      if (field & newline) {
        parser->file->lines.tail++;
        parser->file->fields.tail[count] = line_feed;
        newline &= -field;
      } else {
        // count newlines here so number of newlines remains correct if last
        // token is start of contiguous or quoted and index must be reset
        *parser->file->lines.tail += count_ones(newline & ~(-field));
        parser->file->fields.tail[count] = base + trailing_zeroes(field);
        newline &= -field;
      }
      parser->file->delimiters.tail[count] = base + trailing_zeroes(delimiters);
      fields = clear_lowest_bit(fields);
      delimiters = clear_lowest_bit(delimiters);
    }

    for (; count < delimiter_count; count++) {
      parser->file->delimiters.tail[count] = base + trailing_zeroes(delimiters);
      delimiters = clear_lowest_bit(delimiters);
    }

    parser->file->fields.tail += field_count;
    parser->file->delimiters.tail += delimiter_count;
  } else {
    for (uint64_t i=0; i < 6; i++) {
      parser->file->fields.tail[i] = base + trailing_zeroes(fields);
      parser->file->delimiters.tail[i] = base + trailing_zeroes(delimiters);
      fields = clear_lowest_bit(fields);
      delimiters = clear_lowest_bit(delimiters);
    }

    if (zone_unlikely(count > 6)) {
      for (uint64_t i=6; i < 12; i++) {
        parser->file->fields.tail[i] = base + trailing_zeroes(fields);
        parser->file->delimiters.tail[i] = base + trailing_zeroes(delimiters);
        fields = clear_lowest_bit(fields);
        delimiters = clear_lowest_bit(delimiters);
      }

      if (zone_unlikely(count > 12)) {
        for (uint64_t i=12; i < count; i++) {
          parser->file->fields.tail[i] = base + trailing_zeroes(fields);
          parser->file->delimiters.tail[i] = base + trailing_zeroes(delimiters);
          fields = clear_lowest_bit(fields);
          delimiters = clear_lowest_bit(delimiters);
        }
      }
    }

    parser->file->fields.tail += field_count;
    parser->file->delimiters.tail += delimiter_count;
  }
}

zone_nonnull_all
static zone_never_inline void step(zone_parser_t *parser, token_t *token)
{
  block_t block = { 0 };
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
  if (parser->file->end_of_file == ZONE_HAVE_DATA) {
    int32_t code;
    const char *start;
    if (parser->file->fields.head[0])
      start = parser->file->fields.head[0];
    else
      start = parser->file->buffer.data + parser->file->buffer.index;
    parser->file->fields.head[0] = parser->file->buffer.data;
    const size_t length =
      (size_t)((parser->file->buffer.data+parser->file->buffer.length) - start);
    const size_t index =
      (size_t)((parser->file->buffer.data+parser->file->buffer.index) - start);
    memmove(parser->file->buffer.data, start, length);
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
    simd_loadu_8x64(&block.input, (const uint8_t *)data);
    scan(parser, &block);
    tokenize(parser, &block, 0);
    parser->file->buffer.index += ZONE_BLOCK_SIZE;
  }

  const size_t length = parser->file->buffer.length - parser->file->buffer.index;
  assert(length <= ZONE_BLOCK_SIZE);
  if (parser->file->end_of_file == ZONE_HAVE_DATA)
    goto terminate;
  if (length > (size_t)(tape_limit - parser->file->fields.tail))
    goto terminate;

  uint8_t buffer[ZONE_BLOCK_SIZE] = { 0 };
  memcpy(buffer, &parser->file->buffer.data[parser->file->buffer.index], length);
  const uint64_t clear = ~((1llu << length) - 1);
  simd_loadu_8x64(&block.input, buffer);
  scan(parser, &block);
  //block.starts &= ~clear;
  block.contiguous &= ~clear;
  tokenize(parser, &block, clear);
  parser->file->buffer.index += length;
  parser->file->end_of_file = ZONE_NO_MORE_DATA;

terminate:
  // make sure tape contains no partial tokens
  if ((uint64_t)((int64_t)(block.contiguous | block.in_quoted) >> 63)) {
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
    const char *data = parser->file->fields.head[0];
    token->data = data;
    token->code = (int32_t)contiguous[ (uint8_t)*data ];
    // end-of-file is idempotent
    parser->file->fields.head += (*token->data != '\0');
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
      token->length = 1;
      return;
    } else if (token->code == QUOTED) {
      const char *delimiter = *parser->file->delimiters.head++;
      token->data++;
      assert(delimiter >= token->data);
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
      token->length = 1;
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
