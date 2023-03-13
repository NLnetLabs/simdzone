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
#include "generic/error.h"

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
  uint64_t *quoted,
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

  *quoted = delimiters & quotes;
  *comment = delimiters & ~quotes;
}

static inline uint64_t follows(const uint64_t match, uint64_t *overflow)
{
  const uint64_t result = match << 1 | (*overflow);
  *overflow = match >> 63;
  return result;
}

static const simd_table_t blank_table = SIMD_TABLE(
  0x20, 0x00, 0x00, 0x00, // " " = 0x20
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x09, 0x00, 0x00, // "\t" = 0x09
  0x00, 0x0d, 0x00, 0x00  // "\r" = 0x0d
);

static const simd_table_t special_table = SIMD_TABLE(
  0xff, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x28, 0x29, 0x0a, 0x00, // "(" = 0x28, ")" = 0x29, "\n" = 0x0a
  0x00, 0x00, 0x00, 0x00
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
  uint64_t bits;
};

zone_always_inline()
static inline void scan(zone_parser_t *parser, block_t *block)
{
  // escaped newlines are classified as contiguous. however, escape sequences
  // have no meaning in comments and newlines, escaped or not, have no
  // special meaning in quoted
  block->newline = simd_find_8x64(&block->input, '\n');
  block->backslash = simd_find_8x64(&block->input, '\\');
  block->escaped = find_escaped(
    block->backslash, &parser->file->indexer.is_escaped);

  block->comment = 0;
  block->quoted = simd_find_8x64(&block->input, '"') & ~block->escaped;
  block->semicolon = simd_find_8x64(&block->input, ';') & ~block->escaped;

  block->in_quoted = parser->file->indexer.in_quoted;
  block->in_comment = parser->file->indexer.in_comment;

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
    parser->file->indexer.in_quoted = (uint64_t)((int64_t)block->in_quoted >> 63);
    block->in_comment ^= prefix_xor(block->comment);
    parser->file->indexer.in_comment = (uint64_t)((int64_t)block->in_comment >> 63);
  } else {
    block->in_quoted ^= prefix_xor(block->quoted);
    parser->file->indexer.in_quoted = (uint64_t)((int64_t)block->in_quoted >> 63);
  }

  block->blank =
    simd_find_any_8x64(&block->input, blank_table) & ~(block->escaped | block->in_quoted | block->in_comment);
  block->special =
    simd_find_any_8x64(&block->input, special_table) & ~(block->escaped | block->in_quoted | block->in_comment);

  block->contiguous =
    ~(block->blank | block->special | block->quoted) & ~(block->in_quoted | block->in_comment);
  block->follows_contiguous =
    follows(block->contiguous, &parser->file->indexer.follows_contiguous);

  // quoted and contiguous have dynamic lengths, write two indexes
  block->bits = (block->contiguous ^ block->follows_contiguous) | block->quoted | block->special;
}

static inline void refill(zone_parser_t *parser)
{
  zone_file_t *file = parser->file;

  // grow buffer if necessary
  if (file->buffer.length == file->buffer.size) {
    size_t size = file->buffer.size + 16384; // should be a compile time constant!
    char *data = file->buffer.data;
    if (!(data = zone_realloc(&parser->options, data, size + 1)))
      SYNTAX_ERROR(parser, "actually out of memory");
    file->buffer.size = size;
    file->buffer.data = data;
  }

  size_t count = fread(file->buffer.data + file->buffer.length,
                       sizeof(file->buffer.data[0]),
                       file->buffer.size - file->buffer.length,
                       file->handle);

  if (count == 0 && ferror(file->handle))
    SYNTAX_ERROR(parser, "actually a read error");

  // always null-terminate so terminating token can point to something
  file->buffer.length += (size_t)count;
  file->buffer.data[file->buffer.length] = '\0';
  file->end_of_file = feof(file->handle) != 0;
}

zone_always_inline()
static inline void tokenize(zone_parser_t *parser, const block_t *block)
{
  uint64_t bits = block->bits;
  uint64_t count = count_ones(bits);
  const char *base = parser->file->buffer.data + parser->file->buffer.index;

  uint64_t newline = block->newline;
  const uint64_t in_string = block->contiguous | block->in_quoted;

  // take slow path if (escaped) newlines appear in contiguous or quoted.
  // edge case, but must be supported and handled in the scanner for ease of
  // use and to accommodate for parallel processing in the parser. note that
  // escaped newlines may have been present in the last block
  if (zone_unlikely(parser->file->indexer.newlines || (newline & in_string))) {
    for (uint64_t i=0; i < count; i++) {
      uint64_t bit = -bits & bits;
      bits ^= bit;
      if (bit & newline) {
        parser->file->indexer.tail[i] =
          (zone_transition_t){
            base + trailing_zeroes(bit), parser->file->indexer.newlines };
        parser->file->indexer.newlines = 0;
        newline &= -bit;
      } else {
        // count newlines here so number of newlines remains correct if last
        // token is start of contiguous or quoted and index must be reset
        parser->file->indexer.tail[i] =
          (zone_transition_t){ base + trailing_zeroes(bit), 0 };
        parser->file->indexer.newlines += count_ones(newline & ~(-bit));
        newline &= -bit;
      }
    }

    parser->file->indexer.tail += count;
  } else {
    for (uint64_t i=0; i < 6; i++) {
      parser->file->indexer.tail[i] =
        (zone_transition_t){ base + trailing_zeroes(bits), 0 };
      bits = clear_lowest_bit(bits);
    }

    if (zone_unlikely(count > 6)) {
      for (uint64_t i=6; i < 12; i++) {
        parser->file->indexer.tail[i] =
          (zone_transition_t){ base + trailing_zeroes(bits), 0 };
        bits = clear_lowest_bit(bits);
      }

      if (zone_unlikely(count > 12)) {
        for (uint64_t i=12; i < count; i++) {
          parser->file->indexer.tail[i] =
            (zone_transition_t){ base + trailing_zeroes(bits), 0 };
          bits = clear_lowest_bit(bits);
        }
      }
    }

    parser->file->indexer.tail += count;
  }
}

extern const uint8_t *zone_forward;
extern const uint8_t *zone_jump;

zone_never_inline()
zone_nonnull_all()
static zone_return_t step(zone_parser_t *parser, zone_token_t *token)
{
  block_t block = { 0 };
  zone_file_t *file = parser->file;
  const char *base;
  bool start_of_line;

  // check if next token is located at start of line
  assert(file->indexer.tail > file->indexer.tape);
  base = file->indexer.tail[-1].address;
  start_of_line =
    base[0] == '\n' && &base[1] == file->buffer.data + file->buffer.index;

  file->indexer.head = file->indexer.tape;
  file->indexer.tail = file->indexer.tape;

  // refill buffer if required
  if (file->buffer.length - file->buffer.index <= ZONE_BLOCK_SIZE) {
shuffle:
    memmove(file->buffer.data,
            file->buffer.data + file->buffer.index,
            file->buffer.length - file->buffer.index);
    file->buffer.length -= file->buffer.index;
    file->buffer.index = 0;
    refill(parser);
  }

  base = file->buffer.data + file->buffer.index;

  while (file->buffer.length - file->buffer.index >= ZONE_BLOCK_SIZE) {
    if ((file->indexer.tape + ZONE_TAPE_SIZE) - file->indexer.tail < ZONE_BLOCK_SIZE)
      goto terminate;
    simd_loadu_8x64(&block.input, (uint8_t *)&file->buffer.data[file->buffer.index]);
    scan(parser, &block);
    tokenize(parser, &block);
    file->buffer.index += ZONE_BLOCK_SIZE;
  }

  size_t length = file->buffer.length - file->buffer.index;
  assert(length <= ZONE_BLOCK_SIZE);
  if (!file->end_of_file)
    goto terminate;
  if (length > (size_t)((file->indexer.tape + ZONE_TAPE_SIZE) - file->indexer.tail))
    goto terminate;

  uint8_t buffer[ZONE_BLOCK_SIZE] = { 0 };
  memcpy(buffer, &file->buffer.data[file->buffer.index], length);
  const uint64_t clear = ~((1llu << length) - 1);
  simd_loadu_8x64(&block.input, buffer);
  scan(parser, &block);
  block.bits &= ~clear;
  block.contiguous &= ~clear;
  tokenize(parser, &block);
  file->buffer.index += length;
  file->end_of_file = ZONE_NO_MORE_DATA;

terminate:
  // ensure tape contains no partial tokens
  if ((uint64_t)((int64_t)(block.contiguous | block.in_quoted) >> 63)) {
    // FIXME: .com (for example) uses single fields for base64 data, hence a
    //        lot of reprocessing is required for those types of zones. it may
    //        be beneficial to store where we left off
    assert(file->indexer.tail > file->indexer.tape);
    file->indexer.tail--;
    file->indexer.in_comment = 0;
    file->indexer.in_quoted = 0;
    file->indexer.is_escaped = 0;
    file->indexer.follows_contiguous = 0;
    file->buffer.index =
      (size_t)(file->indexer.tail[0].address - file->buffer.data);
  }

  file->indexer.tail[0] =
    (zone_transition_t) { file->buffer.data + file->buffer.length, 0 };
  file->indexer.tail[1] =
    (zone_transition_t) { file->buffer.data + file->buffer.length, 0 };
  file->start_of_line = file->indexer.head[0].address == base && start_of_line;

  do {
    const char *start = file->indexer.head[0].address;
    const char *end   = file->indexer.head[1].address;
    assert(start < end || (start == end && *start == '\0' && *end == '\0'));

    switch (zone_jump[ (unsigned char)*start ]) {
      case 0: // contiguous
        *token = (zone_token_t){ (size_t)(end - start), start };
        // discard index for blank or semicolon
        file->indexer.head += zone_forward[ (unsigned char)*end ];
        return ZONE_CONTIGUOUS;
      case 1: // quoted
        *token = (zone_token_t){ (size_t)(end - start), start + 1 };
        // discard index for closing quote
        file->indexer.head += 2;
        return ZONE_QUOTED;
      case 2: // newline
        file->line += file->indexer.head[0].newlines + 1;
        file->indexer.head++;
        if (file->grouped)
          break;
        file->start_of_line = (end - start) == 1;
        *token = (zone_token_t){ 1, start };
        return ZONE_DELIMITER;
      case 3: // end of file
        if (file->end_of_file != ZONE_NO_MORE_DATA)
          goto shuffle;
        if (file->grouped)
          SYNTAX_ERROR(parser, "Missing closing brace");
        assert(start == file->buffer.data + file->buffer.length);
        assert(end == file->buffer.data + file->buffer.length);
        *token = (zone_token_t){ 1, start };
        return ZONE_DELIMITER;
      case 4: // left parenthesis
        if (file->grouped)
          SYNTAX_ERROR(parser, "Nested opening brace");
        file->grouped = true;
        file->indexer.head++;
        break;
      case 5: // right parenthesis
        if (!file->grouped)
          SYNTAX_ERROR(parser, "Closing brace without opening brace");
        file->grouped = false;
        file->indexer.head++;
        break;
    }
  } while (1);
}

#endif // SCANNER_H
