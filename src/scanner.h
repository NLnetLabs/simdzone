/*
 * scanner.h -- fast lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "zone.h"

#define zone_error(parser, ...) fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

#define ERROR(parser, code, ...) \
  do { zone_error(parser, __VA_ARGS__); return code; } while (0)

#define SYNTAX_ERROR(parser, ...) \
  ERROR(parser, ZONE_SYNTAX_ERROR, __VA_ARGS__)

#define SEMANTIC_ERROR(parser, ...) \
  ERROR(parser, ZONE_SEMANTIC_ERROR, __VA_ARGS__)

#define NOT_IMPLEMENTED(parser, ...) \
  ERROR(parser, ZONE_NOT_IMPLEMENTED, __VA_ARGS__)

#define OUT_OF_MEMORY(parser) \
  return ZONE_OUT_OF_MEMORY

// scanner states
#define ZONE_INITIAL (0)
// ZONE_TTL
// ZONE_CLASS 
// ZONE_TYPE
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)
// ZONE_OWNER
// ZONE_RDATA

// secondary scanner states
#define GROUPED (1<<24)
#define GENERIC_RDATA (1<<25) // parsing generic rdata (RFC3597)

#ifndef NDEBUG
static void print_input(const char *label, const char *str, size_t len)
{
  char bar[120];
  memset(bar, '=', sizeof(bar));
  bar[sizeof(bar)-1] = '\0';
  printf("%-.12s%-.70s\n", bar, bar);
  printf("%-12s: ' ", label);
  for (size_t i=0; i < len; i++) {
    if (str[i] == '\n' || str[i] == '\r')
      putchar('_');
    else if (str[i] == '\t')
      putchar(' ');
    else
      putchar(str[i]);
  }   
  printf(" '\n");
}

static void print_mask(const char *label, uint64_t mask) {
  printf("%-12s: [ ", label);
  for(int i = 0, n = (sizeof(mask)*8)-1; i <= n; i++){
    char c = (mask &(1LL<<i))? '1' : '0';
    putchar(c);
  }
  printf(" ]\n");
}
#else
#define print_input(label, str, len)
#define print_mask(label, mask)
#endif

extern void *zone_malloc(zone_options_t *opts, size_t size);
extern void *zone_realloc(zone_options_t *opts, void *ptr, size_t size);
extern void zone_free(zone_options_t *opts, void *ptr);
extern char *zone_strdup(zone_options_t *opts, const char *str);

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
//
// * while lookup tables can be used to identify sequences, doing so seems
//   more expensive going by the results of some preliminary experiments.
//   two dfa-based approaches are possible:
//   1. classify quote, comment, newline and non-special characters
//      (requires 2 bits to differentiate characters) after discarding any
//      escaped quotes and semicolons and pack them using pext. lookup the
//      dense representation with some state and expand the result using
//      pdep.
//
//      this approach requires interleaving three different masks after
//      discarding escaped bits or converting the escaped mask back into a
//      simd vector and then extract the required information. either
//      mechanism requires quite a few instructions to to come up with a
//      working key and work the result back into a mask. if more than two
//      lookups worth of keys exist in the input, the scanner could branch.
//
//      (not implement/tested, seemed to expensive right of the bat)
//
//   2. classify all structural characters (requires 3 bits to differentiate
//      between characters) and pack 4 characters together in 12 bits. use a
//      precompiled state table indexed by key, lookup all keys and extract
//      the correct values using the state from the last lookup.
//
//      (implemented, initial results were not promising enough)
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

    // FIXME: technically, this introduces a data de
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

static const table_t space_table = TABLE(
  0x20, 0x00, 0x00, 0x00, // " " = 0x20
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x09, 0x00, 0x00, // "\t" = 0x09
  0x00, 0x0d, 0x00, 0x00  // "\r" = 0x0d
);

static const table_t special_table = TABLE(
  0xff, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x28, 0x29, 0x0a, 0x00, // "(" = 0x28, ")" = 0x29, "\n" = 0x0a
  0x00, 0x00, 0x00, 0x00
);

static inline uint64_t scan(zone_parser_t *parser, const uint8_t *ptr)
{
  input_t input;

  load(&input, ptr);

  // escaped newlines are classified as contiguous. however, escape sequences
  // have no meaning in comments and newlines, escaped or not, have no
  // special meaning in quoted
  const uint64_t newline = find(&input, '\n');
  const uint64_t backslash = find(&input, '\\');
  const uint64_t escaped = find_escaped(
    backslash, &parser->file->indexer.is_escaped);

  uint64_t comment = 0;
  uint64_t quoted = find(&input, '"') & ~escaped;
  const uint64_t semicolon = find(&input, ';') & ~escaped;

  uint64_t in_quoted = parser->file->indexer.in_quoted;
  uint64_t in_comment = parser->file->indexer.in_comment;

  if (in_comment || semicolon) {
    find_delimiters(
      quoted, semicolon, newline, in_quoted, in_comment, &quoted, &comment);

    in_quoted ^= prefix_xor(quoted);
    parser->file->indexer.in_quoted = (uint64_t)((int64_t)in_quoted >> 63);
    in_comment ^= prefix_xor(comment);
    parser->file->indexer.in_comment = (uint64_t)((int64_t)in_comment >> 63);
  } else {
    in_quoted ^= prefix_xor(quoted);
    parser->file->indexer.in_quoted = (uint64_t)((int64_t)in_quoted >> 63);
  }

  const uint64_t space =
    find_any(&input, space_table) & ~(escaped | in_quoted | in_comment);
  const uint64_t special =
    find_any(&input, special_table) & ~(escaped | in_quoted | in_comment);

  const uint64_t contiguous =
    ~(space | special | quoted) & ~(in_quoted | in_comment);
  const uint64_t follows_contiguous =
    follows(contiguous, &parser->file->indexer.follows_contiguous);

  // quote and contiguous have dynamic lengths, write two indexes
  const uint64_t bits =
    (contiguous ^ follows_contiguous) | quoted | special |
    ((backslash | escaped | newline) & (contiguous | in_quoted));

  print_mask("bits", bits);

  return bits;
}

static inline zone_return_t refill(zone_parser_t *parser)
{
  zone_file_t *file = parser->file;

  // grow buffer if necessary
  if (file->buffer.length == file->buffer.size) {
    size_t size = file->buffer.size + 16384; // should be a compile time constant!
    char *data = file->buffer.data;
    if (!(data = zone_realloc(&parser->options, data, size + 1)))
      return ZONE_OUT_OF_MEMORY;
    file->buffer.size = size;
    file->buffer.data = data;
  }

  ssize_t count = read(file->handle,
                       file->buffer.data + file->buffer.length,
                       file->buffer.size - file->buffer.length);
  if (count < 0)
    return ZONE_READ_ERROR;
  // always null-terminate so terminating token can point to something
  file->buffer.length += (size_t)count;
  file->buffer.data[file->buffer.length] = '\0';
  file->end_of_file = count == 0;
  return 0;
}

#define unlikely(x) __builtin_expect(!!(x), 0)
static inline void dump(zone_parser_t *parser, uint64_t bits)
{
  int count = count_ones(bits);

  for (int i=0; i < 6; i++) {
    parser->file->indexer.tail[i] =
      parser->file->buffer.index + trailing_zeroes(bits);
    bits = clear_lowest_bit(bits);
  }

  if (unlikely(count > 6)) {
    for (int i=6; i < 12; i++) {
      parser->file->indexer.tail[i] =
        parser->file->buffer.index + trailing_zeroes(bits);
      bits = clear_lowest_bit(bits);
    }

    if (unlikely(count > 12)) {
      for (int i=12; i < count; i++) {
        parser->file->indexer.tail[i] =
          parser->file->buffer.index + trailing_zeroes(bits);
        bits = clear_lowest_bit(bits);
      }
    }
  }

  parser->file->indexer.tail += count;
}

static inline zone_return_t step(zone_parser_t *parser, size_t *start)
{
  parser->file->indexer.head = parser->file->indexer.tape;
  parser->file->indexer.tail = parser->file->indexer.tape;

  // refill buffer if required
  if (parser->file->buffer.length - parser->file->buffer.index <= 64) {
    assert(*start <= parser->file->buffer.index);
    // flush everything if no existing blocks need to be retained
    if (!*start)
      *start = parser->file->buffer.index;
    memmove(parser->file->buffer.data,
            parser->file->buffer.data + *start,
            parser->file->buffer.length - *start);
    parser->file->buffer.index -= *start;
    parser->file->buffer.length -= *start;
    *start = 0;

    zone_return_t result;
    if ((result = refill(parser)) < 0)
      return result;
  }

  zone_file_t *file = parser->file;

  size_t length = 0;
  static const size_t size =
    sizeof(file->indexer.tape) / sizeof(file->indexer.tape[0]);

  while (file->buffer.length - file->buffer.index >= 64) {
    if (size - length < 64)
      goto terminate;
    const uint64_t bits = scan(
      parser, (uint8_t *)&file->buffer.data[file->buffer.index]);
    dump(parser, bits);
    file->buffer.index += 64;
    length += (file->indexer.tail - file->indexer.tape) / sizeof(size_t);
  }

  const size_t count = file->buffer.length - file->buffer.index;
  if (!file->end_of_file || !count)
    goto terminate;
  if (size - length < count)
    goto terminate;

  uint8_t buffer[64] = { 0 };
  memcpy(buffer, &file->buffer.data[file->buffer.index], count);
  uint64_t bits = scan(parser, buffer) & ((1llu << count) - 1);
  dump(parser, bits);
  file->buffer.index += count;

terminate:
  parser->file->indexer.tail[0] = parser->file->buffer.size;
  return 0;
}

static inline bool empty(const zone_parser_t *parser)
{
  if (!parser->file->end_of_file)
    return 0;
  if (parser->file->buffer.index < parser->file->buffer.length)
    return 0;
  return 1;
}

#define STRING(length, data) \
  (zone_token_t){ .string = { length, data } }

static inline zone_return_t lex_quoted(
  zone_parser_t *parser, zone_token_t *token, size_t start)
{
  size_t end;
  zone_return_t result;

do_jump:
  end = *parser->file->indexer.head++;
  switch (parser->file->buffer.data[end]) {
    case '\0': goto do_null;
    case '\"': goto do_quote;
    case '\\': goto do_escaped;
    case '\n': goto do_newline;
    default:   goto do_panic;
  }

do_quote:
  *token = STRING(end - start, &parser->file->buffer.data[start]);
  return 'q'; // (q)uoted

do_newline:
  parser->file->line++;
  goto do_jump;

do_null:
  if (empty(parser))
    SYNTAX_ERROR(parser, "Unterminated string");
  if ((result = step(parser, &start)) < 0)
    return result;
  goto do_jump;

do_escaped:
  end = *parser->file->indexer.head++;
  switch (parser->file->buffer.data[end]) {
    case '\0': goto do_escaped_null;
    case '\n': goto do_newline;
    default:   goto do_jump;
  }

do_escaped_null:
  if (empty(parser))
    SYNTAX_ERROR(parser, "Unterminated string");
  if ((result = step(parser, &start)) < 0)
    return result;
  goto do_jump;

do_panic:
  abort();
}

static inline zone_return_t lex_contiguous(
  zone_parser_t *parser, zone_token_t *token, size_t start)
{
  size_t end;
  zone_return_t result;

do_jump:
  end = *parser->file->indexer.head;
  switch (parser->file->buffer.data[end]) {
    case '\0': goto do_null;
    case ' ':
    case '\t':
    case '\r': goto do_blank;
    case '\\': goto do_escaped;
    default:   goto do_special;
  }

do_blank:
  parser->file->indexer.head++;
do_special:
  *token = STRING(end - start, &parser->file->buffer.data[start]);
  return 'c'; // (c)ontiguous

do_null:
  if (empty(parser))
    goto do_special;
  if ((result = step(parser, &start)) < 0)
    return result;
  goto do_jump;

do_escaped:
  parser->file->indexer.head++;
  end = *parser->file->indexer.head;
  switch (parser->file->buffer.data[end]) {
    case '\0': goto do_escaped_null;
    case '\n': goto do_newline;
    default:   goto do_jump;
  }

do_newline:
  parser->file->line++;
  parser->file->indexer.head++;
  goto do_jump;

do_escaped_null:
  if (empty(parser))
    goto do_special;
  if ((result = step(parser, &start)) < 0)
    return result;
  goto do_escaped;
}

static inline zone_return_t lex_escaped(
  zone_parser_t *parser, zone_token_t *token, size_t start)
{
  size_t end;
  zone_return_t result;

do_jump:
  end = *parser->file->indexer.head++;
  switch (parser->file->buffer.data[end]) {
    case '\0': goto do_null;
    case '\n': goto do_newline;
    default:   goto do_contiguous;
  }

do_newline:
  parser->file->line++;
do_contiguous:
  return lex_contiguous(parser, token, start);

do_null:
  if (empty(parser))
    goto do_contiguous;
  if ((result = step(parser, &start)) < 0)
    return result;
  goto do_jump;
}

static inline zone_return_t lex(
  zone_parser_t *parser, zone_token_t *token)
{
  size_t dummy = 0, start;
  zone_return_t result;

do_jump:
  start = *parser->file->indexer.head++;
  switch (parser->file->buffer.data[start]) {
    case '(':   goto do_open_bracket;
    case ')':   goto do_close_bracket;
    case ' ':
    case '\t':
    case '\r':  goto do_blank;
    case '\n':  goto do_newline;
    case '\0':  goto do_null;
    case '\"':  goto do_quoted;
    case '\\':  goto do_escaped;
    default:    goto do_contiguous;
  }

do_open_bracket:
  if (parser->state.scanner & GROUPED)
    SYNTAX_ERROR(parser, "Nested opening brace");
  parser->state.scanner |= GROUPED;
  goto do_jump;

do_close_bracket:
  if (!(parser->state.scanner & GROUPED))
    SYNTAX_ERROR(parser, "Closing brace without opening brace");
  parser->state.scanner &= ~GROUPED;
  goto do_jump;

do_blank:
  abort();

do_newline:
  parser->file->line++;
  if (parser->state.scanner & GROUPED)
    goto do_jump;
  switch (parser->file->buffer.data[start+1]) {
    case ' ':
    case '\t':
    case '\n':
      parser->file->start_of_line = false;
      break;
    default:
      parser->file->start_of_line = true;
      break;
  }
  *token = STRING(1, "\n");
  return '\n';

do_quoted:
  return lex_quoted(parser, token, start+1);

do_contiguous:
  return lex_contiguous(parser, token, start);

do_escaped:
  return lex_escaped(parser, token, start);

do_null:
  if (empty(parser))
    return '\0';
  if ((result = step(parser, &dummy)) < 0)
    return result;
  goto do_jump;
}

#endif // SCANNER_H
