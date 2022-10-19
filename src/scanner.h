/*
 * scanner.h -- fast lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_SCANNER_H
#define ZONE_SCANNER_H

#include <assert.h>
#include <immintrin.h> // assume x86_64 for now

#include "zone.h"

// scanner states
#define ZONE_INITIAL (0)
// ZONE_TTL
// ZONE_CLASS 
// ZONE_TYPE
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)
// ZONE_OWNER
// ZONE_RDATA

// secondary scanner states
#define ZONE_GROUPED (1<<24)
#define ZONE_GENERIC_RDATA (1<<25) // parsing generic rdata (RFC3597)
#define ZONE_DEFERRED_RDATA (1<<26)

// operate on 64-bit blocks. always.
typedef struct input input_t;
struct input {
  __m256i chunks[2];
};

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

#define zone_unlikely(x) __builtin_expect(!!(x), 0)

static inline uint64_t follows(const uint64_t match, uint64_t *overflow)
{
  const uint64_t result = match << 1 | (*overflow);
  *overflow = match >> 63;
  return result;
}

static inline void load(
  input_t *input, const uint8_t *ptr)
{
  input->chunks[0] = _mm256_loadu_si256((const __m256i *)(ptr));
  input->chunks[1] = _mm256_loadu_si256((const __m256i *)(ptr+32));
}

static inline uint64_t find(
  const input_t *input, uint8_t needle)
{
  const __m256i needles = _mm256_set1_epi8(needle);

  const __m256i v0 = _mm256_cmpeq_epi8(input->chunks[0], needles);
  const __m256i v1 = _mm256_cmpeq_epi8(input->chunks[1], needles);
  
  const uint64_t r0 = (uint32_t)_mm256_movemask_epi8(v0);
  const uint64_t r1 = _mm256_movemask_epi8(v1);
    
  return r0 | (r1 << 32);
}

static const uint8_t space[32] = {
  0x20, 0x00, 0x00, 0x00, // " " = 0x20
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x09, 0x00, 0x00, // "\t" = 0x09
  0x00, 0x0d, 0x00, 0x00, // "\r" = 0x0d
  0x20, 0x00, 0x00, 0x00, // " " = 0x20
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x09, 0x00, 0x00, // "\t" = 0x09
  0x00, 0x0d, 0x00, 0x00  // "\r" = 0x0d
};

static const uint8_t special[32] = {
  0xff, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x28, 0x29, 0x0a, 0x00, // "(" = 0x28, ")" = 0x29, "\n" = 0x0a
  0x00, 0x00, 0x00, 0x00,
  0xff, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x28, 0x29, 0x0a, 0x00, // "(" = 0x28, ")" = 0x29, "\n" = 0x0a
  0x00, 0x00, 0x00, 0x00
};

static inline uint64_t find_any(
  const input_t *input, const uint8_t needles[32])
{
  const __m256i t = _mm256_loadu_si256((const __m256i*)needles);
  const __m256i eq0 = _mm256_cmpeq_epi8(
    _mm256_shuffle_epi8(t, input->chunks[0]), input->chunks[0]);
  const __m256i eq1 = _mm256_cmpeq_epi8(
    _mm256_shuffle_epi8(t, input->chunks[1]), input->chunks[1]);

  const uint64_t r0 = (uint32_t)_mm256_movemask_epi8(eq0);
  const uint64_t r1 = _mm256_movemask_epi8(eq1);

  return r0 | (r1 << 32);
}

static inline bool add_overflow(uint64_t value1, uint64_t value2, uint64_t *result) {
  return __builtin_uaddll_overflow(value1, value2, (unsigned long long *)result);
}

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

static inline uint64_t find_bounds(
  uint64_t quotes,
  uint64_t semicolons,
  uint64_t newlines,
  uint64_t *in_quoted,
  uint64_t *in_comment)
{
  uint64_t bounds, starts = quotes | semicolons;
  uint64_t end, start = 0;

  assert(!(quotes & semicolons));

  // carry over state from last block
  end = (newlines & *in_comment) | (quotes & *in_quoted);
  end &= -end;

  bounds = end;
  starts &= ~((*in_comment | *in_quoted) ^ (-end - end));

  while (starts) {
    start = -starts & starts;
    assert(start);
    const uint64_t quote = quotes & start;
    const uint64_t semicolon = semicolons & start;

    end = (newlines & -semicolon) | (quotes & (-quote - quote));
    end &= -end;

    bounds |= end | start;
    starts &= -end - end;
  }

  // carry over state to next block
  *in_quoted = (uint64_t)((int64_t)(
    ((-(start & quotes) | (*in_quoted & ~(-start))) & ~(-end))) >> 63);
  *in_comment = (uint64_t)((int64_t)(
    ((-(start & semicolons) | (*in_comment & ~(-start))) & ~(-end))) >> 63);

  return bounds;
}

static inline uint64_t prefix_xor(const uint64_t bitmask) {
  // There should be no such thing with a processor supporting avx2
  // but not clmul.
  __m128i all_ones = _mm_set1_epi8('\xFF');
  __m128i result = _mm_clmulepi64_si128(_mm_set_epi64x(0ULL, bitmask), all_ones, 0);
  return _mm_cvtsi128_si64(result);
}

static inline void index_data(
  zone_parser_t *parser, zone_block_t *block, const uint8_t *ptr)
{
  input_t input;

  load(&input, ptr);

  block->backslash = find(&input, '\\');
  block->escaped = find_escaped(
    block->backslash, &parser->file->indexer.is_escaped);

  block->quote = find(&input, '"') & ~block->escaped;
  block->semicolons = find(&input, ';') & ~block->escaped;
  // escaped newlines are classified as contiguous. however, escape sequences
  // have no meaning in comments and newlines, escaped or not, have no special
  // meaning in quoted
  block->newlines = find(&input, '\n');

  assert(!(parser->file->indexer.in_quoted & parser->file->indexer.in_comment));

  const uint64_t prev_in_bounded =
    parser->file->indexer.in_quoted | parser->file->indexer.in_comment;

  block->bounds = find_bounds(
    block->quote,
    block->semicolons,
    block->newlines,
   &parser->file->indexer.in_quoted,
   &parser->file->indexer.in_comment);

  // discard any quotes found in comments
  block->quote &= block->bounds;

  const uint64_t in_bounded = prefix_xor(block->bounds) ^ prev_in_bounded;

  block->space = find_any(&input, space) & ~(block->escaped | in_bounded);
  block->special = find_any(&input, special) & ~(block->escaped | in_bounded);

  block->contiguous =
    ~(block->space | block->special | block->quote) & ~in_bounded;
  block->follows_contiguous =
    follows(block->contiguous, &parser->file->indexer.follows_contiguous);

  print_input("input", (const char *)ptr, 64);
  print_mask("backslash", block->backslash);
  print_mask("escaped", block->escaped);
  print_mask("quote", block->quote);
  print_mask("semicolons", block->semicolons);
  print_mask("bounds", block->bounds);
  print_mask("bounded", in_bounded);
  print_mask("space", block->space);
  print_mask("special", block->special);
  print_mask("contiguous", block->contiguous);
}

static inline zone_return_t refill(zone_parser_t *parser)
{
  zone_file_t *file = parser->file;

  if (file->buffer.index == file->buffer.length) {
    file->buffer.offset = 0;
    file->buffer.index = 0;
    file->buffer.length = 0;
  } else {
    assert(file->buffer.index < file->buffer.length);
    memcpy(file->buffer.data,
           file->buffer.data + file->buffer.index,
           file->buffer.length - file->buffer.index);
    file->buffer.length -= file->buffer.index;
    file->buffer.index = 0;
    file->buffer.offset = 0;
  }

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
  file->empty = count == 0;
  return 0;
}

static inline size_t has_data(const zone_parser_t *parser)
{
  assert(parser->file->buffer.length <= parser->file->buffer.size);
  assert(parser->file->buffer.length >= parser->file->buffer.index);
  return parser->file->buffer.length - parser->file->buffer.index;
}

static inline bool is_empty(const zone_parser_t *parser)
{
  return parser->file->empty;
}

static inline uint8_t *read_data(const zone_parser_t *parser)
{
  const char *ptr = &parser->file->buffer.data[parser->file->buffer.index];
  return (uint8_t *)ptr;
}

static inline void advance_data(const zone_parser_t *parser, size_t skip)
{
  assert(parser->file->buffer.length >= skip);
  assert(parser->file->buffer.length <= parser->file->buffer.size);
  assert(parser->file->buffer.index <= parser->file->buffer.length - skip);
  parser->file->buffer.index += skip;
}

static inline long long int count_ones(uint64_t input_num) {
  return _mm_popcnt_u64(input_num);
}

static inline uint64_t trailing_zeroes(uint64_t input_num) {
  return __builtin_ctzll(input_num);
}

/* result might be undefined when input_num is zero */
static inline uint64_t clear_lowest_bit(uint64_t input_num) {
  return input_num & (input_num-1);
}

static inline uint64_t leading_zeroes(uint64_t input_num) {
  return __builtin_clzll(input_num);
}

static inline bool has_tape(const zone_parser_t *parser)
{
  const size_t used = parser->file->indexer.tail - parser->file->indexer.tape;
  const size_t size = sizeof(parser->file->indexer.tape);
  return 64 <= (size / sizeof(parser->file->indexer.tape[0])) - used;
}

#define unlikely(x) __builtin_expect(!!(x), 0)

static inline void write_tape(
  zone_parser_t *parser, const zone_block_t *block)
{
  // quoted and contiguous have a dynamic length, write two indexes
  const uint64_t contiguous = block->contiguous ^ block->follows_contiguous;
  const uint64_t quoted = block->quote;
  // length for special characters is fixed. always.
  const uint64_t special = block->special;

  uint64_t bits = contiguous | quoted | special;

  print_mask("bits", bits);

  int count = count_ones(bits);

  for (int i=0; i < 6; i++) {
    parser->file->indexer.tail[i] =
      parser->file->buffer.index + trailing_zeroes(bits);
    bits = clear_lowest_bit(bits);
  }

  if (zone_unlikely(count > 6)) {
    for (int i=6; i < 12; i++) {
      parser->file->indexer.tail[i] =
        parser->file->buffer.index + trailing_zeroes(bits);
      bits = clear_lowest_bit(bits);
    }

    if (zone_unlikely(count > 12)) {
      for (int i=12; i < count; i++) {
        parser->file->indexer.tail[i] =
          parser->file->buffer.index + trailing_zeroes(bits);
        bits = clear_lowest_bit(bits);
      }
    }
  }

  parser->file->indexer.tail += count;
}

static inline void terminate_tape(
  zone_parser_t *parser)
{
  assert(parser->file->indexer.tail >= parser->file->indexer.tape);
  assert(parser->file->indexer.tail <= parser->file->indexer.tape + ZONE_TAPE_SIZE);
  parser->file->indexer.tail[0] = parser->file->buffer.size;
}

static inline size_t read_tape(
  const zone_parser_t *parser, const size_t skip)
{
  assert(parser->file->indexer.index <= (ZONE_TAPE_SIZE+1) - skip);
  return parser->file->indexer.tape[parser->file->indexer.index + skip];
}

static inline void advance_tape(
  const zone_parser_t *parser, const size_t skip)
{
  assert(skip == 1 || skip == 2);
  assert(parser->file->indexer.index <= (ZONE_TAPE_SIZE+1) - skip);
  parser->file->indexer.index += skip;
}

static inline zone_return_t roll(zone_parser_t *parser)
{
  zone_return_t err;

  if (parser->file->indexer.index) {
    assert(parser->file->buffer.index <= parser->file->buffer.length);
    size_t index = parser->file->indexer.index;
    size_t count = parser->file->indexer.tape[index] != parser->file->buffer.size;
    assert(parser->file->indexer.tape[index+count] == parser->file->buffer.size);
    if (count)
      parser->file->indexer.tape[0] =
        parser->file->indexer.tape[index] - parser->file->buffer.index;
    parser->file->indexer.tail = parser->file->indexer.tape + count;
    parser->file->indexer.index = count;
  } else {
    assert(parser->file->indexer.tape == parser->file->indexer.tail);
  }

  if ((err = refill(parser)) != 0)
    return err;

  while (has_data(parser) >= 64) {
    if (!has_tape(parser))
      goto terminate;
    zone_block_t block;
    const uint8_t *ptr = read_data(parser);
    index_data(parser, &block, ptr);
    write_tape(parser, &block);
    advance_data(parser, 64);
  }

  size_t size;
  if (is_empty(parser) && (size = has_data(parser))) {
    uint8_t buffer[ZONE_BLOCK_SIZE] = { 0 };
    const uint8_t *ptr = read_data(parser);
    assert(size < ZONE_BLOCK_SIZE);
    memcpy(buffer, ptr, size);
    zone_block_t block;
    index_data(parser, &block, buffer);
    block.contiguous &= (1 << size) - 1;
    block.follows_contiguous &= (1 << size) - 1;
    write_tape(parser, &block);
    advance_data(parser, size);
  }

terminate:
  terminate_tape(parser);
  return 0;
}

static inline zone_return_t zone_scan(
  zone_parser_t *parser, zone_token_t *token)
{
  zone_return_t err;

  for (;;) {
    size_t end, start = read_tape(parser, 0);
    uint8_t delim;

    switch (parser->file->buffer.data[start]) {
      case '(':
        if (parser->state.scanner & ZONE_GROUPED) {
          fprintf(stderr, "Nested braces");
          return ZONE_SYNTAX_ERROR;
        }
        parser->state.scanner |= ZONE_GROUPED;
        advance_tape(parser, 1);
        break;
      case ')':
        if (!(parser->state.scanner & ZONE_GROUPED)) {
          fprintf(stderr, "Closing brace without opening brace");
          return ZONE_SYNTAX_ERROR;
        }
        parser->state.scanner &= ~ZONE_GROUPED;
        advance_tape(parser, 1);
        break;
      case ' ':
      case '\t':
        advance_tape(parser, 1);
        break;
      case '\n':
        parser->file->indexer.index++;
        if (parser->state.scanner & ZONE_GROUPED)
          break;
        *token = (zone_token_t){ start, 1 };
        return '\n';
      case '\0':
        if (!is_empty(parser))
          goto roll;
        *token = (zone_token_t){ start, 1 };
        return '\0';
      case '\"':
        end = read_tape(parser, 1);
        delim = parser->file->buffer.data[end];
        if (delim == '\0' && !is_empty(parser))
          goto roll;
        if (delim != '\"') {
          fprintf(stderr, "Undelimited string");
          return ZONE_SYNTAX_ERROR;
        }
        advance_tape(parser, 2);
        *token = (zone_token_t){ start+1, end - start };
        return 'q'; // (q)uoted
      default:
        end = read_tape(parser, 1);
        delim = parser->file->buffer.data[end];
        if (delim == '\0' && !is_empty(parser))
          goto roll;
        advance_tape(parser, 1);
        *token = (zone_token_t){ start+0, end - start };
        return 'c'; // (c)ontiguous
roll:
        if ((err = roll(parser)) != 0)
          return 0;
        else if (err)
          return err;
        break;
    }
  }
}

#endif // ZONE_SCANNER_H
