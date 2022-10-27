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
#include "dfa.h"

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
typedef struct block block_t;
struct block {
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

static void print_classified(const char *label, const block_t *block)
{
  printf("%-12s: [ ", label);
  for (size_t i=0; i < 32; i++) {
    const uint8_t b = ((uint8_t *)&block->chunks[0])[i];
    printf("%x", (int)b);
  }
  for (size_t i=0; i < 32; i++) {
    const uint8_t b = ((uint8_t *)&block->chunks[1])[i];
    printf("%x", (int)b);
  }
  printf(" ]\n");
}

static void print_compressed(const char *label, const block_t *block)
{
  printf("%-12s: [ ", label);
  const uint32_t *x = (const uint32_t *)&block->chunks[0];
  for (size_t i=0; i < 16; i++) {
    const uint32_t y = x[i]&0xfff;
    printf("%x%x%x%x", y&7, (y>>3)&7, (y>>6)&7, (y>>9)&7);
  }
  printf(" ]\n");
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
#define print_classified(label, block)
#define print_compressed(label, block)
#define print_mask(label, mask)
#endif

#define zone_unlikely(x) __builtin_expect(!!(x), 0)

static inline void load(block_t *block, const uint8_t *input)
{
  block->chunks[0] = _mm256_loadu_si256((const __m256i *)(input));
  block->chunks[1] = _mm256_loadu_si256((const __m256i *)(input+32));
}

#define TABLE(v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,  \
              v8,  v9,  v10, v11, v12, v13, v14, v15) \
 { v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,             \
   v8,  v9,  v10, v11, v12, v13, v14, v15,            \
   v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,             \
   v8,  v9,  v10, v11, v12, v13, v14, v15 }

static const uint8_t mask_hi[32] = TABLE(
  /* 0x00 */  0x80 | ZONE_SPACE | ZONE_NEWLINE,
  /* 0x10 */  0x00, 
  /* 0x20 */  0x40 | ZONE_SPACE | ZONE_QUOTE | ZONE_BRACKET,
  /* 0x30 */  0x20 | ZONE_SEMICOLON,
  /* 0x40 */  0x00, 
  /* 0x50 */  0x10 | ZONE_BACKSLASH,
  /* 0x60 */  0x00,
  /* 0x70 */  0x00,
  /* 0x80 */  0x00,
  /* 0x90 */  0x00,
  /* 0xa0 */  0x00,
  /* 0xb0 */  0x00,
  /* 0xc0 */  0x00,
  /* 0xd0 */  0x00,
  /* 0xe0 */  0x00,
  /* 0xf0 */  0x00 
);  

static const uint8_t mask_lo[32] = TABLE(
  /* 0x00 */  0x40 | ZONE_SPACE,
  /* 0x01 */  0x00,
  /* 0x02 */  0x40 | ZONE_QUOTE | ZONE_BACKSLASH,
  /* 0x03 */  0x00,
  /* 0x04 */  0x00,
  /* 0x05 */  0x00,
  /* 0x06 */  0x00,
  /* 0x07 */  0x00,
  /* 0x08 */  0x40 | ZONE_BRACKET,
  /* 0x09 */  0xc0 | ZONE_SPACE | ZONE_BRACKET,
  /* 0x0a */  0x80 | ZONE_NEWLINE,
  /* 0x0b */  0x20 | ZONE_SEMICOLON,
  /* 0x0c */  0x10 | ZONE_BACKSLASH,
  /* 0x0d */  0x80 | ZONE_SPACE,
  /* 0x0e */  0x00,
  /* 0x0f */  0x00
);

static inline void classify_chunk(__m256i *chunk)
{
  const __m256i hi =
    _mm256_and_si256(_mm256_srli_epi16(*chunk, 0x4), _mm256_set1_epi8(0xf));

  const __m256i shuffled_lo = _mm256_shuffle_epi8(*(const __m256i *)mask_lo, *chunk);
  const __m256i shuffled_hi = _mm256_shuffle_epi8(*(const __m256i *)mask_hi, hi);

  *chunk = _mm256_and_si256(shuffled_lo, shuffled_hi);
  *chunk = _mm256_subs_epu8(*chunk, _mm256_set1_epi8(0x10));
  // just for ease of visualization; we don't need this
  *chunk = _mm256_and_si256(*chunk, _mm256_set1_epi8(0x0f));
}

static inline void classify(block_t *block)
{
  classify_chunk(&block->chunks[0]);
  classify_chunk(&block->chunks[1]);
}

static inline void compress_chunk(__m256i *chunk)
{
  *chunk = _mm256_and_si256(*chunk, _mm256_set1_epi8(0x7));
  *chunk = _mm256_or_si256(_mm256_srli_epi16(*chunk, 5), *chunk);
  *chunk = _mm256_and_si256(*chunk, _mm256_set1_epi16(0x3f));
  *chunk = _mm256_or_si256(_mm256_srli_epi32(*chunk, 10), *chunk);
}

static inline void compress(block_t *block)
{
  compress_chunk(&block->chunks[0]);
  compress_chunk(&block->chunks[1]);
}

static inline uint32_t key(block_t *block, uint32_t which)
{
  const uint32_t *keys = (const uint32_t *)&block->chunks[0];
  return keys[which] & 0xfff;
}

#include "transitions.h"

static inline uint64_t lex(zone_parser_t *parser, const uint8_t *input)
{
  uint64_t bits = 0;
  uint32_t masks[16];
  block_t block;

  print_input("input", (const char *)input, 64);
  load(&block, input);
  classify(&block);
  print_classified("classified", &block);
  compress(&block);
  print_compressed("compressed", &block);

  for (int i=0; i < 16; i++) {
    const uint32_t k = key(&block, i);
    masks[i] = transitions[k];
  }

  for (int i=0; i < 16; i++) {
    uint32_t state = parser->file->indexer.state;
    const uint64_t mask = (masks[i] >> (state*4)) & 0xf;
    bits |= (mask << (i*4));
    state = (masks[i] >> ((state*3) + 24)) & 0x7;
    parser->file->indexer.state = state;
  }

  print_mask("bits", bits);
  return bits;
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

static inline void write_tape(zone_parser_t *parser, uint64_t bits)
{
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
    const uint8_t *ptr = read_data(parser);
    uint64_t bits = lex(parser, ptr);
    write_tape(parser, bits);
    advance_data(parser, 64);
  }

  size_t size;
  if (is_empty(parser) && (size = has_data(parser))) {
    uint8_t buffer[ZONE_BLOCK_SIZE] = { 0 };
    const uint8_t *ptr = read_data(parser);
    assert(size < ZONE_BLOCK_SIZE);
    memcpy(buffer, ptr, size);
    uint64_t bits = lex(parser, buffer);
    bits &= (1 << size) - 1;
    write_tape(parser, bits);
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
