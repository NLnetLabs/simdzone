/*
 * text.h -- string parsing implementation targeting SSE4.2
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef STRING_H
#define STRING_H

typedef struct string_block string_block_t;
struct string_block {
  uint64_t backslash;
  uint64_t delimiter;
};

zone_nonnull_all
static zone_really_inline void copy_contiguous_string_block(
  const char *text, uint8_t *wire, string_block_t *block)
{
  const __m256i d0 = _mm256_setr_epi8(
    0x10, 0x00, 0x20, 0x00, -128, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x20, 0x00, -128, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  const __m256i d1 = _mm256_setr_epi8(
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x30, 0x10, 0x00, -128, 0x10, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x30, 0x10, 0x00, -128, 0x10, 0x00, 0x00);

  const __m256i i = _mm256_loadu_si256((const __m256i *)(text));
  _mm256_storeu_si256((__m256i *)wire, i);

  const __m256i ds0 = _mm256_shuffle_epi8(d0, _mm256_srli_epi16(i, 4));
  const __m256i ds1 = _mm256_shuffle_epi8(d1, i);
  const __m256i ds = _mm256_and_si256(ds0, ds1);

  block->backslash =
    (uint32_t)_mm256_movemask_epi8(ds);
  block->delimiter =
    (uint32_t)_mm256_movemask_epi8(_mm256_cmpgt_epi8(ds, _mm256_setzero_si256()));
}

zone_nonnull_all
static zone_really_inline void copy_quoted_string_block(
  const char *text, uint8_t *wire, string_block_t *block)
{
  const __m256i b = _mm256_set1_epi8('\\');
  const __m256i q = _mm256_set1_epi8('\"');

  const __m256i i = _mm256_loadu_si256((const __m256i *)(text));
  _mm256_storeu_si256((__m256i *)wire, i);

  block->backslash = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(i, b));
  block->delimiter = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(i, q));
}

#endif // STRING_H
