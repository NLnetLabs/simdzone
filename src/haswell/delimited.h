/*
 * string.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef STRING_H
#define STRING_H

zone_nonnull_all
static zone_really_inline void copy_and_scan_delimited(
  delimited_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source,
  uint8_t *destination)
{
  __m256i b = _mm256_loadu_si256((const __m256i *)space);
  __m256i d = _mm256_loadu_si256((const __m256i *)delimiter);

  simd_loadu_8x(&block->input, (const uint8_t *)source);
  b = _mm256_shuffle_epi8(b, block->input.chunks[0]);
  d = _mm256_shuffle_epi8(d, block->input.chunks[0]);
  simd_storeu_8x(destination, &block->input);
  b = _mm256_cmpeq_epi8(block->input.chunks[0], b);
  d = _mm256_cmpeq_epi8(block->input.chunks[0], d);
  block->delimiter = (uint32_t)_mm256_movemask_epi8(_mm256_or_si256(b, d));
}

zone_nonnull_all
static zone_really_inline void scan_delimited(
  delimited_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source)
{
  __m256i b = _mm256_loadu_si256((const __m256i *)space);
  __m256i d = _mm256_loadu_si256((const __m256i *)delimiter);

  simd_loadu_8x(&block->input, (const uint8_t *)source);
  b = _mm256_shuffle_epi8(b, block->input.chunks[0]);
  d = _mm256_shuffle_epi8(d, block->input.chunks[0]);
  b = _mm256_cmpeq_epi8(block->input.chunks[0], b);
  d = _mm256_cmpeq_epi8(block->input.chunks[0], d);
  block->delimiter = (uint32_t)_mm256_movemask_epi8(_mm256_or_si256(b, d));
}

#endif // STRING_H
