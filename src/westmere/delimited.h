/*
 * string.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef DELIMITED_H
#define DELIMITED_H

zone_nonnull_all
static zone_really_inline void copy_and_scan_delimited(
  delimited_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source,
  uint8_t *destination)
{
  __m128i b = _mm_loadu_si128((const __m128i *)space);
  __m128i d = _mm_loadu_si128((const __m128i *)delimiter);

  simd_loadu_8x(&block->input, (const uint8_t *)source);
  b = _mm_shuffle_epi8(b, block->input.chunks[0]);
  d = _mm_shuffle_epi8(d, block->input.chunks[0]);
  simd_storeu_8x(destination, &block->input);
  b = _mm_cmpeq_epi8(block->input.chunks[0], b);
  d = _mm_cmpeq_epi8(block->input.chunks[0], d);
  block->delimiter = (uint16_t)_mm_movemask_epi8(_mm_or_si128(b, d));
}

zone_nonnull_all
static zone_really_inline void scan_delimited(
  delimited_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source)
{
  __m128i b = _mm_loadu_si128((const __m128i *)space);
  __m128i d = _mm_loadu_si128((const __m128i *)delimiter);

  simd_loadu_8x(&block->input, (const uint8_t *)source);
  b = _mm_shuffle_epi8(b, block->input.chunks[0]);
  d = _mm_shuffle_epi8(d, block->input.chunks[0]);
  b = _mm_cmpeq_epi8(block->input.chunks[0], b);
  d = _mm_cmpeq_epi8(block->input.chunks[0], d);
  block->delimiter = (uint16_t)_mm_movemask_epi8(_mm_or_si128(b, d));
}

#endif // STRING_H
