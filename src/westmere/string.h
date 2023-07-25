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
  const __m128i d0 = _mm_setr_epi8(
    0x10, 0x00, 0x20, 0x00, -128, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  const __m128i d1 = _mm_setr_epi8(
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x30, 0x10, 0x00, -128, 0x10, 0x00, 0x00);

  const __m128i i0 = _mm_loadu_si128((const __m128i *)(text));
  const __m128i i1 = _mm_loadu_si128((const __m128i *)(text+16));
  _mm_storeu_si128((__m128i *)(wire), i0);
  _mm_storeu_si128((__m128i *)(wire+16), i1);

  // FIXME: this is and error!
  const __m128i ds00 = _mm_shuffle_epi8(d0, _mm_srli_epi16(i0, 4));
  const __m128i ds01 = _mm_shuffle_epi8(d1, i0);
  const __m128i ds0 = _mm_and_si128(ds00, ds01);

  const __m128i ds10 = _mm_shuffle_epi8(d0, _mm_srli_epi16(i1, 4));
  const __m128i ds11 = _mm_shuffle_epi8(d1, i1);
  const __m128i ds1 = _mm_and_si128(ds10, ds11);

  const uint64_t bm0 = (uint16_t)_mm_movemask_epi8(ds0);
  const uint64_t bm1 = (uint16_t)_mm_movemask_epi8(ds1);
  const uint64_t dm0 =
    (uint16_t)_mm_movemask_epi8(_mm_cmpgt_epi8(ds0, _mm_setzero_si128()));
  const uint64_t dm1 =
    (uint16_t)_mm_movemask_epi8(_mm_cmpgt_epi8(ds1, _mm_setzero_si128()));

  block->backslash = bm0 | (bm1 << 16);
  block->delimiter = dm0 | (dm1 << 16);
}

zone_nonnull_all
static zone_really_inline void copy_quoted_string_block(
  const char *text, uint8_t *wire, string_block_t *block)
{
  const __m128i b = _mm_set1_epi8('\\');
  const __m128i q = _mm_set1_epi8('\"');

  const __m128i i0 = _mm_loadu_si128((const __m128i *)(text));
  const __m128i i1 = _mm_loadu_si128((const __m128i *)(text+16));
  _mm_storeu_si128((__m128i *)(wire), i0);
  _mm_storeu_si128((__m128i *)(wire+16), i1);

  const uint64_t bm0 = (uint16_t)_mm_movemask_epi8(_mm_cmpeq_epi8(i0, b));
  const uint64_t bm1 = (uint16_t)_mm_movemask_epi8(_mm_cmpeq_epi8(i1, b));
  const uint64_t qm0 = (uint16_t)_mm_movemask_epi8(_mm_cmpeq_epi8(i0, q));
  const uint64_t qm1 = (uint16_t)_mm_movemask_epi8(_mm_cmpeq_epi8(i1, q));

  block->backslash = bm0 | (bm1 << 16);
  block->delimiter = qm0 | (qm1 << 16);
}

#endif // STRING_H
