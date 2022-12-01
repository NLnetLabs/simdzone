/*
 * haswell.h -- SIMD abstractions targeting AVX2
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef HASWELL_SIMD_H
#define HASWELL_SIMD_H

#include <stdint.h>
#include <immintrin.h>

#include "classes.h"

// operate on 64-bit blocks. always.
typedef struct { __m256i chunks[2]; } input_t;

typedef uint8_t table_t[32];

#define TABLE(v00, v01, v02, v03, v04, v05, v06, v07, \
              v08, v09, v0a, v0b, v0c, v0d, v0e, v0f) \
  {                                                   \
    v00, v01, v02, v03, v04, v05, v06, v07,           \
    v08, v09, v0a, v0b, v0c, v0d, v0e, v0f,           \
    v00, v01, v02, v03, v04, v05, v06, v07,           \
    v08, v09, v0a, v0b, v0c, v0d, v0e, v0f            \
  }

static const table_t mask_hi = TABLE(
  /* 0x00 */  0x80 | BLANK | NEWLINE,
  /* 0x10 */  0x00,
  /* 0x20 */  0x40 | BLANK | QUOTE | PARENTHESES,
  /* 0x30 */  0x20 | SEMICOLON,
  /* 0x40 */  0x00,
  /* 0x50 */  0x10 | BACKSLASH,
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

static const table_t mask_lo = TABLE(
  /* 0x00 */  0x40 | BLANK,
  /* 0x01 */  0x00,
  /* 0x02 */  0x40 | QUOTE | SEMICOLON,
  /* 0x03 */  0x00,
  /* 0x04 */  0x00,
  /* 0x05 */  0x00,
  /* 0x06 */  0x00,
  /* 0x07 */  0x00,
  /* 0x08 */  0x40 | PARENTHESES,
  /* 0x09 */  0xc0 | BLANK | PARENTHESES,
  /* 0x0a */  0x80 | NEWLINE,
  /* 0x0b */  0x20 | SEMICOLON,
  /* 0x0c */  0x10 | BACKSLASH,
  /* 0x0d */  0x80 | BLANK,
  /* 0x0e */  0x00,
  /* 0x0f */  0x00
);

static __m256i classify_chunk(const uint8_t *ptr)
{
  const __m256i input_lo =
    _mm256_loadu_si256((const __m256i*)ptr);
  const __m256i input_hi =
    _mm256_and_si256(_mm256_srli_epi16(input_lo, 4), _mm256_set1_epi8(0x0f));

  const __m256i shuffled_hi = _mm256_shuffle_epi8(*(const __m256i *)mask_lo, input_lo);
  const __m256i shuffled_lo = _mm256_shuffle_epi8(*(const __m256i *)mask_hi, input_hi);

  __m256i result = _mm256_and_si256(shuffled_lo, shuffled_hi);
  result = _mm256_subs_epu8(result, _mm256_set1_epi8(0x10));
  result = _mm256_and_si256(result, _mm256_set1_epi8(0x0f));
  return result;
}

static inline void classify(input_t *input, const uint8_t *ptr)
{
  input->chunks[0] = classify_chunk(ptr);
  input->chunks[1] = classify_chunk(ptr+32);
}

static inline uint64_t find(const input_t *input, uint8_t key)
{
  const __m256i k = _mm256_set1_epi8(key);

  const __m256i r0 = _mm256_cmpeq_epi8(input->chunks[0], k);
  const __m256i r1 = _mm256_cmpeq_epi8(input->chunks[1], k);

  const uint64_t m0 = (uint32_t)_mm256_movemask_epi8(r0);
  const uint64_t m1 = _mm256_movemask_epi8(r1);

  return m0 | (m1 << 32);
}

static inline uint64_t find_any(const input_t *input, uint_fast8_t key)
{
  const __m256i k = _mm256_set1_epi8(key);

  const __m256i r0 = _mm256_cmpgt_epi8(input->chunks[0], k);
  const __m256i r1 = _mm256_cmpgt_epi8(input->chunks[1], k);

  const uint64_t m0 = (uint32_t)_mm256_movemask_epi8(r0);
  const uint64_t m1 = _mm256_movemask_epi8(r1);

  return m0 | (m1 << 32);
}

#endif // HASWELL_SIMD_H
