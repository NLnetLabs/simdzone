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

// operate on 64-bit blocks. always.
typedef struct { __m256i chunks[2]; } input_t;

static inline void load(input_t *input, const uint8_t *ptr)
{
  input->chunks[0] = _mm256_loadu_si256((const __m256i *)(ptr));
  input->chunks[1] = _mm256_loadu_si256((const __m256i *)(ptr+32));
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


typedef uint8_t table_t[32];

#define TABLE(v00, v01, v02, v03, v04, v05, v06, v07, \
              v08, v09, v0a, v0b, v0c, v0d, v0e, v0f) \
  {                                                   \
    v00, v01, v02, v03, v04, v05, v06, v07,           \
    v08, v09, v0a, v0b, v0c, v0d, v0e, v0f,           \
    v00, v01, v02, v03, v04, v05, v06, v07,           \
    v08, v09, v0a, v0b, v0c, v0d, v0e, v0f            \
  }

static inline uint64_t find_any(const input_t *input, const table_t table)
{
  const __m256i t = _mm256_loadu_si256((const __m256i *)table);

  const __m256i r0 = _mm256_cmpeq_epi8(
    _mm256_shuffle_epi8(t, input->chunks[0]), input->chunks[0]);
  const __m256i r1 = _mm256_cmpeq_epi8(
    _mm256_shuffle_epi8(t, input->chunks[1]), input->chunks[1]);

  const uint64_t m0 = (uint32_t)_mm256_movemask_epi8(r0);
  const uint64_t m1 = _mm256_movemask_epi8(r1);

  return m0 | (m1 << 32);
}

#endif // HASWELL_SIMD_H
