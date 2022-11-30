/*
 * simd.h -- SIMD abstractions targeting SSE4.2
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef WESTMERE_SIMD_H
#define WESTMERE_SIMD_H

#include <stdint.h>
#include <immintrin.h>

// operate on 64-bit blocks. always.
typedef struct { __m128i chunks[4]; } input_t;

static inline void load(input_t *input, const uint8_t *ptr)
{
  input->chunks[0] = _mm_loadu_si128((const __m128i *)ptr);
  input->chunks[1] = _mm_loadu_si128((const __m128i *)(ptr+16));
  input->chunks[2] = _mm_loadu_si128((const __m128i *)(ptr+32));
  input->chunks[3] = _mm_loadu_si128((const __m128i *)(ptr+48));
}

static inline uint64_t find(const input_t *input, uint8_t key)
{
  const __m128i k = _mm_set1_epi8(key);

  const __m128i r0 = _mm_cmpeq_epi8(input->chunks[0], k);
  const __m128i r1 = _mm_cmpeq_epi8(input->chunks[1], k);
  const __m128i r2 = _mm_cmpeq_epi8(input->chunks[2], k);
  const __m128i r3 = _mm_cmpeq_epi8(input->chunks[3], k);

  const uint64_t m0 = (uint16_t)_mm_movemask_epi8(r0);
  const uint64_t m1 = (uint16_t)_mm_movemask_epi8(r1);
  const uint64_t m2 = (uint16_t)_mm_movemask_epi8(r2);
  const uint64_t m3 = _mm_movemask_epi8(r3);

  return m0 | (m1 << 16) | (m2 << 32) | (m3 << 48);
}


typedef uint8_t table_t[16];

#define TABLE(v00, v01, v02, v03, v04, v05, v06, v07, \
              v08, v09, v0a, v0b, v0c, v0d, v0e, v0f) \
  {                                                   \
    v00, v01, v02, v03, v04, v05, v06, v07,           \
    v08, v09, v0a, v0b, v0c, v0d, v0e, v0f            \
  }

static inline uint64_t find_any(const input_t *input, const table_t table)
{
  const __m128i t = _mm_loadu_si128((const __m128i *)table);

  const __m128i r0 = _mm_cmpeq_epi8(
    _mm_shuffle_epi8(t, input->chunks[0]), input->chunks[0]);
  const __m128i r1 = _mm_cmpeq_epi8(
    _mm_shuffle_epi8(t, input->chunks[1]), input->chunks[1]);
  const __m128i r2 = _mm_cmpeq_epi8(
    _mm_shuffle_epi8(t, input->chunks[2]), input->chunks[2]);
  const __m128i r3 = _mm_cmpeq_epi8(
    _mm_shuffle_epi8(t, input->chunks[3]), input->chunks[3]);

  const uint64_t m0 = (uint16_t)_mm_movemask_epi8(r0);
  const uint64_t m1 = (uint16_t)_mm_movemask_epi8(r1);
  const uint64_t m2 = (uint16_t)_mm_movemask_epi8(r2);
  const uint64_t m3 = _mm_movemask_epi8(r3);

  return m0 | (m1 << 16) | (m2 << 32) | (m3 << 48);
}

#endif // WESTMERE_SIMD_H
