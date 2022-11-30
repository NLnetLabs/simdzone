/*
 * bits.h -- Haswell specific implementation of bit manipulation instructions
 *
 * Copyright (c) 2022 simdjson
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef HASWELL_BITS_H
#define HASWELL_BITS_H

#include <stdbool.h>
#include <stdint.h>
#include <immintrin.h>

static inline bool add_overflow(uint64_t value1, uint64_t value2, uint64_t *result) {
  return __builtin_uaddll_overflow(value1, value2, (unsigned long long *)result);
}

static inline uint64_t count_ones(uint64_t bits) {
  return _popcnt64(bits);
}

static inline uint64_t trailing_zeroes(uint64_t bits) {
  return __builtin_ctzll(bits);
}

// result might be undefined when bits is zero
static inline uint64_t clear_lowest_bit(uint64_t bits) {
  return bits & (bits - 1);
}

static inline uint64_t leading_zeroes(uint64_t bits) {
  return __builtin_clzll(bits);
}

static inline uint64_t prefix_xor(const uint64_t bitmask) {
  // There should be no such thing with a processor supporting avx2
  // but not clmul.
  __m128i all_ones = _mm_set1_epi8('\xFF');
  __m128i result = _mm_clmulepi64_si128(_mm_set_epi64x(0ULL, bitmask), all_ones, 0);
  return _mm_cvtsi128_si64(result);
}

#endif // HASWELL_BITS_H
