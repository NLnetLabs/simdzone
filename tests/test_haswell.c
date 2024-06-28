/*
 * test_haswell.c -- test haswell support
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdint.h>
#include <immintrin.h>

#if defined __GNUC__
# define zone_has_gnuc(major, minor)     ((__GNUC__ > major) || (__GNUC__ == major && __GNUC_MINOR__ >= minor))
#else
# define zone_has_gnuc(major, minor) (0)
#endif

#if defined __has_attribute
# define zone_has_attribute(params) __has_attribute(params)
#else
# define zone_has_attribute(params) (0)
#endif

#if _MSC_VER
# define really_inline __forceinline
#else // _MSC_VER
# if (zone_has_attribute(always_inline) || zone_has_gnuc(3, 1)) && ! defined __NO_INLINE__
#   define really_inline inline __attribute__((always_inline))
# else
#   define really_inline inline
# endif
#endif

typedef struct { __m256i chunks[1]; } simd_8x_t;
static really_inline void simd_loadu_8x(simd_8x_t *simd, const void *address)
{
  simd->chunks[0] = _mm256_loadu_si256((const __m256i *)(address));
}

int
main(void)
{
  uint64_t addr[4] = {0x1, 0x2, 0x3, 0x4};
  simd_8x_t simd;
  simd_loadu_8x(&simd, addr);
  (void)simd;
  return 0;
}
