/*
 * test_westmere.c -- test westmere support
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

static inline uint64_t count_ones(uint64_t input_num) {
  return (uint64_t)_mm_popcnt_u64(input_num);
}

int
main(void)
{
  uint64_t x = count_ones(0x1234);
  (void)x;
  return 0;
}
