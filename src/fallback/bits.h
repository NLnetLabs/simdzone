/*
 * bits.h -- bit manipulation instructions
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef BITS_H
#define BITS_H

#if _MSC_VER
#include <intrin.h>

static really_inline uint64_t trailing_zeroes(uint64_t mask)
{
  unsigned long index;
  if (_BitScanForward64(&index, mask))
    return index;
  else
    return 64;
}

static really_inline uint64_t leading_zeroes(uint64_t mask)
{
  unsigned long index;
  if (_BitScanReverse64(&index, mask))
    return 63 - index;
  else
    return 64;
}
#else
static really_inline uint64_t trailing_zeroes(uint64_t mask)
{
  return (uint64_t)__builtin_ctzll(mask);
}

static really_inline uint64_t leading_zeroes(uint64_t mask)
{
  return (uint64_t)__builtin_clzll(mask);
}
#endif // _MSC_VER
#endif // BITS_H
