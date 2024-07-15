/*
 * westmere.test.c -- test if -march=westmere works
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdint.h>
#include <immintrin.h>

int main(int argc, char *argv[])
{
  (void)argv;
  uint64_t popcnt = _mm_popcnt_u64((uint64_t)argc);
  return popcnt == 11;
}
