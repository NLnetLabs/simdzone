/*
 * bits.c -- test bit manipulation instructions
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <cmocka.h>

#include "attributes.h"
#include "fallback/bits.h"

void test_fallback_trailing_zeroes(void **state)
{
  (void)state;
  fprintf(stderr, "test_fallback_trailing_zeroes\n");
  for (uint64_t shift = 0; shift < 63; shift++) {
    uint64_t bit = 1llu << shift;
    uint64_t tz = trailing_zeroes(bit);
    assert_int_equal(tz, shift);
  }
}

void test_fallback_leading_zeroes(void **state)
{
  (void)state;
  fprintf(stderr, "test_fallback_leading_zeroes\n");
  for (uint64_t shift = 0; shift < 63; shift++) {
    const uint64_t bit = 1llu << shift;
    uint64_t lz = leading_zeroes(bit);
    assert_int_equal(lz, 63 - shift);
  }
}
