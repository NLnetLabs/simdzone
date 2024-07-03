/*
 * bits-haswell.c -- test Haswell specific bit manipulation instructions
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>

#include "attributes.h"
#include "haswell/bits.h"

void test_haswell_trailing_zeroes(void **state)
{
  (void)state;
  fprintf(stderr, "test_haswell_trailing_zeroes\n");
  for (uint64_t shift = 0; shift < 63; shift++) {
    uint64_t bit = 1llu << shift;
    uint64_t tz = trailing_zeroes(bit);
    assert_int_equal(tz, shift);
  }
}

void test_haswell_leading_zeroes(void **state)
{
  (void)state;
  fprintf(stderr, "test_haswell_leading_zeroes\n");
  for (uint64_t shift = 0; shift < 63; shift++) {
    const uint64_t bit = 1llu << shift;
    uint64_t lz = leading_zeroes(bit);
    assert_int_equal(lz, 63 - shift);
  }
}

void test_haswell_prefix_xor(void **state)
{
  (void)state;
  fprintf(stderr, "test_haswell_prefix_xor\n");
  // "0001 0001 0000 0101 0000 0110 0000 0000"
  uint64_t mask =
    (1llu << 28) | (1llu << 24) |
    (1llu << 18) | (1llu << 16) |
    (1llu << 10) | (1llu <<  9);
  // "0000 1111 0000 0011 0000 0010 0000 0000"
  uint64_t prefix_mask =
    (1llu << 27) | (1llu << 26) | (1llu << 25) | (1llu << 24) |
    (1llu << 17) | (1llu << 16) |
    (1llu <<  9);

  assert_int_equal(prefix_xor(mask), prefix_mask);
}

void test_haswell_add_overflow(void **state)
{
  (void)state;
  fprintf(stderr, "test_haswell_add_overflow\n");
  uint64_t all_ones = UINT64_MAX;
  uint64_t result = 0;
  uint64_t overflow = add_overflow(all_ones, 2llu, &result);
  assert_int_equal(result, 1llu);
  assert_true(overflow);
  overflow = add_overflow(all_ones, 1llu, &result);
  assert_int_equal(result, 0llu);
  assert_true(overflow);
  overflow = add_overflow(all_ones, 0llu, &result);
  assert_int_equal(result, all_ones);
  assert_false(overflow);
}
