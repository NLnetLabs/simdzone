/*
 * bits.c -- test bit manipulation instructions
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <cmocka.h>

#include "config.h"
#include "attributes.h"
#include "isadetection.h"

#if _MSC_VER
# define strcasecmp(s1, s2) _stricmp(s1, s2)
# define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#else
#include <strings.h>
#endif

#include "diagnostic.h"

struct kernel {
  const char *name;
  uint32_t instruction_set;
  void (*test_trailing_zeroes)(void **state);
  void (*test_leading_zeroes)(void **state);
  void (*test_prefix_xor)(void **state);
  void (*test_add_overflow)(void **state);
};

#if HAVE_HASWELL
extern void test_haswell_trailing_zeroes(void **);
extern void test_haswell_leading_zeroes(void **);
extern void test_haswell_prefix_xor(void **);
extern void test_haswell_add_overflow(void **);
#endif

#if HAVE_WESTMERE
extern void test_westmere_trailing_zeroes(void **);
extern void test_westmere_leading_zeroes(void **);
extern void test_westmere_prefix_xor(void **);
extern void test_westmere_add_overflow(void **);
#endif

extern void test_fallback_trailing_zeroes(void **);
extern void test_fallback_leading_zeroes(void **);

static const struct kernel kernels[] = {
#if HAVE_HASWELL
  { "haswell", AVX2,     &test_haswell_trailing_zeroes,
                         &test_haswell_leading_zeroes,
                         &test_haswell_prefix_xor,
                         &test_haswell_add_overflow },
#endif
#if HAVE_WESTMERE
  { "westmere", SSE42,   &test_westmere_trailing_zeroes,
                         &test_westmere_leading_zeroes,
                         &test_westmere_prefix_xor,
                         &test_westmere_add_overflow },
#endif
  { "fallback", DEFAULT, &test_fallback_trailing_zeroes,
                         &test_fallback_leading_zeroes,
                         0, 0 }
};

static inline const struct kernel *
select_kernel(void)
{
  const char *preferred;
  const uint32_t supported = detect_supported_architectures();
  const size_t length = sizeof(kernels)/sizeof(kernels[0]);
  size_t count = 0;

diagnostic_push()
msvc_diagnostic_ignored(4996)
  preferred = getenv("ZONE_KERNEL");
diagnostic_pop()

  if (preferred) {
    for (; count < length; count++)
      if (strcasecmp(preferred, kernels[count].name) == 0)
        break;
    if (count == length)
      count = 0;
  }

  for (; count < length; count++)
    if ((kernels[count].instruction_set & supported) == (kernels[count].instruction_set))
      return &kernels[count];

  return &kernels[length - 1];
}

/*!cmocka */
void test_trailing_zeroes(void **state)
{
  const struct kernel *kernel = select_kernel();
  assert(kernel);
  kernel->test_trailing_zeroes(state);
}

/*!cmocka */
void test_leading_zeroes(void **state)
{
  const struct kernel *kernel = select_kernel();
  assert(kernel);
  kernel->test_leading_zeroes(state);
}

/*!cmocka */
void test_prefix_xor(void **state)
{
  const struct kernel *kernel = select_kernel();
  assert(kernel);
  if (kernel->test_prefix_xor)
    kernel->test_prefix_xor(state);
  else
    assert_true(1);
}

/*!cmocka */
void test_add_overflow(void **state)
{
  const struct kernel *kernel = select_kernel();
  assert(kernel);
  if (kernel->test_add_overflow)
    kernel->test_add_overflow(state);
  else
    assert_true(1);
}
