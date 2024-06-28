#
# configure.ac -- Autoconf script for simdzone
#
# Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# This file is intended for inclusion by configure.ac in NSD. Support for any
# platform not supported by NSD here is undesirable. Builds for standalone use
# or development/testing are required to use CMake.

AC_INIT([simdzone],[0.1.0],[https://github.com/NLnetLabs/simdzone/issues])

AC_CONFIG_HEADERS([config.h:src/config.h.in])
AC_CONFIG_FILES([Makefile])

m4_include(m4/ax_check_compile_flag.m4)
m4_version_prereq([2.70], [AC_PROG_CC], [AC_PROG_CC_STDC])

AC_CHECK_HEADER(endian.h, AC_DEFINE(HAVE_ENDIAN_H, 1, [Wether or not have the <endian.h> header file]))

AC_ARG_ENABLE(westmere, AS_HELP_STRING([--disable-westmere],[Disable Westmere (SSE4.2) kernel]))
case "$enable_westmere" in
  no)    enable_westmere=no ;;
  yes|*) enable_westmere=yes ;;
esac

AC_ARG_ENABLE(haswell, AS_HELP_STRING([--disable-haswell],[Disable Haswell (AVX2) kernel]))
case "$enable_haswell" in
  no)    enable_haswell=no ;;
  yes|*) enable_haswell=yes ;;
esac

# Figure out the canonical target architecture.
AC_CANONICAL_TARGET

# Multiple instruction sets may be supported by a specific architecture.
# e.g. x86_64 may (or may not) support any of SSE42, AVX2 and AVX-512. The
# best instruction set is automatically selected at runtime, but the compiler
# may or may not support generating code for an instruction set.
case "$target" in
  *amd64*)  x86_64=yes ;;
  *x86_64*) x86_64=yes ;;
  *)        x86_64=no  ;;
esac

if test $x86_64 = "yes"; then
  AC_CHECK_HEADER(immintrin.h,,,)
  AX_CHECK_COMPILE_FLAG([-march=westmere],,,[-Werror])
  AX_CHECK_COMPILE_FLAG([-march=haswell],,,[-Werror])

  # Check if the arch instruction set support includes the simd instructions.
  if test $ax_cv_check_cflags__Werror__march_westmere = "yes" -a \
          $ac_cv_header_immintrin_h = "yes" ; then
  AC_MSG_CHECKING(whether -march=westmere works)
  BAKCFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -march=westmere"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
AC_INCLUDES_DEFAULT
[
#include <stdint.h>
#include <immintrin.h>

#if defined __GNUC__
# define zone_has_gnuc(major, minor) \
    ((__GNUC__ > major) || (__GNUC__ == major && __GNUC_MINOR__ >= minor))
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
]
], [[
	uint64_t x = count_ones(0x1234);
	(void)x;
]])],[march_westmere_works="yes"],[march_westmere_works="no"])
  CFLAGS="$BAKCFLAGS"
  AC_MSG_RESULT($march_westmere_works)
  fi

  if test $ax_cv_check_cflags__Werror__march_haswell = "yes" -a \
          $ac_cv_header_immintrin_h = "yes" ; then
  AC_MSG_CHECKING(whether -march=haswell works)
  BAKCFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -march=haswell"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
AC_INCLUDES_DEFAULT
[
#include <stdint.h>
#include <immintrin.h>

#if defined __GNUC__
# define zone_has_gnuc(major, minor) \
    ((__GNUC__ > major) || (__GNUC__ == major && __GNUC_MINOR__ >= minor))
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
]
], [[
	uint64_t addr[4] = {0x1, 0x2, 0x3, 0x4};
	simd_8x_t simd;
	simd_loadu_8x(&simd, addr);
	(void)simd;
]])],[march_haswell_works="yes"],[march_haswell_works="no"])
  CFLAGS="$BAKCFLAGS"
  AC_MSG_RESULT($march_haswell_works)
  fi

  if test $enable_westmere != "no" -a \
          $ac_cv_header_immintrin_h = "yes" -a \
          $ax_cv_check_cflags__Werror__march_westmere = "yes" -a \
          $march_westmere_works = "yes"
  then
    AC_DEFINE(HAVE_WESTMERE, 1, [Wether or not to compile support for SSE4.2])
    HAVE_WESTMERE=WESTMERE
  else
    HAVE_WESTMERE=NO
  fi

  if test $enable_haswell != "no" -a \
          $ac_cv_header_immintrin_h = "yes" -a \
          $ax_cv_check_cflags__Werror__march_haswell = "yes" -a \
          $march_haswell_works = "yes"
  then
    AC_DEFINE(HAVE_HASWELL, 1, [Wether or not to compile support for AVX2])
    HAVE_HASWELL=HASWELL
  else
    HAVE_HASWELL=NO
  fi
fi

AC_SUBST([HAVE_WESTMERE])
AC_SUBST([HAVE_HASWELL])

AC_OUTPUT
