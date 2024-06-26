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

  if test $enable_westmere != "no" -a \
          $ac_cv_header_immintrin_h = "yes" -a \
          $ax_cv_check_cflags__Werror__march_westmere = "yes"
  then
    AC_DEFINE(HAVE_WESTMERE, 1, [Wether or not to compile support for SSE4.2])
    HAVE_WESTMERE=WESTMERE
  else
    HAVE_WESTMERE=NO
  fi

  if test $enable_haswell != "no" -a \
          $ac_cv_header_immintrin_h = "yes" -a \
          $ax_cv_check_cflags__Werror__march_haswell = "yes"
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
