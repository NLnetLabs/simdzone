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

AC_INIT([simdzone],[0.2.4],[https://github.com/NLnetLabs/simdzone/issues])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

version_info=0:1:0
# This is current:revision:age
# 0.2.4 had 0:1:0
#
#
#   Current  -- the number of the binary API that we're implementing
#   Revision -- which iteration of the implementation of the binary
#               API are we supplying?
#   Age      -- How many previous binary API versions do we also
#               support?
#
# If we release a new version that does not change the binary API,
# increment Revision.
#
# If we release a new version that changes the binary API, but does
# not break programs compiled against the old binary API, increment
# Current and Age.  Set Revision to 0, since this is the first
# implementation of the new API.
#
# Otherwise, we're changing the binary API and breaking backward
# compatibility with old binaries.  Increment Current.  Set Age to 0,
# since we're backward compatible with no previous APIs.  Set Revision
# to 0 too.
AC_SUBST(version_info)

sinclude(acx_nlnetlabs.m4)
m4_include(m4/ax_check_compile_flag.m4)

CFLAGS="$CFLAGS"
m4_version_prereq([2.70], [AC_PROG_CC], [AC_PROG_CC_STDC])

# are we on MinGW?
if uname -s 2>&1 | grep MINGW >/dev/null; then on_mingw="yes"
else
	if echo $host | grep mingw >/dev/null; then on_mingw="yes"
	else on_mingw="no"; fi
fi
if test "$on_mingw" = "yes"; then
    if echo "$host" | $GREP -i -e linux >/dev/null; then
	# link with libssp for the stack protector functions on the windows
	# compile, for the static compile -l:libssp.a could be used.
	# But there is no static option right now for simdzone.
	if test -z "$LIBS"; then LIBS="-lssp"; else LIBS="$LIBS -lssp"; fi
    fi
fi

# allow user to override the -g -O2 flags.
if test "x$CFLAGS" = "x" ; then
ACX_CHECK_COMPILER_FLAG(g, [CFLAGS="$CFLAGS -g"])
ACX_CHECK_COMPILER_FLAG(O2, [CFLAGS="$CFLAGS -O2"])
ACX_CHECK_PIE
fi

ACX_LIBTOOL_C_ONLY

AC_CHECK_HEADERS([endian.h sys/endian.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_DECLS([bswap16,bswap32,bswap64], [], [], [
AC_INCLUDES_DEFAULT
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

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

# GCC and Clang
AX_CHECK_COMPILE_FLAG([-MMD],DEPFLAGS="-MMD -MP")
# Oracle Developer Studio (no -MP)
AX_CHECK_COMPILE_FLAG([-xMMD],DEPFLAGS="-xMMD")

AC_SUBST([DEPFLAGS])

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

HAVE_WESTMERE=NO
HAVE_HASWELL=NO

if test $x86_64 = "yes"; then
  AC_CHECK_HEADER(immintrin.h,,,)
  AX_CHECK_COMPILE_FLAG([-march=westmere],,,[-Werror])
  AX_CHECK_COMPILE_FLAG([-march=haswell],,,[-Werror])

  # Check if the arch instruction set support includes the simd instructions.
  if test $enable_westmere != "no" -a \
          $ax_cv_check_cflags__Werror__march_westmere = "yes" -a \
          $ac_cv_header_immintrin_h = "yes" ; then
    AC_MSG_CHECKING(whether -march=westmere works)
    BAKCFLAGS="$CFLAGS"
    CFLAGS="-march=westmere $CFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([
AC_INCLUDES_DEFAULT
[
#include <stdint.h>
#include <immintrin.h>

int main(int argc, char *argv[])
{
  (void)argv;
  uint64_t popcnt = _mm_popcnt_u64((uint64_t)argc);
  return popcnt == 11;
}
]])
],[
    AC_DEFINE(HAVE_WESTMERE, 1, [Wether or not to compile support for SSE4.2])
    HAVE_WESTMERE=WESTMERE
    AC_MSG_RESULT(yes)
],[
    AC_MSG_RESULT(no)
])
    CFLAGS="$BAKCFLAGS"
  fi

  if test $enable_haswell != "no" -a \
          $ax_cv_check_cflags__Werror__march_haswell = "yes" -a \
          $ac_cv_header_immintrin_h = "yes" ; then
    AC_MSG_CHECKING(whether -march=haswell works)
    BAKCFLAGS="$CFLAGS"
    CFLAGS="-march=haswell $CFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([
AC_INCLUDES_DEFAULT
[
#include <stdint.h>
#include <immintrin.h>

int main(int argc, char *argv[])
{
  (void)argv;
  int argc32x8[8] = { argc, 0, 0, 0, 0, 0, 0, 0 };
  __m256i argc256 = _mm256_loadu_si256((__m256i *)argc32x8);
  return _mm256_testz_si256(argc256, _mm256_set1_epi8(11));
}
]])
],[
    AC_DEFINE(HAVE_HASWELL, 1, [Wether or not to compile support for AVX2])
    HAVE_HASWELL=HASWELL
    AC_MSG_RESULT(yes)
],[
    AC_MSG_RESULT(no)
])
    CFLAGS="$BAKCFLAGS"
  fi
fi

AC_CHECK_FUNCS([realpath],,[
	AC_CHECK_FUNCS([_fullpath],,[
		AC_MSG_ERROR([realpath and _fullpath are not available])
	])
])

AC_SUBST([HAVE_ENDIAN_H])
AC_SUBST([HAVE_WESTMERE])
AC_SUBST([HAVE_HASWELL])

AH_BOTTOM([
/* Defines _XOPEN_SOURCE and _POSIX_C_SOURCE implicitly in features.h */
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif
])

AC_OUTPUT
