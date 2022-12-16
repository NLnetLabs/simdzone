/*
 * zone.h -- compiler attribute abstractions for (DNS) zone file parser
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ZONE_ATTRIBUTES_H
#define ZONE_ATTRIBUTES_H

#if defined __has_attribute
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#elif zone_gnuc
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#else
# define zone_has_attribute(x)
# define zone_attribute(x)
#endif

#if __clang__
# define zone_clang \
  (__clang_major__ * 100000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif __GCC__
# define zone_gcc \
  (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#if defined __has_attribute
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#elif zone_gcc
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#else
# define zone_has_attribute(x)
# define zone_attribute(x)
#endif

#define zone_nonnull(x) zone_attribute((__nonnull__ x))
#define zone_nonnull_all() zone_attribute((__nonnull__))

#if _MSC_VER
# define zone_always_inline() __forceinline
# define zone_never_inline() __declspec(noinline)
# define zone_unlikely(x)
#else
# define zone_always_inline() zone_attribute((always_inline))
# define zone_never_inline() zone_attribute((noinline))
# define zone_unlikely(x) __builtin_expect((x), 0)
#endif

#endif // ZONE_ATTRIBUTES_H
