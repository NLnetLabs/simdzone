/*
 * attributes.h -- compiler attribute abstractions
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ZONE_ATTRIBUTES_H
#define ZONE_ATTRIBUTES_H

#if __clang__
# define zone_clang \
  (__clang_major__ * 100000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif __GCC__
# define zone_gcc \
  (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#if defined __has_attribute
# define zone_has_attribute(params) __has_attribute(params)
# define zone_attribute(params) __attribute__(params)
#elif zone_gcc
# define zone_has_attribute(params) __has_attribute(params)
# define zone_attribute(params) __attribute__(params)
#else
# define zone_has_attribute(params)
# define zone_attribute(params)
#endif

#if defined __has_attribute
# define zone_has_attribute(params) __has_attribute(params)
# define zone_attribute(params) __attribute__(params)
#elif zone_gcc
# define zone_has_attribute(params) __has_attribute(params)
# define zone_attribute(params) __attribute__(params)
#else
# define zone_has_attribute(params)
# define zone_attribute(params)
#endif

#define zone_nonnull(params) zone_attribute((__nonnull__ params))
#define zone_nonnull_all zone_attribute((__nonnull__))

#if _MSC_VER
# define zone_really_inline __forceinline
# define zone_never_inline __declspec(noinline)
# define zone_warn_unused_result

# define zone_likely(params) (params)
# define zone_unlikely(params) (params)

# define zone_format(params)
# define zone_format_printf(string_index, first_to_check)
#else // _MSC_VER
# define zone_really_inline inline zone_attribute((always_inline))
# define zone_never_inline zone_attribute((noinline))
# if zone_has_attribute(warn_unused_result)
#   define zone_warn_unused_result zone_attribute((warn_unused_result))
# else
#   define zone_warn_unused_result
# endif

# define zone_likely(params) __builtin_expect(!!(params), 1)
# define zone_unlikely(params) __builtin_expect(!!(params), 0)

# if zone_has_attribute(format)
#   define zone_format(params) zone_attribute((__format__ params))
#   if __MINGW32__
#     if __MINGW_PRINTF_FORMAT
#       define zone_format_printf(string_index, first_to_check) \
          zone_format((__MINGW_PRINTF_FORMAT, string_index, first_to_check))
#     else
#       define zone_format_printf(string_index, first_to_check) \
          zone_format((gnu_printf, string_index, first_to_check))
#     endif
#   else
#     define zone_format_printf(string_index, first_to_check) \
        zone_format((printf, string_index, first_to_check))
#   endif
# else
#   define zone_format(params)
#   define zone_format_printf(string_index, first_to_check)
# endif
#endif

#endif // ZONE_ATTRIBUTES_H
