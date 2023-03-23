/*
 * diagnostic.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef DIAGNOSTIC_H
#define DIAGNOSTIC_H

#if _MSC_VER
# define diagnostic_push() \
           __pragma(warning(push))
# define msvc_diagnostic_ignored(warning) \
           __pragma(warning(disable: ## warning))
# define diagnostic_pop() \
           __pragma(warning(pop))
#elif __GNUC__
# define stringify(x) #x
# define paste(flag, warning) stringify(flag ## warning)
# define pragma(x) _Pragma(#x)
# define diagnostic_ignored(warning) pragma(warning)

# define diagnostic_push() _Pragma("GCC diagnostic push")
# define diagnostic_pop() _Pragma("GCC diagnostic pop")
# if __clang__
#   define clang_diagnostic_ignored(warning) \
      diagnostic_ignored(GCC diagnostic ignored paste(-W,warning))
# elif __GNUC__ && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 406
#   define gcc_diagnostic_ignored(warning) \
      diagnostic_ignored(GCC diagnostic ignored paste(-W,warning))
#endif
#endif

#if !defined diagnostic_push
# define diagnostic_push()
# define diagnostic_pop()
#endif

#if !defined gcc_diagnostic_ignored
# define gcc_diagnostic_ignored(warning)
#endif

#if !defined clang_diagnostic_ignored
# define clang_diagnostic_ignored(warning)
#endif

#if !defined msvc_diagnostic_ignored
# define msvc_diagnostic_ignored(warning)
#endif

#endif // DIAGNOSTIC_H
