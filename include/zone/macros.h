/*
 * macros.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ZONE_MACROS_H
#define ZONE_MACROS_H

#if _MSC_VER
# define zone_diagnostic_push() \
           __pragma(warning(push))
# define zone_msvc_diagnostic_ignored(warning) \
           __pragma(warning(disable: ## warning))
# define zone_diagnostic_pop() \
           __pragma(warning(pop))
#elif __GNUC__
# define zone_stringify(x) #x
# define zone_paste(flag, warning) zone_stringify(flag ## warning)
# define zone_pragma(x) _Pragma(#x)
# define zone_diagnostic_ignored(warning) zone_pragma(warning)

# define zone_diagnostic_push() _Pragma("GCC diagnostic push")
# define zone_diagnostic_pop() _Pragma("GCC diagnostic pop")
# if __clang__
#   define zone_clang_diagnostic_ignored(warning) \
      zone_diagnostic_ignored(GCC diagnostic ignored zone_paste(-W,warning))
# elif __GNUC__ && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 406
#   define zone_gcc_diagnostic_ignored(warning) \
      zone_diagnostic_ignored(GCC diagnostic ignored zone_paste(-W,warning))
#endif
#endif

#if !defined zone_diagnostic_push
# define zone_diagnostic_push()
# define zone_diagnostic_pop()
#endif

#if !defined zone_gcc_diagnostic_ignored
# define zone_gcc_diagnostic_ignored(warning)
#endif

#if !defined zone_clang_diagnostic_ignored
# define zone_clang_diagnostic_ignored(warning)
#endif

#if !defined zone_msvc_diagnostic_ignored
# define zone_msvc_diagnostic_ignored(warning)
#endif

#endif // ZONE_MACROS_H
