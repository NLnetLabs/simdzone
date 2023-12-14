/*
 * attributes.h -- internal compiler attribute abstractions
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone/attributes.h"

#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#define nonnull(params) zone_nonnull(params)
#define nonnull_all zone_nonnull_all

#if _MSC_VER
# define really_inline __forceinline
# define never_inline __declspec(noinline)
# define warn_unused_result

# define likely(params) (params)
# define unlikely(params) (params)

# define zone_format(params)
# define zone_format_printf(string_index, first_to_check)
#else // _MSC_VER
# define really_inline inline zone_attribute((always_inline))
# define never_inline zone_attribute((noinline))
# if zone_has_attribute(warn_unused_result)
#   define warn_unused_result zone_attribute((warn_unused_result))
# else
#   define warn_unused_result
# endif

# define likely(params) __builtin_expect(!!(params), 1)
# define unlikely(params) __builtin_expect(!!(params), 0)
#endif

#endif // ATTRIBUTES_H
