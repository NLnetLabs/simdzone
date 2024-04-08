/*
 * attributes.h -- internal compiler attribute abstractions
 *
 * Copyright (c) 2023-2024, NLnet Labs. All rights reserved.
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

#else // _MSC_VER
# if zone_has_attribute(always_inline) || zone_has_gnuc(3, 1)
#   define really_inline inline __attribute__((always_inline))
# else
#   define really_inline inline
# endif

# if zone_has_attribute(noinline) || zone_has_gnuc(2, 96)
#   define never_inline __attribute__((noinline))
# else
#   define never_inline
# endif

# if zone_has_attribute(warn_unused_result)
#   define warn_unused_result __attribute__((warn_unused_result))
# else
#   define warn_unused_result
# endif

# define likely(params) __builtin_expect(!!(params), 1)
# define unlikely(params) __builtin_expect(!!(params), 0)
#endif

#endif // ATTRIBUTES_H
