/*
 * heap.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef HEAP_H
#define HEAP_H

#include "zone.h"

ZONE_EXPORT void zone_free(
  zone_parser_t *parser, void *ptr)
zone_nonnull((1));

ZONE_EXPORT void *zone_malloc(
  zone_parser_t *parser, size_t size)
zone_nonnull((1))
zone_allocator(zone_free, 2)
zone_attribute((alloc_size(2)));

ZONE_EXPORT void *zone_realloc(
  zone_parser_t *parser, void *ptr, size_t size)
zone_nonnull((1))
zone_allocator(zone_free, 2)
zone_attribute((alloc_size(3)));

ZONE_EXPORT char *zone_strdup(
  zone_parser_t *parser, const char *str)
zone_nonnull_all()
zone_allocator(zone_free, 2);

#endif // HEAP_H
