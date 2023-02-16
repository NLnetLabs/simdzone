/*
 * table.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <string.h>

#include "zone.h"

int zone_compare(const void *p1, const void *p2)
{
  const zone_string_t *s1 = p1, *s2 = p2;
  assert(s1 && s1->data && s1->length);
  assert(s2 && s2->data && s2->length);
  int eq;
  const size_t n = s1->length < s2->length ? s1->length : s2->length;
  if ((eq = strncasecmp(s1->data, s2->data, n)) != 0)
    return eq;
  return s1->length < s2->length ? -1 : (s1->length > s2->length ? +1 : 0);
}

extern inline zone_symbol_t *
zone_lookup(const zone_table_t *table, const zone_string_t *string);
