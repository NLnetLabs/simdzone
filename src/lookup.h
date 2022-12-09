/*
 * lookup.h -- some useful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_LOOKUP_H
#define ZONE_LOOKUP_H

#include "zone.h"

static inline int zone_mapcmp(const void *key, const void *member)
{
  const zone_symbol_t *s1 = key, *s2 = member;
  assert(s1 && s1->key.data && s1->key.length);
  assert(s2 && s2->key.data && s2->key.length);
  int eq;
  const size_t n = s1->key.length < s2->key.length ? s1->key.length : s2->key.length;
  if ((eq = strncasecmp(s1->key.data, s2->key.data, n)) != 0)
    return eq;
  return s1->key.length < s2->key.length ? -1 : (s1->key.length > s2->key.length ? +1 : 0);
}

static inline zone_symbol_t *zone_lookup(
  const zone_table_t *table, const zone_string_t *string)
{
  const zone_symbol_t key = { *string, 0 };

  return bsearch(
    &key, table->symbols, table->length, sizeof(table->symbols[0]), zone_mapcmp);
}

#endif // ZONE_LOOKUP_H
