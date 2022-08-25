/*
 * lookup.h -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_LOOKUP_H
#define ZONE_LOOKUP_H

#include "zone.h"

static inline int zone_mapesccmp(const void *key, const void *member)
{
  const zone_key_value_t *kv1 = key, *kv2 = member;
  assert(kv1 && kv1->name && kv1->length);
  assert(kv2 && kv2->name && kv2->length);

  size_t i1 = 0, i2 = 0;
  const char *s1 = kv1->name, *s2 = kv2->name;
  const size_t n1 = kv1->length, n2 = kv2->length;

  for (; i1 < n1 && i2 < n2; i2++) {
    if ((s1[i1]|0x20) == (s2[i2]|0x20)) {
      i1++;
    } else if (s1[i1] != '\\') {
      return s1[i1] - s2[i2];
    } else {
      char c;
      size_t n;

      if (n1 - i1 > 3 && (s1[i1+1] >= '0' && s1[i1+1] <= '2') &&
                         (s1[i1+2] >= '0' && s1[i1+2] <= '5') &&
                         (s1[i1+3] >= '0' && s1[i1+3] <= '5'))
      {
        c = (s1[i1+1]-'0') * 100 + (s1[i1+2]-'0') * 10 + (s1[i1+3]-'0');
        n = 4;
      } else if (n1 - i1 > 1) {
        c = s1[i1+1];
        n = 2;
      } else {
        c = s1[i1];
        n = 1;
      }

      if ((c|0x20) == (s2[i2]|0x20))
        return c - s2[i2];
      i1 += n;
    }
  }

  if (i1 == n1 && i2 == n2)
    return 0;
  else if (i1 < n1)
    return -1;
  else
    return +1;
}

static inline int zone_mapcmp(const void *key, const void *member)
{
  const zone_key_value_t *k1 = key, *k2 = member;
  assert(k1 && k1->name && k1->length);
  assert(k2 && k2->name && k2->length);
  int eq;
  const size_t n = k1->length < k2->length ? k1->length : k2->length;
  if ((eq = strncasecmp(k1->name, k2->name, n)) != 0)
    return eq;
  return k1->length < k2->length ? -1 : (k1->length > k2->length ? +1 : 0);
}

static inline zone_key_value_t *zone_lookup(
  const zone_map_t *__restrict map, const zone_string_t *zstr)
{
  const zone_key_value_t key = { zstr->data, zstr->length, 0 };

  if (zstr->code & ZONE_ESCAPED)
    return bsearch(
      &key, map->sorted, map->length, sizeof(map->sorted[0]), zone_mapesccmp);
  else
    return bsearch(
      &key, map->sorted, map->length, sizeof(map->sorted[0]), zone_mapcmp);
}

#endif // ZONE_LOOKUP_H
