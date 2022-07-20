#ifndef ZONE_MAP_H
#define ZONE_MAP_H

#include <stdint.h>
#include <string.h>

#include "zone.h"

static inline int zone_mapcasecmp(const void *p1, const void *p2)
{
  int cmp;
  size_t n;
  const zone_map_t *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->length);
  assert(m2 && m2->name && m2->length);
  n = m1->length < m2->length ? m1->length : m2->length;
  if ((cmp = strncasecmp(m1->name, m2->name, n)) != 0)
    return cmp;
  if (m1->length == m2->length)
    return 0;
  return m1->length < m2->length ? -1 : +1;
}

#endif // ZONE_MAP_H
