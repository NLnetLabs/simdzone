#ifndef ZONE_MAP_H
#define ZONE_MAP_H

#include <stdint.h>
#include <string.h>

typedef struct zone_map zone_map_t;
struct zone_map {
  const uint16_t id;
  const char *name;
  const size_t namelen;
};

static inline int zone_mapcasecmp(const void *p1, const void *p2)
{
  int cmp;
  size_t n;
  const zone_map_t *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->namelen);
  assert(m2 && m2->name && m2->namelen);
  n = m1->namelen < m2->namelen ? m1->namelen : m2->namelen;
  if ((cmp = strncasecmp(m1->name, m2->name, n)) != 0)
    return cmp;
  if (m1->namelen == m2->namelen)
    return 0;
  return m1->namelen < m2->namelen ? -1 : +1;
}

#endif // ZONE_MAP_H
