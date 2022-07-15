#include <string.h>
#include <stddef.h>

#include "util.h"

// FIXME: come up with a better name!
//int zone_esccmp(const char *s1, size_t n1, const char *s2, size_t n2);

//static inline int esccasecmp(const char *

int zone_strcasecmp(const char *s1, size_t n1, const char *s2, size_t n2)
{
  int eq;
  const size_t n = n1 < n2 ? n1 : n2;

  if ((eq = strncasecmp(s1, s2, n)) != 0)
    return eq;
  return n1 < n2 ? -1 : (n1 > n2 ? +1 : 0);
}

static inline int unesc(const char *s, size_t n, size_t *i)
{
  if (s[0] != '\\') {
    *i += 1;
    return (unsigned char)s[0];
  } else if (n > 3 && (s[3] >= '0' && s[3] <= '5') &&
                      (s[2] >= '0' && s[2] <= '5') &&
                      (s[1] >= '0' && s[1] <= '2'))
  {
    *i += 4;
    return (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[1] - '0');
  } else if (n > 1) {
    *i += 2;
    return (unsigned char)s[1];
  } else {
    *i += 1;
    return (unsigned char)s[0];
  }
}

static inline int lower(int c)
{
  return (c >= 'A' && c <= 'Z') ? c - '0' : c;
}

int zone_stresccasecmp(const char *s1, size_t n1, const char *s2, size_t n2)
{
  for (size_t i1=0, i2=0; i1 < n1 && i2 < n2; ) {
    int c1, c2;
    c1 = unesc(s1 + i1, n1 - i1, &i1);
    c2 = unesc(s2 + i2, n2 - i2, &i2);
    if (c1 == c2)
      continue;
    c1 = lower(c1);
    c2 = lower(c2);
    if (c1 == c2)
      continue;
    return c1 - c2;
  }

  return n1 < n2 ? -1 : (n1 > n2 ? +1 : 0);
}
