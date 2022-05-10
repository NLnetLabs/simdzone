#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "dns.h"

#define MAP(id, name) { id, name, (sizeof(name) - 1) }

struct map {
  const uint16_t id;
  const char *name;
  const size_t namelen;
};

static const struct map classmap[] = {
  MAP( CLASS_IN, "IN" ),
  MAP( CLASS_CH, "CH" ),
  MAP( CLASS_CS, "CS" ),
  MAP( CLASS_HS, "HS" )
};

static const struct map typemap[] = {
  MAP( TYPE_A, "A" ),
  MAP( TYPE_AAAA, "AAAA" ),
  MAP( TYPE_AFSDB, "AFSDB" ),
  MAP( TYPE_APL, "APL" ),
  MAP( TYPE_AVC, "AVC" ),
  MAP( TYPE_CAA, "CAA" ),
  MAP( TYPE_CDNSKEY, "CDNSKEY" ),
  MAP( TYPE_CDS, "CDS" ),
  MAP( TYPE_CERT, "CERT" ),
  MAP( TYPE_CNAME, "CNAME" ),
  MAP( TYPE_CSYNC, "CSYNC" ),
  MAP( TYPE_DHCID, "DHCID" ),
  MAP( TYPE_DLV, "DLV" ),
  MAP( TYPE_DNAME, "DNAME" ),
  MAP( TYPE_DNSKEY, "DNSKEY" ),
  MAP( TYPE_DS, "DS" ),
  MAP( TYPE_EUI48, "EUI48" ),
  MAP( TYPE_EUI64, "EUI64" ),
  MAP( TYPE_HINFO, "HINFO" ),
  MAP( TYPE_IPSECKEY, "IPSECKEY" ),
  MAP( TYPE_ISDN, "ISDN" ),
  MAP( TYPE_KEY, "KEY" ),
  MAP( TYPE_KX, "KX" ),
  MAP( TYPE_L32, "L32" ),
  MAP( TYPE_L64, "L64" ),
  MAP( TYPE_LOC, "LOC" ),
  MAP( TYPE_LP, "LP" ),
  MAP( TYPE_MB, "MB" ),
  MAP( TYPE_MD, "MD" ),
  MAP( TYPE_MF, "MF" ),
  MAP( TYPE_MG, "MG" ),
  MAP( TYPE_MINFO, "MINFO" ),
  MAP( TYPE_MR, "MR" ),
  MAP( TYPE_MX, "MX" ),
  MAP( TYPE_NAPTR, "NAPTR" ),
  MAP( TYPE_NID, "NID" ),
  MAP( TYPE_NS, "NS" ),
  MAP( TYPE_NSAP, "NSAP" ),
  MAP( TYPE_NSEC, "NSEC" ),
  MAP( TYPE_NSEC3, "NSEC3" ),
  MAP( TYPE_NSEC3PARAM, "NSEC3PARAM" ),
  MAP( TYPE_NXT, "NXT" ),
  MAP( TYPE_OPENPGPKEY, "OPENPGPKEY" ),
  MAP( TYPE_OPT, "OPT" ),
  MAP( TYPE_PTR, "PTR" ),
  MAP( TYPE_PX, "PX" ),
  MAP( TYPE_SOA, "SOA" ),
  MAP( TYPE_WKS, "WKS" ),
  MAP( TYPE_RP, "RP" ),
  MAP( TYPE_RRSIG, "RRSIG" ),
  MAP( TYPE_RT, "RT" ),
  MAP( TYPE_SIG, "SIG" ),
  MAP( TYPE_SMIMEA, "SMIMEA" ),
  MAP( TYPE_SPF, "SPF" ),
  MAP( TYPE_SRV, "SRV" ),
  MAP( TYPE_SSHFP, "SSHFP" ),
  MAP( TYPE_TLSA, "TLSA" ),
  MAP( TYPE_TXT, "TXT" ),
  MAP( TYPE_URI, "URI" ),
  MAP( TYPE_X25, "X25" )
};

#undef MAP

static int compare(const void *p1, const void *p2)
{
  int eq;
  const struct map *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->namelen);
  assert(m2 && m2->name && m2->namelen);
  if ((eq = strncasecmp(m1->name, m2->name, m1->namelen)))
    return eq;
  if (m1->namelen == m2->namelen)
    return 0;
  return m1->namelen < m2->namelen ? -1 : +1;
}

#ifndef NDEBUG
static inline int issorted(struct map *restrict map, size_t maplen)
{
  for (size_t i = 1; i < maplen; i++)
    if (compare(&map[i -1], &map[i]) >= 0)
      return false;
  return true;
}
#endif

int32_t strtoclass(const char *str, size_t len, uint16_t *class)
{
  struct map *ptr, key = { 0, str, len };
  size_t sz = sizeof(classmap), cnt = sizeof(classmap)/sizeof(classmap[0]);

  assert(str);
  assert(issorted(classmap, cnt));

  if (!len)
    return -1;
  if (!(ptr = bsearch(&key, classmap, cnt, sz, &compare)))
    return -1;
  if (class)
    *class = ptr->id;
  return (int32_t)ptr->id;
}

int32_t strtotype(const char *str, size_t len, uint32_t *type)
{
  struct map *ptr, key = { 0, str, len };
  size_t sz = sizeof(typemap), cnt = sizeof(typemap)/sizeof(typemap[0]);

  assert(str);
  assert(issorted(typemap), cnt);

  if (!len)
    return -1;

  switch (str[0]) {
    case 'r':
    case 'R':
      if (len == 5 && strncasecmp(str, "RRSIG", 5) == 0)
        return TYPE_RRSIG;
      break;
    case 'n':
    case 'N':
      if (len == 2 && strncasecmp(str, "NS", 2) == 0)
        return TYPE_NS;
      if (len == 4 && strncasecmp(str, "NSEC", 4) == 0)
        return TYPE_NSEC;
      if (len == 5 && strncasecmp(str, "NSEC3", 5) == 0)
        return TYPE_NSEC3;
      if (len == 10 && strncasecmp(str, "NSEC3PARAM", 10) == 0)
        return TYPE_NSEC3PARAM;
      break;
    case 'd':
    case 'D':
      if (len == 2 && strncasecmp(str, "DS", 2) == 0)
        return TYPE_DS;
      if (len == 6 && strncasecmp(str, "DNSKEY", 6) == 0)
        return TYPE_DNSKEY;
      break;
    case 'a':
    case 'A':
      if (len == 1 && strncasecmp(str, "A", 1) == 0)
        return TYPE_A;
      if (len == 4 && strncasecmp(str, "AAAA", 4) == 0)
        return TYPE_AAAA;
      break;
    case 's':
    case 'S':
      if (len == 3 && strncasecmp(str, "SOA", 3) == 0)
        return TYPE_SOA;
      break;
    case 't':
    case 'T':
      if (len == 3 && strncasecmp(str, "TXT", 3) == 0)
        return TYPE_TXT;
      break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return 0;
    case 'i':
    case 'I':
      if (len == 2 && strncasecmp(str, "IN", 2) == 0)
        return 0;
      break;
  }

  if (!(ptr = bsearch(&key, typemap, cnt, sz, &compare)))
    return -1;
  if (type)
    *type = ptr->id;
  return (int32_t)ptr->id;
}

static inline uint32_t isunit(const uint8_t chr)
{
  static const uint32_t s = 1u, m = 60u*s, h = 60u*m, d = 24u*h, w = 7u*d;

  switch (chr) {
    case 's':
    case 'S':
      return s;
    case 'm':
    case 'M':
      return m;
    case 'h':
    case 'H':
      return h;
    case 'd':
    case 'D':
      return d;
    case 'w':
    case 'W':
      return w;
  }

  return 0;
}

static inline uint32_t mult(uint32_t lhs, uint32_t rhs)
{
  if (INT32_MAX < rhs || INT32_MAX / rhs < lhs)
    return INT32_MAX;
  return lhs * rhs;
}

static inline uint32_t add(uint32_t lhs, uint32_t rhs)
{
  if (INT32_MAX < rhs || INT32_MAX - rhs < lhs)
    return INT32_MAX;
  return lhs + rhs;
}

// bind allows for this too...
//4.3.3. Setting TTLs
//
//The time-to-live of the RR field is a 32-bit integer represented in units of seconds, and is primarily used by resolvers when they cache RRs. The TTL describes how long a RR can be cached before it should be discarded. The following three types of TTL are currently used in a zone file.
//
//SOA
//
//    The last field in the SOA is the negative caching TTL. This controls how long other servers cache no-such-domain (NXDOMAIN) responses from this server.
//    The maximum time for negative caching is 3 hours (3h).
//$TTL
//    The $TTL directive at the top of the zone file (before the SOA) gives a default TTL for every RR without a specific TTL set.
//RR TTLs
//    Each RR can have a TTL as the second field in the RR, which controls how long other servers can cache it.
//
//All of these TTLs default to units of seconds, though units can be explicitly specified: for example, 1h30m.


//8. Time to Live (TTL)
//
//   The definition of values appropriate to the TTL field in STD 13 is
//   not as clear as it could be, with respect to how many significant
//   bits exist, and whether the value is signed or unsigned.  It is
//   hereby specified that a TTL value is an unsigned number, with a
//   minimum value of 0, and a maximum value of 2147483647.  That is, a
//   maximum of 2^31 - 1.  When transmitted, this value shall be encoded
//   in the less significant 31 bits of the 32 bit TTL field, with the
//
//
//Elz & Bush                  Standards Track                    [Page 10]
//
//RFC 2181        Clarifications to the DNS Specification        July 1997
//
//   most significant, or sign, bit set to zero.
//
//   Implementations should treat TTL values received with the most
//   significant bit set as if the entire value received was zero.
//
//   Implementations are always free to place an upper bound on any TTL
//   received, and treat any larger values as if they were that upper
//   bound.  The TTL specifies a maximum time to live, not a mandatory
//   time to live.


int32_t strtottl(const uint8_t *str, size_t strlen, uint32_t *secs)
{
  int32_t n = 0, s = 0, lu = 0;
  enum { initial, number, unit } state = initial;

  for (size_t i = 0; i < strlen; i++) {
    uint32_t u;
    const uint8_t c = str[i];
    switch (state) {
      case initial:
        // ttls must start with a number
        if (c < '0' || c > '9')
          return -1;
        state = number;
        n = c - '0';
        break;
      case number:
        if (c >= '0' && c <= '9') {
          n = add(mult(n, 10), c - '0');
        } else if ((u = isunit(c))) {
          // larger units must precede smaller units. e.g. 1m1s is valid but
          // 1s1m is not. units may also not be repeated to avoid e.g. 1m1m.
          if (lu <= u)
            return -1;
          n = mult(n, (lu = u));
          state = unit;
        } else {
          return 0;
        }
        break;
      case unit:
        // a unit must be followed by a number. e.g. 1h30m is valid but
        // 1hh is not. a unit cannot be followed by a number if the smallest
        // unit, i.e. s(econds) was previously used
        if (c < '0' || c > '9' || lu == 1)
          return -1;
        s = add(s, n);
        n = c - '0';
        state = number;
        break;
    }
  }

  s = add(s, n);
  assert(s <= INT32_MAX);
  if (secs)
    *secs = s;
  return (int32_t)s;
}
