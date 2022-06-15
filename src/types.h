/*
 * types.h -- resource record descriptors for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_TYPES_H
#define ZONE_TYPES_H

// separate include so that macros may be used to generate typemap

TYPES(
  { 0 },
  TYPE(A, 1, 0, RDATA( IP4(ADDRESS, 0) )),
  TYPE(NS, 2, ANY, RDATA( NAME(NSDNAME, COMPRESSED) )),
  TYPE(MD, 3, ANY|OBSOLETE, RDATA( NAME(MADNAME, COMPRESSED) )),
  TYPE(MF, 4, ANY|OBSOLETE, RDATA( NAME(MADNAME, COMPRESSED) )),
  TYPE(CNAME, 5, 0, RDATA( NAME(CNAME, COMPRESSED) )),

  TYPE(SOA, 6, 0,
    RDATA(
      NAME(MNAME, COMPRESSED),
      NAME(RNAME, MAILBOX),
      INT32(SERIAL, 0),
      INT32(REFRESH, 0, PARSE(parse_ttl)),
      INT32(RETRY, 0, PARSE(parse_ttl)),
      INT32(EXPIRE, 0, PARSE(parse_ttl)),
      INT32(MINIMUM, 0, PARSE(parse_ttl)))),

  TYPE(MB, 7, ANY|EXPERIMENTAL, RDATA( NAME(MADNAME, COMPRESSED) )),
  TYPE(MG, 8, ANY|EXPERIMENTAL, RDATA( NAME(MGMNAME, MAILBOX) )),
  TYPE(MR, 9, ANY|EXPERIMENTAL, RDATA( NAME(NEWNAME, MAILBOX) )),
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  { 0 },
  TYPE(AAAA, 28, 0, RDATA( IP6(ADDRESS, 0) ))
)

#endif // ZONE_TYPES_H
