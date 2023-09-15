/*
 * wks.c -- Well known services RDATA parser
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef WKS_H
#define WKS_H

// http://0x80.pl/notesen/2022-01-29-http-verb-parse.html
#define STRING64(s0, s1, s2, s3, s4, s5, s6, s7, ...) \
  (((uint64_t)((uint8_t)(s0)) << 0*8) | \
   ((uint64_t)((uint8_t)(s1)) << 1*8) | \
   ((uint64_t)((uint8_t)(s2)) << 2*8) | \
   ((uint64_t)((uint8_t)(s3)) << 3*8) | \
   ((uint64_t)((uint8_t)(s4)) << 4*8) | \
   ((uint64_t)((uint8_t)(s5)) << 5*8) | \
   ((uint64_t)((uint8_t)(s6)) << 6*8) | \
   ((uint64_t)((uint8_t)(s7)) << 7*8))

#define PREFIX64(...) STRING64(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0)

zone_nonnull((1))
static zone_really_inline int32_t scan_protocol(
  const char *name, size_t length)
{
  // RFC1035 section 3.4.2:
  // The purpose of WKS RRs is to provide availability information for servers
  // for TCP and UDP.
  //
  // NSD and BIND use getprotobyname, which reads /etc/protocols (optimizations
  // may be in place for TCP and UDP). Note that BIND passes the protocol to
  // getservbyname for TCP and UDP only, NULL otherwise, which means any
  // protocol matches. Unfortunately, getprotobyname is NOT thread-safe.
  // getprotobyname_r exist on most BSDs and Linux, but not Windows.
  // The list of known protocols also differs between operating systems and no
  // list covers all IANA (link below) registered protocols, which may cause
  // compatibility issues.
  //
  // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  //
  //
  // WKS RRs are rarely used and a document to deprecate the RRTYPE (among
  // others) has been drafted (WKS removed from the second draft).
  //
  // https://datatracker.ietf.org/doc/html/draft-sury-deprecate-obsolete-resource-records-00
  // https://mailarchive.ietf.org/arch/msg/dnsop/YCVvXuM8HbJLF2SoXyDqyOGao34/
  //
  //
  // WKS RRs have been said to be deprecated in an informational document (NOT
  // a standard), although it wrongly claims WKS RRs are in fact deprecated.
  //
  // RFC1912 section 2.6.1:
  // WKS records are deprecated in [RFC 1123].  They serve no known useful
  // function, except internally among LISP machines.  Don't use them.
  //
  // https://datatracker.ietf.org/doc/html/rfc1912
  //
  //
  // Rather than supporting any protocol registered by IANA, support a small
  // subset of mnemonics (TCP and UDP) as well as numeric values and add
  // support (or remove it entirely) for additional protocols on demand.
  uint64_t key;
  uint64_t mask = 0xffffffffffffffffu;
  if (length < 8)
    mask = (1llu << (length * 8)) - 1;

  memcpy(&key, name, sizeof(key)); // safe, input is padded
  key |= (key & 0x4040404040404040) >> 1; // convert to lower case
  key &= mask;

  if (key == PREFIX64('t', 'c', 'p'))
    return 6;
  if (key == PREFIX64('u', 'd', 'p'))
    return 17;

  if (length > 3) // protocol numbers must be between 0 and 255
    return -1;

  uint8_t digit;
  int32_t number = 0;
  size_t index = 0;
  while ((digit = (uint8_t)name[index++]) - '0' <= 9)
    number = number * 10 + digit;

  if (index != length || number > 255)
    return -1;
  return number;
}

zone_nonnull((1))
static zone_really_inline int32_t scan_service(
  const char *name, size_t length, int32_t protocol)
{
  uint8_t digit = (uint8_t)*name - '0';

  (void)protocol; // all supported services map to tcp and udp

  if (digit > 9) {
    uint64_t key;
    uint64_t mask = 0xffffffffffffffffllu;
    if (length < 8)
      mask = (1llu << (length * 8)) - 1llu;

    memcpy(&key, name, sizeof(key)); // safe, input is padded
    key |= (key & 0x4040404040404040) >> 1; // convert to lower case
    key &= mask;

    // https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    switch (key) {
      case PREFIX64('t', 'c', 'p', 'm', 'u', 'x'):
        return 1;
      case PREFIX64('e', 'c', 'h', 'o'):
        return 7;
      case PREFIX64('f', 't', 'p', '-', 'd', 'a', 't', 'a'):
        return length == 8 ? 20 : -1;
      case PREFIX64('f', 't', 'p'):
        return 21;
      case PREFIX64('s', 's', 'h'):
        return 22;
      case PREFIX64('t', 'e', 'l', 'n', 'e', 't'):
        return 23;
      case PREFIX64('l', 'm', 't', 'p'):
        return 24;
      case PREFIX64('s', 'm', 't', 'p'):
        return 25;
      case PREFIX64('n', 'i', 'c', 'n', 'a', 'm', 'e'):
        return 43;
      case PREFIX64('d', 'o', 'm', 'a', 'i', 'n'):
        return 53;
      case PREFIX64('w', 'h', 'o', 'i', 's', 'p', 'p'):
        return 63;
      case PREFIX64('h', 't', 't', 'p'):
        return 80;
      case PREFIX64('k', 'e', 'r', 'b', 'e', 'r', 'o', 's'):
        if (length == 8)
          return 88;
        return -1;
      case PREFIX64('n', 'p', 'p'):
        return 92;
      case PREFIX64('p', 'o', 'p', '3'):
        return 110;
      case PREFIX64('n', 'n', 't', 'p'):
        return 119;
      case PREFIX64('n', 't', 'p'):
        return 123;
      case PREFIX64('i', 'm', 'a', 'p'):
        return 143;
      case PREFIX64('s', 'n', 'm', 'p'):
        return 161;
      case PREFIX64('s', 'n', 'm', 'p', 't', 'r', 'a', 'p'):
        return length == 8 ? 162 : -1;
      case PREFIX64('b', 'g', 'm', 'p'):
        return 264;
      case PREFIX64('p', 't', 'p', '-', 'e', 'v', 'e', 'n'):
        if (length == 9 && strncasecmp(name, "ptp-event", 9) == 0)
          return 319;
        return -1;
      case PREFIX64('p', 't', 'p', '-', 'g', 'e', 'n', 'e'):
        if (length == 11 && strncasecmp(name, "ptp-general", 11) == 0)
          return 320;
        return -1;
      case PREFIX64('n', 'n', 's', 'p'):
        return 433;
      case PREFIX64('h', 't', 't', 'p', 's'):
        return 443;
      case PREFIX64('s', 'u', 'b', 'm', 'i', 's', 's', 'i'):
        if (length == 10 && strncasecmp(name, "submission", 10) == 0)
          return 587;
        if (length == 11 && strncasecmp(name, "submissions", 11) == 0)
          return 465;
        return 0;
      case PREFIX64('n', 'n', 't', 'p', 's'):
        return 563;
      case PREFIX64('l', 'd', 'a', 'p', 's'):
        return 636;
      case PREFIX64('f', 't', 'p', 's', '-', 'd', 'a', 't'):
        if (length == 9 && strncasecmp(name, "ftps-data", 9) == 0)
          return 989;
        return -1;
      case PREFIX64('f', 't', 'p', 's'):
        return 990;
      case PREFIX64('i', 'm', 'a', 'p', 's'):
        return 993;
      case PREFIX64('p', 'o', 'p', '3', 's'):
        return 995;
      default:
        return -1;
    }
  } else {
    int32_t number = digit;
    size_t index = 1;

    if (length > 5) // port numbers must be between 0 and 65535
      return -1;
    for (; ((digit = ((uint8_t)name[index] - '0')) <= 9); index++)
      number = number * 10 + digit;
    if (index != length || number > 65535)
      return -1;
    return number;
  }
}

#endif // WKS_H
