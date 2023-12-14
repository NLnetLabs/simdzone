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

// Matching inspired by Wojciech Muła's article "Fast Parsing HTTP verbs"
// (http://0x80.pl/notesen/2022-01-29-http-verb-parse.html). Hexadecimal
// notation rather than macro used to specify prefixes because of compilation
// errors in Microsoft Visual Studio.
#define PREFIX_TCP         (0x706374llu)
#define PREFIX_UDP         (0x706475llu)
#define PREFIX_TCPMUX      (0x78756d706374llu)
#define PREFIX_ECHO        (0x6f686365llu)
#define PREFIX_FTP_DATA    (0x617461642d707466llu)
#define PREFIX_FTP         (0x707466llu)
#define PREFIX_SSH         (0x687373llu)
#define PREFIX_TELNET      (0x74656e6c6574llu)
#define PREFIX_LMTP        (0x70746d6cllu)
#define PREFIX_SMTP        (0x70746d73llu)
#define PREFIX_NICNAME     (0x656d616e63696ellu)
#define PREFIX_DOMAIN      (0x6e69616d6f64llu)
#define PREFIX_WHOISPP     (0x707073696f6877llu)
#define PREFIX_HTTP        (0x70747468llu)
#define PREFIX_KERBEROS    (0x736f72656272656bllu)
#define PREFIX_NPP         (0x70706ellu)
#define PREFIX_POP3        (0x33706f70llu)
#define PREFIX_NNTP        (0x70746e6ellu)
#define PREFIX_NTP         (0x70746ellu)
#define PREFIX_IMAP        (0x70616d69llu)
#define PREFIX_SNMP        (0x706d6e73llu)
#define PREFIX_SNMPTRAP    (0x70617274706d6e73llu)
#define PREFIX_BGMP        (0x706d6762llu)
#define PREFIX_PTP_EVENT   (0x6e6576652d707470llu)
#define PREFIX_PTP_GENERAL (0x656e65672d707470llu)
#define PREFIX_NNSP        (0x70736e6ellu)
#define PREFIX_HTTPS       (0x7370747468llu)
#define PREFIX_SUBMISSION  (0x697373696d627573llu)
#define PREFIX_NNTPS       (0x7370746e6ellu)
#define PREFIX_LDAPS       (0x737061646cllu)
#define PREFIX_DOMAIN_S    (0x732d6e69616d6f64llu)
#define PREFIX_FTPS_DATA   (0x7461642d73707466llu)
#define PREFIX_FTPS        (0x73707466llu)
#define PREFIX_IMAPS       (0x7370616d69llu)
#define PREFIX_POP3S       (0x7333706f70llu)

nonnull((1))
static really_inline int32_t scan_protocol(
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

  if (key == PREFIX_TCP)
    return 6;
  if (key == PREFIX_UDP)
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

nonnull((1))
static really_inline int32_t scan_service(
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
      case PREFIX_TCPMUX:
        return 1;
      case PREFIX_ECHO:
        return 7;
      case PREFIX_FTP_DATA:
        return length == 8 ? 20 : -1;
      case PREFIX_FTP:
        return 21;
      case PREFIX_SSH:
        return 22;
      case PREFIX_TELNET:
        return 23;
      case PREFIX_LMTP:
        return 24;
      case PREFIX_SMTP:
        return 25;
      case PREFIX_NICNAME:
        return 43;
      case PREFIX_DOMAIN:
        return 53;
      case PREFIX_WHOISPP:
        return 63;
      case PREFIX_HTTP:
        return 80;
      case PREFIX_KERBEROS:
        if (length == 8)
          return 88;
        return -1;
      case PREFIX_NPP:
        return 92;
      case PREFIX_POP3:
        return 110;
      case PREFIX_NNTP:
        return 119;
      case PREFIX_NTP:
        return 123;
      case PREFIX_IMAP:
        return 143;
      case PREFIX_SNMP:
        return 161;
      case PREFIX_SNMPTRAP:
        return length == 8 ? 162 : -1;
      case PREFIX_BGMP:
        return 264;
      case PREFIX_PTP_EVENT:
        if (length == 9 && strncasecmp(name, "ptp-event", 9) == 0)
          return 319;
        return -1;
      case PREFIX_PTP_GENERAL:
        if (length == 11 && strncasecmp(name, "ptp-general", 11) == 0)
          return 320;
        return -1;
      case PREFIX_NNSP:
        return 433;
      case PREFIX_HTTPS:
        return 443;
      case PREFIX_SUBMISSION:
        if (length == 10 && strncasecmp(name, "submission", 10) == 0)
          return 587;
        if (length == 11 && strncasecmp(name, "submissions", 11) == 0)
          return 465;
        return 0;
      case PREFIX_NNTPS:
        return 563;
      case PREFIX_LDAPS:
        return 636;
      case PREFIX_DOMAIN_S:
        if (length == 8)
          return 853;
        return -1;
      case PREFIX_FTPS_DATA:
        if (length == 9 && strncasecmp(name, "ftps-data", 9) == 0)
          return 989;
        return -1;
      case PREFIX_FTPS:
        return 990;
      case PREFIX_IMAPS:
        return 993;
      case PREFIX_POP3S:
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

#undef PREFIX_TCP
#undef PREFIX_UDP
#undef PREFIX_TCPMUX
#undef PREFIX_ECHO
#undef PREFIX_FTP_DATA
#undef PREFIX_FTP
#undef PREFIX_SSH
#undef PREFIX_TELNET
#undef PREFIX_LMTP
#undef PREFIX_SMTP
#undef PREFIX_NICNAME
#undef PREFIX_DOMAIN
#undef PREFIX_WHOISPP
#undef PREFIX_HTTP
#undef PREFIX_KERBEROS
#undef PREFIX_NPP
#undef PREFIX_POP3
#undef PREFIX_NNTP
#undef PREFIX_NTP
#undef PREFIX_IMAP
#undef PREFIX_SNMP
#undef PREFIX_SNMPTRAP
#undef PREFIX_BGMP
#undef PREFIX_PTP_EVENT
#undef PREFIX_PTP_GENERAL
#undef PREFIX_NNSP
#undef PREFIX_HTTPS
#undef PREFIX_SUBMISSION
#undef PREFIX_NNTPS
#undef PREFIX_LDAPS
#undef PREFIX_DOMAIN_S
#undef PREFIX_FTPS_DATA
#undef PREFIX_FTPS
#undef PREFIX_IMAPS
#undef PREFIX_POP3S

#endif // WKS_H
