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

// RFC1035 section 3.4.2:
// The purpose of WKS RRs is to provide availability information for servers
// for TCP and UDP.
//
// NSD and BIND use getprotobyname, which reads /etc/protocols (optimizations
// may be in place for TCP and UDP). Note that BIND passes the protocol to
// getservbyname for TCP and UDP only, NULL otherwise, which means any
// protocol matches. Unfortunately, getprotobyname is NOT thread-safe.
// getprotobyname_r exist on most BSDs and Linux, but not Windows.
// The list of known protocols and services also differs between operating
// systems and no list covers all IANA (links below) registered protocols
// and services, which may cause compatibility issues.
//
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
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

#if BYTE_ORDER == LITTLE_ENDIAN
# define TCP (0x0000000000706374llu)
# define UDP (0x0000000000706475llu)
#elif BYTE_ORDER == BIG_ENDIAN
# define TCP (0x7463700000000000llu)
# define UDP (0x7564700000000000llu)
#else
#error
# error "byte order unknown"
#endif

static really_inline int32_t scan_protocol(
  const char *name, size_t length)
{
  static const int8_t zero_masks[48] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0
  };

  uint64_t key;
  uint64_t mask;
  const int8_t *zero_mask = &zero_masks[32 - (length & 0x1f)];
  memcpy(&mask, zero_mask, 8);

  memcpy(&key, name, sizeof(key)); // safe, input is padded
  key |= (key & 0x4040404040404040) >> 1; // convert to lower case
  key &= mask;

  if (key == TCP)
    return 6;
  if (key == UDP)
    return 17;

  if (length > 3) // protocol numbers must be between 0 and 255
    return -1;

  uint8_t digit;
  int32_t number = 0;
  size_t index = 0;
  while ((digit = (uint8_t)name[index++] - '0') <= 9)
    number = number * 10 + digit;

  if (index != length || number > 255)
    return -1;
  return number;
}

typedef struct service service_t;
struct service {
  struct {
    const char name[16];
    size_t length;
  } key;
  uint16_t port;
};

#define UNKNOWN_SERVICE() { { "", 0 }, 0 }
#define SERVICE(name, port) { { name, sizeof(name) - 1 }, port }

// FIXME: state we're not interested in reverse lookup for wks!
static const service_t services[64] = {
  SERVICE("imap", 143),
  SERVICE("ftp", 21),
  SERVICE("ntp", 123),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("ptp-general", 320),
  SERVICE("nicname", 43),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("ssh", 22),
  SERVICE("https", 443),
  SERVICE("http", 80),
  UNKNOWN_SERVICE(),
  SERVICE("telnet", 23),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("snmptrap", 162),
  SERVICE("lmtp", 24),
  SERVICE("smtp", 25),
  SERVICE("ftps-data", 989),
  SERVICE("ptp-event", 319),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("nntps", 563),
  SERVICE("nntp", 119),
  UNKNOWN_SERVICE(),
  SERVICE("nnsp", 433),
  UNKNOWN_SERVICE(),
  SERVICE("npp", 92),
  SERVICE("domain", 53),
  UNKNOWN_SERVICE(),
  SERVICE("tcpmux", 1),
  UNKNOWN_SERVICE(),
  SERVICE("submission", 587),
  // submissions cannot be distinguished from submission by hash value because
  // the shared prefix is too long. include length to generate a unique key
  SERVICE("submissions", 465),
  UNKNOWN_SERVICE(),
  SERVICE("echo", 7),
  SERVICE("domain-s", 853),
  UNKNOWN_SERVICE(),
  SERVICE("whoispp", 63),
  SERVICE("snmp", 161),
  UNKNOWN_SERVICE(),
  SERVICE("ftp-data", 20),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("bgmp", 264),
  SERVICE("ftps", 990),
  SERVICE("ldaps", 636),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("pop3s", 995),
  SERVICE("pop3", 110),
  SERVICE("kerberos", 88),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("imaps", 993),
};

#undef SERVICE
#undef UNKNOWN_SERVICE

// magic (138261570) generated using wks-hash.c
static really_inline uint8_t service_hash(uint64_t input, size_t length)
{
  // le64toh is required for big endian, no-op on little endian
  input = le64toh(input);
  uint32_t input32 = (uint32_t)((input >> 32) ^ input);
  return (((input32 * 138261570llu) >> 32) + length) & 0x3f;
}

nonnull((1,4))
static really_inline int32_t scan_service(
  const char *data, size_t length, int32_t protocol, uint16_t *port)
{
  uint8_t digit = (uint8_t)*data - '0';
  static const int8_t zero_masks[48] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0
  };

  (void)protocol; // all supported services map to tcp and udp

  if (digit > 9) {
    uint64_t input0, input1;
    static const uint64_t upper_mask = 0xdfdfdfdfdfdfdfdfllu;
    static const uint64_t letter_mask = 0x4040404040404040llu;
    memcpy(&input0, data, 8);
    memcpy(&input1, data+8, 8);
    // convert to upper case, unconditionally transforms digits (0x30-0x39)
    // and dash (0x2d), but does not introduce clashes
    uint64_t key = input0 & upper_mask;
    // zero out non-relevant bytes
    uint64_t zero_mask0, zero_mask1;
    const int8_t *zero_mask = &zero_masks[32 - (length & 0xf)];
    memcpy(&zero_mask0, zero_mask, 8);
    memcpy(&zero_mask1, zero_mask+8, 8);
    uint8_t index = service_hash(key & zero_mask0, length);
    assert(index < 64);

    input0 |= (input0 & letter_mask) >> 1;
    input0 &= zero_mask0;
    input1 |= (input1 & letter_mask) >> 1;
    input1 &= zero_mask1;

    uint64_t name0, name1;
    memcpy(&name0, services[index].key.name, 8);
    memcpy(&name1, services[index].key.name+8, 8);

    *port = services[index].port;
    return (input0 == name0) &
	   (input1 == name1) &
	   (services[index].key.length == length);
  }

  return scan_int16(data, length, port);
}

#endif // WKS_H
