/*
 * types.c -- Happy path tests to demonstrate supported types
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdarg.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "zone.h"

// automatically pad string literal
#define PAD(literal) \
  literal \
  "\0\0\0\0\0\0\0\0" /*  0 -  7 */ \
  "\0\0\0\0\0\0\0\0" /*  8 - 15 */ \
  "\0\0\0\0\0\0\0\0" /* 16 - 23 */ \
  "\0\0\0\0\0\0\0\0" /* 24 - 31 */ \
  "\0\0\0\0\0\0\0\0" /* 32 - 39 */ \
  "\0\0\0\0\0\0\0\0" /* 40 - 47 */ \
  "\0\0\0\0\0\0\0\0" /* 48 - 55 */ \
  "\0\0\0\0\0\0\0\0" /* 56 - 63 */ \
  ""

#define RDATA(...) \
 { sizeof( (const uint8_t[]){ __VA_ARGS__ } )/sizeof(uint8_t), (const uint8_t[]){ __VA_ARGS__ } }

typedef struct rdata rdata_t;
struct rdata {
  size_t length;
  const uint8_t *octets;
};

/* RFC9460 Appendix D. Test Vectors */


// D.1. AliasMode

// Figure 2: AliasMode
static const char d1_svcb_text[] =
  PAD("v01     SVCB    0 foo.example.com.");
static const char d1_svcb_generic_text[] =
  PAD("v01     SVCB    \\# 19 (\n"
      "00 00                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      ")");
static const char d1_https_text[] =
  PAD("v11     HTTPS   0 foo.example.com.");
static const char d1_https_generic_text[] =
  PAD("v11     HTTPS   \\# 19 (\n"
      "00 00                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      ")");
static const rdata_t d1_rdata = RDATA(
  // priority
  0x00, 0x00,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00);


// D.2. ServiceMode

// Figure 3: TargetName is "."
// The first form is the simple "use the ownername".
static const char d2_f3_svcb_text[] =
  PAD("v02     SVCB    1 .");
static const char d2_f3_svcb_generic_text[] =
  PAD("v02     SVCB    \\# 3 (\n"
      "00 01      ; priority\n"
      "00         ; target (root label)\n"
      ")");

static const char d2_f3_https_text[] =
  PAD("v12     HTTPS   1 .");
static const char d2_f3_https_generic_text[] =
  PAD("v12     HTTPS   \\# 3 (\n"
      "00 01      ; priority\n"
      "00         ; target (root label)\n"
      ")");

static const rdata_t d2_f3_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target (root label)
  0x00);

// Figure 4: Specifies a Port
// This vector only has a port.
static const char d2_f4_svcb_text[] =
  PAD("v03     SVCB    16 foo.example.com. port=53");
static const char d2_f4_svcb_generic_text[] =
  PAD("v03     SVCB    \\# 25 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "00 03                                              ; key 3\n"
      "00 02                                              ; length 2\n"
      "00 35                                              ; value\n"
      ")");

static const char d2_f4_https_text[] =
  PAD("v13     HTTPS   16 foo.example.com. port=53");
static const char d2_f4_https_generic_text[] =
  PAD("v13     HTTPS   \\# 25 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "00 03                                              ; key 3\n"
      "00 02                                              ; length 2\n"
      "00 35                                              ; value\n"
      ")");

static const rdata_t d2_f4_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 3
  0x00, 0x03,
  // length 2
  0x00, 0x02,
  // value
  0x00, 0x35);

// Figure 5: A Generic Key and Unquoted Value
// This example has a key that is not registered, its value is unquoted.
static const char d2_f5_svcb_text[] =
  PAD("v04     SVCB    1 foo.example.com. key667=hello");
static const char d2_f5_svcb_generic_text[] =
  PAD("v04     SVCB    \\# 28 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "02 9b                                              ; key 667\n"
      "00 05                                              ; length 5\n"
      "68 65 6c 6c 6f                                     ; value\n"
      ")");

static const char d2_f5_https_text[] =
  PAD("v14     HTTPS   1 foo.example.com. key667=hello");
static const char d2_f5_https_generic_text[] =
  PAD("v14     HTTPS   \\# 28 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "02 9b                                              ; key 667\n"
      "00 05                                              ; length 5\n"
      "68 65 6c 6c 6f                                     ; value\n"
      ")");

static const rdata_t d2_f5_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 667
  0x02, 0x9b,
  // length 9
  0x00, 0x05,
  // value
  0x68, 0x65, 0x6c, 0x6c, 0x6f);

// Figure 6: A Generic Key and Quoted Value with a Decimal Escape
// This example has a key that is not registered, its value is quoted and
// contains a decimal-escaped character.
static const char d2_f6_svcb_text[] =
  PAD("v05     SVCB    1 foo.example.com. key667=\"hello\\210qoo\"");
static const char d2_f6_svcb_generic_text[] =
  PAD("v05     SVCB    \\# 32 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "02 9b                                              ; key 667\n"
      "00 09                                              ; length 9\n"
      "68 65 6c 6c 6f d2 71 6f 6f                         ; value\n"
      ")");

static const char d2_f6_https_text[] =
  PAD("v15     HTTPS   1 foo.example.com. key667=\"hello\\210qoo\"");
static const char d2_f6_https_generic_text[] =
  PAD("v15     HTTPS   \\# 32 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "02 9b                                              ; key 667\n"
      "00 09                                              ; length 9\n"
      "68 65 6c 6c 6f d2 71 6f 6f                         ; value\n"
      ")");

static const rdata_t d2_f6_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 667
  0x02, 0x9b,
  // length 9
  0x00, 0x09,
  // value
  0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd2, 0x71, 0x6f,
  0x6f);

// Figure 7: Two Quoted IPv6 Hints
// Here, two IPv6 hints are quoted in the presentation format.
static const char d2_f7_svcb_text[] =
  PAD("v06     SVCB    1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"");
static const char d2_f7_svcb_generic_text[] =
  PAD("v06     SVCB    \\# 55 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "00 06                                              ; key 6\n"
      "00 20                                              ; length 32\n"
      "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01    ; first address\n"
      "20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01    ; second address\n"
      ")");

static const char d2_f7_https_text[] =
  PAD("v16     HTTPS   1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"");
static const char d2_f7_https_generic_text[] =
  PAD("v16     HTTPS   \\# 55 (\n"
      "00 01                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
      "00 06                                              ; key 6\n"
      "00 20                                              ; length 32\n"
      "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01    ; first address\n"
      "20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01    ; second address\n"
      ")");

static const rdata_t d2_f7_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00,
  // key 6
  0x00, 0x06,
  // length 32
  0x00, 0x20,
  // first address
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  // second address
  0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x01);

// Figure 8: An IPv6 Hint Using the Embedded IPv4 Syntax
// This example shows a single IPv6 hint in IPv4 mapped IPv6 presentation format.
static const char d2_f8_svcb_text[] =
  PAD("v07     SVCB    1 example.com. (\n"
      "          ipv6hint=\"2001:db8:ffff:ffff:ffff:ffff:198.51.100.100\"\n"
      ")");
static const char d2_f8_svcb_generic_text[] =
  PAD("v07     SVCB    \\# 35 (\n"
      "00 01                                              ; priority\n"
      "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00             ; target\n"
      "00 06                                              ; key 6\n"
      "00 10                                              ; length 16\n"
      "20 01 0d b8 ff ff ff ff ff ff ff ff c6 33 64 64    ; address\n"
      ")");

static const char d2_f8_https_text[] =
  PAD("v17     HTTPS   1 example.com. (\n"
      "          ipv6hint=\"2001:db8:ffff:ffff:ffff:ffff:198.51.100.100\"\n"
      ")");
static const char d2_f8_https_generic_text[] =
  PAD("v17     HTTPS   \\# 35 (\n"
      "00 01                                              ; priority\n"
      "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00             ; target\n"
      "00 06                                              ; key 6\n"
      "00 10                                              ; length 16\n"
      "20 01 0d b8 ff ff ff ff ff ff ff ff c6 33 64 64    ; address\n"
      ")");

static const rdata_t d2_f8_rdata = RDATA(
  // priority
  0x00, 0x01,
  // target
  0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x03, 0x63, 0x6f, 0x6d, 0x00,
  // key 6
  0x00, 0x06,
  // length 16
  0x00, 0x10,
  // address
  0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xc6, 0x33, 0x64, 0x64);

// Figure 9: SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format
// In the next vector, neither the SvcParamValues nor the mandatory keys are
// sorted in presentation format, but are correctly sorted in the wire-format.
static const char d2_f9_svcb_text[] =
  PAD("v08     SVCB    16 foo.example.org. (\n"
      "                   alpn=h2,h3-19 mandatory=ipv4hint,alpn\n"
      "                   ipv4hint=192.0.2.1\n"
      ")");
static const char d2_f9_svcb_generic_text[] =
  PAD("v08     SVCB    \\# 48 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 00                                              ; key 0\n"
      "00 04                                              ; param length 4\n"
      "00 01                                              ; value: key 1\n"
      "00 04                                              ; value: key 4\n"
      "00 01                                              ; key 1\n"
      "00 09                                              ; param length 9\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      "05                                                 ; alpn length 5\n"
      "68 33 2d 31 39                                     ; alpn value\n"
      "00 04                                              ; key 4\n"
      "00 04                                              ; param length 4\n"
      "c0 00 02 01                                        ; param value\n"
      ")");

static const char d2_f9_https_text[] =
  PAD("v18     HTTPS   16 foo.example.org. (\n"
      "                   alpn=h2,h3-19 mandatory=ipv4hint,alpn\n"
      "                   ipv4hint=192.0.2.1\n"
      ")");
static const char d2_f9_https_generic_text[] =
  PAD("v18     HTTPS   \\# 48 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 00                                              ; key 0\n"
      "00 04                                              ; param length 4\n"
      "00 01                                              ; value: key 1\n"
      "00 04                                              ; value: key 4\n"
      "00 01                                              ; key 1\n"
      "00 09                                              ; param length 9\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      "05                                                 ; alpn length 5\n"
      "68 33 2d 31 39                                     ; alpn value\n"
      "00 04                                              ; key 4\n"
      "00 04                                              ; param length 4\n"
      "c0 00 02 01                                        ; param value\n"
      ")");

static const rdata_t d2_f9_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
  0x00,
  // key 0
  0x00, 0x00,
  // param length 4
  0x00, 0x04,
  // value: key 1
  0x00, 0x01,
  // value: key 4
  0x00, 0x04,
  // key 1
  0x00, 0x01,
  // param length 9
  0x00, 0x09,
  // alpn length 2
  0x02,
  // alpn value
  0x68, 0x32,
  // alpn length 5
  0x05,
  // alpn value
  0x68, 0x33, 0x2d, 0x31, 0x39,
  // key 4
  0x00, 0x04,
  // param length 4
  0x00, 0x04,
  // param value
  0xc0, 0x00, 0x02, 0x01);
#if 0
// Figure 10: An "alpn" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats
// This last (two) vectors has an alpn value with an escaped comma and an
// escaped backslash in two presentation formats.
static const char d2_f10_1_svcb_text[] =
  PAD("v09     SVCB    16 foo.example.org. alpn=\"f\\\\oo\\,bar,h2\"");
static const char d2_f10_1_svcb_generic_text[] =
  PAD("v09     SVCB    \\# 35 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 01                                              ; key 1\n"
      "00 0c                                              ; param length 12\n"
      "08                                                 ; alpn length 8\n"
      "66 5c 6f 6f 2c 62 61 72                            ; alpn value\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      ")");

static const char d2_f10_1_https_text[] =
  PAD("v19     HTTPS   16 foo.example.org. alpn=\"f\\\\oo\\,bar,h2\"");
static const char d2_f10_1_https_generic_text[] =
  PAD("v19     HTTPS   \\# 35 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 01                                              ; key 1\n"
      "00 0c                                              ; param length 12\n"
      "08                                                 ; alpn length 8\n"
      "66 5c 6f 6f 2c 62 61 72                            ; alpn value\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      ")");

static const char d2_f10_2_svcb_text[] =
  PAD("v10     SVCB    16 foo.example.org. alpn=f\\\092oo\092,bar,h2");
static const char d2_f10_2_svcb_generic_text[] =
  PAD("v10     SVCB    \\# 35 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 01                                              ; key 1\n"
      "00 0c                                              ; param length 12\n"
      "08                                                 ; alpn length 8\n"
      "66 5c 6f 6f 2c 62 61 72                            ; alpn value\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      ")");

static const char d2_f10_2_https_text[] =
  PAD("v20     HTTPS   16 foo.example.org. alpn=f\\\092oo\092,bar,h2");
static const char d2_f10_2_https_generic_text[] =
  PAD("v20     HTTPS   \\# 35 (\n"
      "00 10                                              ; priority\n"
      "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
      "00 01                                              ; key 1\n"
      "00 0c                                              ; param length 12\n"
      "08                                                 ; alpn length 8\n"
      "66 5c 6f 6f 2c 62 61 72                            ; alpn value\n"
      "02                                                 ; alpn length 2\n"
      "68 32                                              ; alpn value\n"
      ")");

static const rdata_t d2_f10_rdata = RDATA(
  // priority
  0x00, 0x10,
  // target
  0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72, 0x67,
  0x00,
  // key 1
  0x00, 0x01,
  // length 12
  0x00, 0x0c,
  // alpn length 8
  0x08,
  // alpn value
  0x66, 0x5c, 0x6f, 0x6f, 0x2c, 0x62, 0x61, 0x72,
  // alpn length 2
  0x02,
  // alpn value
  0x68, 0x32);
#endif

// Failure cases copied from NSD
// svcb.failure-cases-01
// This example has multiple instances of the same SvcParamKey
static const char nsd_fc01_text[] =
  PAD("f01     SVCB   1 foo.example.com. (\n"
      "                       key123=abc key123=def\n"
      "                       )");

// svcb.failure-cases-02
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc02_text[] =
  PAD("f02     SVCB   1 foo.example.com. mandatory");

// svcb.failure-cases-03
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc03_text[] =
  PAD("f03     SVCB   1 foo.example.com. alpn");

// svcb.failure-cases-04
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc04_text[] =
  PAD("f04     SVCB   1 foo.example.com. port");

// svcb.failure-cases-05
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc05_text[] =
  PAD("f05     SVCB   1 foo.example.com. ipv4hint");

// svcb.failure-cases-06
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc06_text[] =
  PAD("f06     SVCB   1 foo.example.com. ipv6hint");

// svcb.failure-cases-07
// ; The "no-default-alpn" SvcParamKey value MUST be empty
static const char nsd_fc07_text[] =
  PAD("f07     SVCB   1 foo.example.com. no-default-alpn=abc");

// svcb.failure-cases-08
// In this record a mandatory SvcParam is missing
static const char nsd_fc08_text[] =
  PAD("f08     SVCB   1 foo.example.com. mandatory=key123");

// svcb.failure-cases-09
// The "mandatory" SvcParamKey MUST not be included in mandatory list
static const char nsd_fc09_text[] =
  PAD("f09     SVCB   1 foo.example.com. mandatory=mandatory");

// svcb.failure-cases-10
// Here there are multiple instances of the same SvcParamKey in the mandatory list
static const char nsd_fc10_text[] =
  PAD("f10     SVCB   1 foo.example.com. (\n"
      "                      mandatory=key123,key123 key123=abc\n"
      "                      )");

// svcb.failure-cases-11
// This example has multiple instances of the same SvcParamKey
static const char nsd_fc11_text[] =
  PAD("f11     HTTPS   1 foo.example.com. (\n"
      "                       key123=abc key123=def\n"
      "                       )");

// svcb.failure-cases-12
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc12_text[] =
  PAD("f12     HTTPS   1 foo.example.com. mandatory");

// svcb.failure-cases-13
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc13_text[] =
  PAD("f13     HTTPS   1 foo.example.com. alpn");

// svcb.failure-cases-14
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc14_text[] =
  PAD("f14     HTTPS   1 foo.example.com. port");

// svcb.failure-cases-15
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc15_text[] =
  PAD("f15     HTTPS   1 foo.example.com. ipv4hint");

// svcb.failure-cases-16
// In the next examples the SvcParamKeys are missing their values.
static const char nsd_fc16_text[] =
  PAD("f16     HTTPS   1 foo.example.com. ipv6hint");

// svcb.failure-cases-17
// The "no-default-alpn" SvcParamKey value MUST be empty
static const char nsd_fc17_text[] =
  PAD("f17     HTTPS   1 foo.example.com. no-default-alpn=abc");

// svcb.failure-cases-18
// In this record a mandatory SvcParam is missing
static const char nsd_fc18_text[] =
  PAD("f18     HTTPS   1 foo.example.com. mandatory=key123");

// svcb.failure-cases-19
// The "mandatory" SvcParamKey MUST not be included in mandatory list
static const char nsd_fc19_text[] =
  PAD("f19     HTTPS   1 foo.example.com. mandatory=mandatory");

// svcb.failure-cases-20
// Here there are multiple instances of the same SvcParamKey in the mandatory list
static const char nsd_fc20_text[] =
  PAD("f20     HTTPS   1 foo.example.com. (\n"
      "                      mandatory=key123,key123 key123=abc\n"
      "                      )");

#if 0
// simdzone cannot detect cross-record errors as no records are kept around.
// svcb.failure-cases-21
// Here there are multiple instances of the same SvcParamKey in the mandatory list
static const char nsd_fc21_text[] =
  PAD("f21     HTTPS   1 foo.example.com. ech=\"123\"\n"
      "f21     HTTPS   1 foo.example.com. echconfig=\"123\"");
#endif

// svcb.failure-cases-22
// Port mus be a positive number < 65536
static const char nsd_fc22_text[] =
  PAD("f22     HTTPS   1 foo.example.com. port=65536");

// svcb.failure-cases-23
// In the next example the SvcParamKey is missing their value.
static const char nsd_fc23_text[] =
  PAD("f23     HTTPS   1 foo.example.com. dohpath");


#if 0
// svcb.success-cases.zone (cut up into separate tests for debuggability)
// A particular key does not need to have a value
static const char nsd_s01_text[] =
  PAD("s01     SVCB   0 . key123");
static const rdata_t nsd_s01_rdata =
  RDATA();

// echconfig does not need to have a value
static const char nsd_s02_text[] =
  PAD("s02     SVCB   0 . echconfig");
static const rdata_t nsd_s02_rdata =
  RDATA();

// When "no-default-alpn" is specified in an RR, "alpn" must also be specified
// in order for the RR to be "self-consistent"
static const char nsd_s03_text[] =
  PAD("s03     HTTPS   0 . alpn="h2,h3" no-default-alpn");
static const rdata_t nsd_s03_rdata =
  RDATA();

// SHOULD is not MUST (so allowed)
// Zone-file implementations SHOULD enforce self-consistency
static const char nsd_s04_text[] =
  PAD("s04     HTTPS   0 . no-default-alpn");
static const rdata_t nsd_s04_rdata =
  RDATA();

// SHOULD is not MUST (so allowed)
// (port and no-default-alpn are automatically mandatory keys with HTTPS)
// Other automatically mandatory keys SHOULD NOT appear in the list either.
static const char nsd_s05_text[] =
  PAD("s05     HTTPS   0 . alpn="dot" no-default-alpn port=853 mandatory=port");
static const rdata_t nsd_s05_rdata =
  RDATA();

// Any valid base64 is okay for ech
static const char nsd_s06_text[] =
  PAD("s06     HTTPS   0 . ech=\"aGVsbG93b3JsZCE=\"");
static const rdata_t nsd_s06_rdata =
  RDATA();

// echconfig is an alias for ech
static const char nsd_s07_text[] =
  PAD("s07     HTTPS   0 . echconfig=\"aGVsbG93b3JsZCE=\"");
static const rdata_t nsd_s07_rdata =
  RDATA();

// dohpath can be (non-)quoted
static const char nsd_s08_text[] =
  PAD("s08     HTTPS   0 . alpn=h2 dohpath=\"/dns-query{?dns}\"");
static const rdata_t nsd_s08_rdata =
  RDATA();

static const char nsd_s09_text[] =
  PAD("s09     HTTPS   0 . alpn=h2 dohpath=/dns-query{é?dns}");
static const rdata_t nsd_s09_rdata =
  RDATA();
#endif



typedef struct test test_t;
struct test {
  uint16_t type;
  int32_t code;
  const char *text;
  const rdata_t *rdata;
};

static const test_t tests[] = {
  { ZONE_SVCB, 0, d1_svcb_text, &d1_rdata },
  { ZONE_SVCB, 0, d1_svcb_generic_text, &d1_rdata },
  { ZONE_HTTPS, 0, d1_https_text, &d1_rdata },
  { ZONE_HTTPS, 0, d1_https_generic_text, &d1_rdata},
  { ZONE_SVCB, 0, d2_f3_svcb_text, &d2_f3_rdata },
  { ZONE_SVCB, 0, d2_f3_svcb_generic_text, &d2_f3_rdata },
  { ZONE_HTTPS, 0, d2_f3_https_text, &d2_f3_rdata },
  { ZONE_HTTPS, 0, d2_f3_https_generic_text, &d2_f3_rdata },
  { ZONE_SVCB, 0, d2_f4_svcb_text, &d2_f4_rdata },
  { ZONE_SVCB, 0, d2_f4_svcb_generic_text, &d2_f4_rdata },
  { ZONE_HTTPS, 0, d2_f4_https_text, &d2_f4_rdata },
  { ZONE_HTTPS, 0, d2_f4_https_generic_text, &d2_f4_rdata },
  { ZONE_SVCB, 0, d2_f5_svcb_text, &d2_f5_rdata },
  { ZONE_SVCB, 0, d2_f5_svcb_generic_text, &d2_f5_rdata },
  { ZONE_HTTPS, 0, d2_f5_https_text, &d2_f5_rdata },
  { ZONE_HTTPS, 0, d2_f5_https_generic_text, &d2_f5_rdata },
  { ZONE_SVCB, 0, d2_f6_svcb_text, &d2_f6_rdata },
  { ZONE_SVCB, 0, d2_f6_svcb_generic_text, &d2_f6_rdata },
  { ZONE_HTTPS, 0, d2_f6_https_text, &d2_f6_rdata },
  { ZONE_HTTPS, 0, d2_f6_https_generic_text, &d2_f6_rdata },
  { ZONE_SVCB, 0, d2_f7_svcb_text, &d2_f7_rdata },
  { ZONE_SVCB, 0, d2_f7_svcb_generic_text, &d2_f7_rdata },
  { ZONE_HTTPS, 0, d2_f7_https_text, &d2_f7_rdata },
  { ZONE_HTTPS, 0, d2_f7_https_generic_text, &d2_f7_rdata },
  { ZONE_SVCB, 0, d2_f8_svcb_text, &d2_f8_rdata },
  { ZONE_SVCB, 0, d2_f8_svcb_generic_text, &d2_f8_rdata },
  { ZONE_HTTPS, 0, d2_f8_https_text, &d2_f8_rdata },
  { ZONE_HTTPS, 0, d2_f8_https_generic_text, &d2_f8_rdata },
  { ZONE_SVCB, 0, d2_f9_svcb_text, &d2_f9_rdata },
  { ZONE_SVCB, 0, d2_f9_svcb_generic_text, &d2_f9_rdata },
  { ZONE_HTTPS, 0, d2_f9_https_text, &d2_f9_rdata },
  { ZONE_HTTPS, 0, d2_f9_https_generic_text, &d2_f9_rdata },
#if 0
  { ZONE_SVCB, 0, d2_f10_1_svcb_text, &d2_f10_rdata },
  { ZONE_SVCB, 0, d2_f10_1_svcb_generic_text, &d2_f10_rdata },
  { ZONE_HTTPS, 0, d2_f10_1_https_text, &d2_f10_rdata },
  { ZONE_HTTPS, 0, d2_f10_1_https_generic_text, &d2_f10_rdata },
  { ZONE_SVCB, 0, d2_f10_2_svcb_text, &d2_f10_rdata },
  { ZONE_SVCB, 0, d2_f10_2_svcb_generic_text, &d2_f10_rdata },
  { ZONE_HTTPS, 0, d2_f10_2_https_text, &d2_f10_rdata },
  { ZONE_HTTPS, 0, d2_f10_2_https_generic_text, &d2_f10_rdata },
#endif
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc01_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc02_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc03_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc04_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc05_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc06_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc07_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc08_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc09_text, NULL },
  { ZONE_SVCB, ZONE_SEMANTIC_ERROR, nsd_fc10_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc11_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc12_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc13_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc14_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc15_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc16_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc17_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc18_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc19_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc20_text, NULL },
  { ZONE_HTTPS, ZONE_SYNTAX_ERROR, nsd_fc22_text, NULL },
  { ZONE_HTTPS, ZONE_SEMANTIC_ERROR, nsd_fc23_text, NULL }
};

static int32_t add_rr(
  zone_parser_t *parser,
  const zone_name_t *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  const test_t *test = user_data;
  (void)parser;
  (void)owner;
  (void)class;
  (void)ttl;
  if (type != test->type)
    return ZONE_SYNTAX_ERROR;
  if (test->code != ZONE_SUCCESS)
    return ZONE_SUCCESS;
  if (rdlength != test->rdata->length)
    return ZONE_SYNTAX_ERROR;
  if (memcmp(rdata, test->rdata->octets, rdlength) != 0)
    return ZONE_SYNTAX_ERROR;
  return ZONE_SUCCESS;
}

static uint8_t origin[] =
  { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

/*!cmocka */
void rfc9460_test_vectors(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    const test_t *test = &tests[i];
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t code;

    options.accept.callback = add_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    fprintf(stderr, "INPUT: '%s'\n", test->text);

    code = zone_parse_string(&parser, &options, &buffers, test->text, strlen(test->text), (void *)test);
    assert_int_equal(code, test->code);
  }
}
