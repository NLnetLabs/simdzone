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

#define EXAMPLE_COM \
  0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, \
  0x03, 0x63, 0x6f, 0x6d, 0x00

#define HOST_EXAMPLE_COM \
  0x04, 0x68, 0x6f, 0x73, 0x74, EXAMPLE_COM

#define HOSTMASTER_EXAMPLE_COM \
  0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, \
  0x74, 0x65, 0x72, EXAMPLE_COM

#define RDATA(...) \
 { sizeof( (const uint8_t[]){ __VA_ARGS__ } )/sizeof(uint8_t), (const uint8_t[]){ __VA_ARGS__ } }

typedef struct rdata rdata_t;
struct rdata {
  size_t length;
  const uint8_t *octets;
};

static const char a_text[] =
  PAD("foo. A 192.0.2.1");
static const char a_generic_text[] =
  PAD("foo. A \\# 4 c0000201");
static const rdata_t a_rdata =
  RDATA(0xc0, 0x00, 0x02, 0x01);

static const char ns_text[] =
  PAD("foo. NS host.example.com.");
static const char ns_generic_text[] =
  PAD("foo. NS \\# 18 04686f7374076578616d706c6503636f6d00");
static const rdata_t ns_rdata =
  RDATA(HOST_EXAMPLE_COM);

static const char md_text[] =
  PAD("foo. MD host.example.com.");
static const char md_generic_text[] =
  PAD("foo. MD \\# 18 04686f7374076578616d706c6503636f6d00");
static const char mf_text[] =
  PAD("foo. MF host.example.com.");
static const char mf_generic_text[] =
  PAD("foo. MF \\# 18 04686f7374076578616d706c6503636f6d00");
static const char cname_text[] =
  PAD("foo. CNAME host.example.com.");
static const char cname_generic_text[] =
  PAD("foo. CNAME \\# 18 04686f7374076578616d706c6503636f6d00");

static const char soa_text[] =
  PAD("foo. SOA host.example.com. hostmaster.example.com. 2023063001 1 2 3 4");
static const char soa_generic_text[] =
  PAD("foo. SOA \\# 62 04686f7374076578616d706c6503636f6d00"
      "                0a686f73746d6173746572076578616d706c6503636f6d00"
      "                78957dd9"
      "                00000001"
      "                00000002"
      "                00000003"
      "                00000004");
static const rdata_t soa_rdata =
  RDATA(/* host.example.com. */
        HOST_EXAMPLE_COM,
        /* hostmaster.example.com. */
        HOSTMASTER_EXAMPLE_COM,
        /* 2023063001 */
        0x78, 0x95, 0x7d, 0xd9,
        /* 1 */
        0x00, 0x00, 0x00, 0x01,
        /* 2 */
        0x00, 0x00, 0x00, 0x02,
        /* 3 */
        0x00, 0x00, 0x00, 0x03,
        /* 4 */
        0x00, 0x00, 0x00, 0x04
      );

static const char mb_text[] =
  PAD("foo. MB host.example.com.");
static const char mb_generic_text[] =
  PAD("foo. MB \\# 18 04686f7374076578616d706c6503636f6d00");

static const char mg_text[] =
  PAD("foo. MG hostmaster.example.com.");
static const char mg_generic_text[] =
  PAD("foo. MG \\# 24 0a686f73746d6173746572076578616d706c6503636f6d00");
static const rdata_t mg_rdata = RDATA(HOSTMASTER_EXAMPLE_COM);

static const char mr_text[] =
  PAD("foo. MR hostmaster.example.com.");
static const char mr_generic_text[] =
  PAD("foo. MR \\# 24 0a686f73746d6173746572076578616d706c6503636f6d00");
static const char ptr_text[] =
  PAD("foo. PTR host.example.com.");
static const char ptr_generic_text[] =
  PAD("foo. PTR \\# 18 04686f7374076578616d706c6503636f6d00");

static const char wks_text[] =
  PAD("foo. WKS 192.0.2.1 tcp 0 tcpmux");
static const char wks_generic_text[] =
  PAD("foo. TYPE11 \\# 6 c0000201 06 c0");
static const rdata_t wks_rdata =
  RDATA(/* address */
        0xc0, 0x00, 0x02, 0x01,
        /* protocol */
        0x06,
        /* bitmap */
        0xc0);

static const char hinfo_text[] =
  PAD("foo. HINFO amd64 linux");
static const char hinfo_generic_text[] =
  PAD("foo. HINFO \\# 12 05616d643634 056c696e7578");
static const rdata_t hinfo_rdata =
  RDATA(/* amd64 */
        5, 'a', 'm', 'd', '6', '4',
        /* linux */
        5, 'l', 'i', 'n', 'u', 'x');

static const char minfo_text[] =
  PAD("foo. MINFO hostmaster.example.com. hostmaster.example.com.");
static const char minfo_generic_text[] =
  PAD("foo. MINFO \\# 48 0a686f73746d6173746572076578616d706c6503636f6d00"
      "                  0a686f73746d6173746572076578616d706c6503636f6d00");
static const rdata_t minfo_rdata =
  RDATA(HOSTMASTER_EXAMPLE_COM, HOSTMASTER_EXAMPLE_COM);

static const char mx_text[] =
  PAD("foo. MX 10 host.example.com.");
static const char mx_generic_text[] =
  PAD("foo. MX \\# 20 000a 04686f7374076578616d706c6503636f6d00");
static const rdata_t mx_rdata =
  RDATA(/* 10 */
        0x00, 0x0a,
        /* host.example.com. */
        HOST_EXAMPLE_COM);

static const char txt_text[] =
  PAD("foo. TXT example of TXT rdata");
static const char txt_generic_text[] =
  PAD("foo. TXT \\# 21 076578616d706c65 026f66 03545854 057264617461");
static const rdata_t txt_rdata =
  RDATA(/* example */
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        /* of */
        0x02, 0x6f, 0x66,
        /* TXT */
        0x03, 0x54, 0x58, 0x54,
        /* rdata */
        0x05, 0x72, 0x64, 0x61, 0x74, 0x61);

static const char rp_text[] =
  PAD("foo. RP hostmaster.example.com. host.example.com.");
static const char rp_generic_text[] =
  PAD("foo. RP \\# 42 0a686f73746d6173746572076578616d706c6503636f6d00"
      "               04686f7374076578616d706c6503636f6d00");
static const rdata_t rp_rdata =
  RDATA(HOSTMASTER_EXAMPLE_COM, HOST_EXAMPLE_COM);

static const char afsdb_text[] =
  PAD("foo. AFSDB 1 host.example.com.");
static const char afsdb_generic_text[] =
  PAD("foo. AFSDB \\# 20 0001 04686f7374076578616d706c6503636f6d00");
static const rdata_t afsdb_rdata =
  RDATA(/* 1 */
        0x00, 0x01,
        /* host.example.com. */
        HOST_EXAMPLE_COM);

static const char x25_text[] =
  PAD("foo. X25 311061700956");
static const char x25_generic_text[] =
  PAD("foo. X25 \\# 13 0c333131303631373030393536");
static const rdata_t x25_rdata =
  RDATA(0x0c, 0x33, 0x31, 0x31, 0x30, 0x36, 0x31, 0x37,
        0x30, 0x30, 0x39, 0x35, 0x36);

static const char isdn_text[] =
  PAD("foo. ISDN 150862028003217 004");
static const char isdn_generic_text[] =
  PAD("foo. ISDN \\# 20 0f313530383632303238303033323137 03303034");
static const rdata_t isdn_rdata =
  RDATA(0x0f, 0x31, 0x35, 0x30, 0x38, 0x36, 0x32, 0x30,
        0x32, 0x38, 0x30, 0x30, 0x33, 0x32, 0x31, 0x37,
        0x03, 0x30, 0x30, 0x34);

static const char rt_text[] =
  PAD("foo. RT 10 relay.example.com.");
static const char rt_generic_text[] =
  PAD("foo. RT \\# 21 000a 0572656c6179076578616d706c6503636f6d00");
static const rdata_t rt_rdata =
  RDATA(/* 10 */
        0x00, 0x0a,
        /* relay.example.com. */
        0x05, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x07, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
        0x6f, 0x6d, 0x00);

static const char nsap_text[] =
  PAD("foo. NSAP 0x47.0005.80.005a00.0000.0001.e133.aaaaaa000111.00");
static const char nsap_generic_text[] =
  PAD("foo. TYPE22 \\# 20 47 0005 80 005a00 0000 0001 e133 aaaaaa000111 00");
static const rdata_t nsap_rdata =
  RDATA(0x47, 0x00, 0x05, 0x80, 0x00, 0x5a, 0x00, 0x00,
        0x00, 0x00, 0x01, 0xe1, 0x33, 0xaa, 0xaa, 0xaa,
        0x00, 0x01, 0x11, 0x00);

static const char nsap_ptr_text[] =
  PAD("0.0.2.6.1.0.0.0.f.f.f.f.f.f.3.3.1.e.1.0.0.0.0.0.0.0.0.0.a.5.0.0.0.8.5.0.0.0.7.4.NSAP.INT. NSAP-PTR host.example.com.");
static const rdata_t nsap_ptr_rdata =
  RDATA(4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0);

static const char sig_text[] =
  PAD("big.foo.tld. SIG NXT 1 3 (  ;type-cov=NXT, alg=1, labels=3\n"
      "             3600           ;original ttl\n"
      "             19960102030405 ;signature expiration\n"
      "             19951211100908 ;time signed\n"
      "             21435          ;key footprint\n"
      "             foo.tld.       ;signer\n"
      "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6VAuHAoNUz4YoU\n"
      "1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=\n"
      ")");
static const rdata_t sig_rdata =
  RDATA(0, 30, // type covered
        1, // algorithm
        3, // labels
        0x00, 0x00, 0x0e, 0x10, // original ttl
        0x30, 0xe8, 0xa0, 0xa5, // signature
        0x30, 0xcc, 0x03, 0x44, // time signed
        0x53, 0xbb, // key footprint
        3, 'f', 'o', 'o', 3, 't', 'l', 'd', 0, // signer
        // signature
        0x33, 0x11, 0x5c, 0x6f, 0x2f, 0x64, 0xff, 0x2b, 0xde, 0x74,
        0xc7, 0xd0, 0x80, 0xac, 0xe1, 0x1f, 0x97, 0xab, 0xd0, 0xcb,
        0xbf, 0xbc, 0x82, 0xf3, 0xe3, 0x92, 0x24, 0xb2, 0x47, 0x1e,
        0x14, 0x68, 0x22, 0x58, 0x29, 0xff, 0x1b, 0x11, 0xe1, 0x6a,
        0x2e, 0x95, 0x02, 0xe1, 0xc0, 0xa0, 0xd5, 0x33, 0xe1, 0x8a,
        0x14, 0xd6, 0xd5, 0x5f, 0x48, 0x24, 0xaa, 0x41, 0x89, 0xfa,
        0xff, 0xfd, 0x75, 0x53, 0xa3, 0x65, 0x77, 0xcd, 0x23, 0x11,
        0xe0, 0xbc, 0x69, 0x3a, 0xce, 0xf8, 0xa2, 0xa6, 0x09, 0xa6);

static const char key_text[] =
  PAD("foo. KEY 0 0 0 Zm9vYmFy");
static const char key_generic_text[] =
  PAD("foo. KEY \\# 10 00000000666f6f626172");
static const rdata_t key_rdata =
  RDATA(0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72);

static const char gpos_text[] =
  PAD("foo. GPOS -32.6882 116.8652 10.0");
static const rdata_t gpos_rdata =
  RDATA(/* latitude */
        8, '-', '3', '2', '.', '6', '8', '8', '2',
        /* longitude */
        8, '1', '1', '6', '.', '8', '6', '5', '2',
        /* altitude */
        4, '1', '0', '.', '0');

static const char px_text[] =
  PAD("*.ab.fr.  IN  PX  50  ab.fr.  PRMD-ab.ADMD-ac.C-fr.");
static const char px_generic_text[] =
  PAD("*.ab.fr.  IN  TYPE26 \\# 31 0032 02616202667200 0750524d442d61620741444d442d616304432d667200");
static const rdata_t px_rdata =
  RDATA(/* preference */
        0x00, 0x32,
        /* map822 */
        0x02, 'a', 'b', 0x02, 'f', 'r', 0x00,
        /* mapx400 */
        0x07, 'P', 'R', 'M', 'D', '-', 'a', 'b',
        0x07, 'A', 'D', 'M', 'D', '-', 'a', 'c',
        0x04, 'C', '-', 'f', 'r', 0x00);

// RFC1876
static const char loc_text[] =
  PAD("cambridge-net.kei.com. LOC 42 21 54 N 71 06 18 W -24m 30m");
static const rdata_t loc_rdata =
  RDATA(0x00, // version (always 0)
        0x33, // size (default 1m)
        0x16, // horizontal precision (default 10000m)
        0x13, // vertical precision (default 10m)
        0x89, 0x17, 0x2d, 0xd0, // latitude
        0x70, 0xbe, 0x15, 0xf0, // longitude
        0x00, 0x98, 0x8d, 0x20); // altitude

static const char nxt_text[] =
  PAD("big.foo.tld. NXT medium.foo.tld. A MX SIG NXT");
static const rdata_t nxt_rdata =
  RDATA(6, 'm', 'e', 'd', 'i', 'u', 'm', 3, 'f', 'o', 'o', 3, 't', 'l', 'd', 0,
        0x40, 0x01, 0x00, 0x82);

static const char naptr_text[] =
  PAD("foo. NAPTR 100 50 \"s\" \"http+I2L+I2C+I2R\" \"\"  _http._tcp.gatech.edu.");
static const char naptr_generic_text[] =
  PAD("foo. NAPTR \\# 47 0064"
      "                  0032"
      "                  0173"
      "                  10687474702b49324c2b4932432b493252"
      "                  00"
      "                  055f68747470045f746370066761746563680365647500");
static const rdata_t naptr_rdata =
  RDATA(/* order */
        0x00, 0x64,
        /* preference */
        0x00, 0x32,
        /* flags */
        0x01, 0x73,
        /* service */
        0x10, 0x68, 0x74, 0x74, 0x70, 0x2b, 0x49, 0x32,
        0x4c, 0x2b, 0x49, 0x32, 0x43, 0x2b, 0x49, 0x32,
        0x52,
        /* regexp */
        0x00,
        /* replacement */
        0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5f,
        0x74, 0x63, 0x70, 0x06, 0x67, 0x61, 0x74, 0x65,
        0x63, 0x68, 0x03, 0x65, 0x64, 0x75, 0x00);

static const char kx_text[] =
  PAD("foo. KX 10 kx-host");
static const char kx_generic_text[] =
  PAD("foo. KX \\# 23 000a 076b782d686f7374076578616d706c6503636f6d00");
static const rdata_t kx_rdata =
  RDATA(0x00, 0x0a, 0x07, 0x6b, 0x78, 0x2d, 0x68, 0x6f, 0x73, 0x74, EXAMPLE_COM);

static const char cert_text[] =
  PAD("foo. CERT PKIX 65535 RSASHA256 Zm9vYmFy");
static const rdata_t cert_rdata =
  RDATA(/* type */
        0x00, 0x01,
        /* key tag */
        0xff, 0xff,
        /* algorithm */
        0x08,
        /* certificate */
        0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72);

static const char dname_text[] = PAD("foo. DNAME host.example.com.");
static const char dname_generic_text[] =
  PAD("foo. DNAME \\# 18 04686f7374076578616d706c6503636f6d00");
static const rdata_t dname_rdata = RDATA(HOST_EXAMPLE_COM);

static const char apl_text[] =
  PAD("foo.example. IN APL 1:192.168.32.0/21 !1:192.168.38.0/28");
static const rdata_t apl_rdata =
  RDATA(/* 1:192.168.32.0/21 */
        0, 1, 21, 0x04, 192, 168, 32, 0,
        /* !1:192.168.38.0/28 */
        0, 1, 28, 0x84, 192, 168, 38, 0);

static const char sshfp_text[] =
  PAD("foo. SSHFP 4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789");
static const char sshfp_generic_text[] =
  PAD("foo. SSHFP \\# 34 04 02"
      "               123456789abcdef6"
      "               7890123456789abc"
      "               def6789012345678"
      "               9abcdef123456789");
static const rdata_t sshfp_rdata =
  RDATA(/* algorithm */
        0x04,
        /* type */
        0x02,
        /* fingerprint */
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf6,
        0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf6, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89);

static const char ipseckey_text[] =
  PAD("38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 0 2\n"
      "                 .\n"
      "                 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )");
static const rdata_t ipseckey_rdata =
  RDATA(/* precedence */
        0x0a,
        /* gateway type */
        0x00,
        /* algorithm */
        0x02,
        /* no gateway */
        /* public key */
        0x01, 0x03, 0x51, 0x53, 0x79, 0x86, 0xed, 0x35,
        0x53, 0x3b, 0x60, 0x64, 0x47, 0x8e, 0xee, 0xb2,
        0x7b, 0x5b, 0xd7, 0x4d, 0xae, 0x14, 0x9b, 0x6e,
        0x81, 0xba, 0x3a, 0x05, 0x21, 0xaf, 0x82, 0xab,
        0x78, 0x01);

static const char ipseckey_ipv4_text[] =
  PAD("38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 1 2\n"
      "                 192.0.2.38\n"
      "                 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )");
static const rdata_t ipseckey_ipv4_rdata =
  RDATA(/* precedence */
        0x0a,
        /* gateway type */
        0x01,
        /* algorithm */
        0x02,
        /* gateway */
        0xc0, 0x00, 0x02, 0x26,
        /* public key */
        0x01, 0x03, 0x51, 0x53, 0x79, 0x86, 0xed, 0x35,
        0x53, 0x3b, 0x60, 0x64, 0x47, 0x8e, 0xee, 0xb2,
        0x7b, 0x5b, 0xd7, 0x4d, 0xae, 0x14, 0x9b, 0x6e,
        0x81, 0xba, 0x3a, 0x05, 0x21, 0xaf, 0x82, 0xab,
        0x78, 0x01);

static const char ipseckey_ipv6_text[] =
  PAD("$ORIGIN 1.0.0.0.0.0.2.8.B.D.0.1.0.0.2.ip6.arpa.\n"
      "0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.0 7200 IN     IPSECKEY ( 10 2 2\n"
      "                 2001:0DB8:0:8002::2000:1\n"
      "                 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )");
static const rdata_t ipseckey_ipv6_rdata =
  RDATA(/* precedence */
        0x0a,
        /* gateway type */
        0x02,
        /* algorithm */
        0x02,
        /* gateway */
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x80, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01,
        /* public key */
        0x01, 0x03, 0x51, 0x53, 0x79, 0x86, 0xed, 0x35,
        0x53, 0x3b, 0x60, 0x64, 0x47, 0x8e, 0xee, 0xb2,
        0x7b, 0x5b, 0xd7, 0x4d, 0xae, 0x14, 0x9b, 0x6e,
        0x81, 0xba, 0x3a, 0x05, 0x21, 0xaf, 0x82, 0xab,
        0x78, 0x01);

static const char ipseckey_name_text[] =
  PAD("38.1.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 3 2\n"
      "                 mygateway.example.com.\n"
      "                 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )");
static const rdata_t ipseckey_name_rdata =
  RDATA(/* precedence */
        0x0a,
        /* gateway type */
        0x03,
        /* algorithm */
        0x02,
        /* gateway */
        0x09,  'm',  'y',  'g',  'a',  't',  'e',  'w',
         'a',  'y', 0x07,  'e',  'x',  'a',  'm',  'p',
         'l',  'e', 0x03,  'c',  'o',  'm', 0x00,
        /* public key */
        0x01, 0x03, 0x51, 0x53, 0x79, 0x86, 0xed, 0x35,
        0x53, 0x3b, 0x60, 0x64, 0x47, 0x8e, 0xee, 0xb2,
        0x7b, 0x5b, 0xd7, 0x4d, 0xae, 0x14, 0x9b, 0x6e,
        0x81, 0xba, 0x3a, 0x05, 0x21, 0xaf, 0x82, 0xab,
        0x78, 0x01);

// https://datatracker.ietf.org/doc/html/rfc4034#section-4.3
static const char nsec_text[] =
  PAD("alfa.example.com. 86400 IN NSEC host.example.com. ( \n"
      "                                A MX RRSIG NSEC TYPE1234 )");

static const rdata_t nsec_rdata =
  RDATA(0x04, 'h',  'o',  's',  't',
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',  0x00,
        0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20);

// https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.2.1
static const char nsec3_no_data_text[] =
  PAD("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd (\n"
      "                       k8udemvp1j2f7eg6jebps17vp3n8i58h )");

static const rdata_t nsec3_no_data_rdata =
  RDATA(0x01, 0x01, 0x00, 0x0c, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0x14, 0xa2, 0x3c, 0xd7, 0x5b, 0xf9, 0x0c, 0xc4, 0xf3,
        0xba, 0x06, 0x9b, 0x97, 0x9e, 0x04, 0xff, 0xc8, 0xee,
        0x89, 0x15, 0x11);

// https://www.rfc-editor.org/rfc/rfc4701.html#section-3.6.1
static const char dhcid_text[] =
  PAD("foo. DHCID   ( AAIBY2/AuCccgoJbsaxcQc9TUapptP69l"
      "               OjxfNuVAA2kjEA= )");
static const char dhcid_generic_text[] =
  PAD("foo. DHCID \\# 35 ( 000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cd"
      "                    b95000da48c40 )");
static const rdata_t dhcid_rdata =
  RDATA(0x00, 0x02, 0x01, 0x63, 0x6f, 0xc0, 0xb8, 0x27,
        0x1c, 0x82, 0x82, 0x5b, 0xb1, 0xac, 0x5c, 0x41,
        0xcf, 0x53, 0x51, 0xaa, 0x69, 0xb4, 0xfe, 0xbd,
        0x94, 0xe8, 0xf1, 0x7c, 0xdb, 0x95, 0x00, 0x0d,
        0xa4, 0x8c, 0x40);

static const char tlsa_text[] =
  PAD("foo. TLSA 0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971");
static const char tlsa_generic_text[] =
  PAD("foo. TLSA \\# 35 00 00 01 ( d2abde240d7cd3ee6b4b28c54df034b9"
      "                            7983a1d16e8a410e4561cb106618e971 )");
static const rdata_t tlsa_rdata =
  RDATA(/* usage */
        0x00,
        /* selector */
        0x00,
        /* matching type */
        0x01,
        /* certificate association data */
        0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee,
        0x6b, 0x4b, 0x28, 0xc5, 0x4d, 0xf0, 0x34, 0xb9,
        0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
        0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71);

static const char smimea_text[] =
  PAD("foo. SMIMEA 0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971");
static const char smimea_generic_text[] =
  PAD("foo. SMIMEA \\# 35 00 00 01 ( d2abde240d7cd3ee6b4b28c54df034b9"
      "                              7983a1d16e8a410e4561cb106618e971 )");
static const rdata_t smimea_rdata =
  RDATA(/* usage */
        0x00,
        /* selector */
        0x00,
        /* matching type */
        0x01,
        /* certificate association data */
        0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee,
        0x6b, 0x4b, 0x28, 0xc5, 0x4d, 0xf0, 0x34, 0xb9,
        0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
        0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71);

static const char hip_text[] =
  PAD("www.example.com. IN HIP ( 2 200100107B1A74DF365639CC39F1D578\n"
      "                          AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cI"
      "vM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ry"
      "ra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXd"
      "XF5D\n"
      "                          rvs1.example.com.\n"
      "                          rvs2.example.com. )");
static const rdata_t hip_rdata =
  RDATA(// HIT length
        0x10,
        // PK algorithm
        2,
        // Public Key length
        0x00, 0x84,
        // HIT
        0x20, 0x01, 0x00, 0x10, 0x7b, 0x1a, 0x74, 0xdf, 0x36, 0x56, 0x39, 0xcc,
        0x39, 0xf1, 0xd5, 0x78,
        // Public Key
        0x03, 0x01, 0x00, 0x01, 0xb7, 0x71, 0xca, 0x13, 0x6e, 0x4a, 0xeb, 0x5c,
        0xe4, 0x43, 0x33, 0xc5, 0x3b, 0x3d, 0x2c, 0x13, 0xc2, 0x22, 0x43, 0x85,
        0x1f, 0xc7, 0x08, 0xbc, 0xce, 0x29, 0xf7, 0xe2, 0xeb, 0x57, 0x87, 0xb5,
        0xf5, 0x6c, 0xca, 0xd3, 0x4f, 0x82, 0x23, 0xac, 0xc1, 0x09, 0x04, 0xdd,
        0xb5, 0x6b, 0x2e, 0xc4, 0xa6, 0xd6, 0x23, 0x2f, 0x3b, 0x50, 0xea, 0x09,
        0x4f, 0x09, 0x14, 0xb3, 0xb9, 0x41, 0xbb, 0xe5, 0x29, 0xaf, 0x58, 0x2c,
        0x36, 0xbb, 0xad, 0xef, 0xda, 0xf2, 0xad, 0xaf, 0x9b, 0x49, 0x11, 0x90,
        0x6f, 0x5b, 0x25, 0x22, 0x60, 0x3c, 0x61, 0x52, 0x72, 0xb8, 0x80, 0xec,
        0x8f, 0xb9, 0x30, 0xcc, 0x6e, 0xe3, 0x9c, 0x44, 0x4d, 0xaa, 0x75, 0xb1,
        0x67, 0x8f, 0x00, 0x5a, 0x4b, 0x24, 0x99, 0xd1, 0xda, 0x54, 0x33, 0xf8,
        0x05, 0xc7, 0xa5, 0xad, 0x32, 0x37, 0xac, 0xc5, 0xdd, 0x5c, 0x5e, 0x43,
        // rvs1.example.com
        4, 'r', 'v', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        // rvs2.example.com
        4, 'r', 'v', 's', '2', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        );

static const char cds_text[] =
  PAD("foo. CDS 58470 5 1 ( 3079F1593EBAD6DC121E202A8B766A6A4837206C )");
static const char cds_generic_text[] =
  PAD("foo. CDS \\# 24 e466 05 01 3079f1593ebad6dc121e202a8b766a6a4837206c");
static const rdata_t cds_rdata =
  RDATA(0xe4, 0x66,
        0x05,
        0x01,
        0x30, 0x79, 0xf1, 0x59, 0x3e, 0xba, 0xd6, 0xdc,
        0x12, 0x1e, 0x20, 0x2a, 0x8b, 0x76, 0x6a, 0x6a,
        0x48, 0x37, 0x20, 0x6c);

static const char cdnskey_text[] =
  PAD("foo. CDNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3"
      "                       Cbl+BBZH4b/0PY1kxkmvHjcZc8no"
      "                       kfzj31GajIQKY+5CptLr3buXA10h"
      "                       WqTkF7H6RfoRqXQeogmMHfpftf6z"
      "                       Mv1LyBUgia7za6ZEzOJBOztyvhjL"
      "                       742iU/TpPSEDhm2SNKLijfUppn1U"
      "                       aNvv4w== )");
static const char cdnskey_generic_text[] = PAD(
  "foo. CDNSKEY \\# 134 0100 03 05"
  "     0103d22a6ca77f35"
  "     b893206fd35e4c50"
  "     6d8378843709b97e"
  "     041647e1bff43d8d"
  "     64c649af1e371973"
  "     c9e891fce3df519a"
  "     8c840a63ee42a6d2"
  "     ebddbb97035d215a"
  "     a4e417b1fa45fa11"
  "     a9741ea2098c1dfa"
  "     5fb5feb332fd4bc8"
  "     152089aef36ba644"
  "     cce2413b3b72be18"
  "     cbef8da253f4e93d"
  "     2103866d9234a2e2"
  "     8df529a67d5468db"
  "     efe3"
);
static const rdata_t cdnskey_rdata =
  RDATA(/* flags */
        0x01, 0x00,
        /* protocol */
        0x03,
        /* algorithm */
        0x05,
        /* public key */
        0x01, 0x03, 0xd2, 0x2a, 0x6c, 0xa7, 0x7f, 0x35,
        0xb8, 0x93, 0x20, 0x6f, 0xd3, 0x5e, 0x4c, 0x50,
        0x6d, 0x83, 0x78, 0x84, 0x37, 0x09, 0xb9, 0x7e,
        0x04, 0x16, 0x47, 0xe1, 0xbf, 0xf4, 0x3d, 0x8d,
        0x64, 0xc6, 0x49, 0xaf, 0x1e, 0x37, 0x19, 0x73,
        0xc9, 0xe8, 0x91, 0xfc, 0xe3, 0xdf, 0x51, 0x9a,
        0x8c, 0x84, 0x0a, 0x63, 0xee, 0x42, 0xa6, 0xd2,
        0xeb, 0xdd, 0xbb, 0x97, 0x03, 0x5d, 0x21, 0x5a,
        0xa4, 0xe4, 0x17, 0xb1, 0xfa, 0x45, 0xfa, 0x11,
        0xa9, 0x74, 0x1e, 0xa2, 0x09, 0x8c, 0x1d, 0xfa,
        0x5f, 0xb5, 0xfe, 0xb3, 0x32, 0xfd, 0x4b, 0xc8,
        0x15, 0x20, 0x89, 0xae, 0xf3, 0x6b, 0xa6, 0x44,
        0xcc, 0xe2, 0x41, 0x3b, 0x3b, 0x72, 0xbe, 0x18,
        0xcb, 0xef, 0x8d, 0xa2, 0x53, 0xf4, 0xe9, 0x3d,
        0x21, 0x03, 0x86, 0x6d, 0x92, 0x34, 0xa2, 0xe2,
        0x8d, 0xf5, 0x29, 0xa6, 0x7d, 0x54, 0x68, 0xdb,
        0xef, 0xe3);

// generated using https://www.huque.com/bin/openpgpkey with
// input from https://www.ietf.org/archive/id/draft-bre-openpgp-samples-01.html
static const char openpgpkey_text[] =
  PAD("2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db._openpgpkey.openpgp.example. IN OPENPGPKEY ("
      "           mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmz"
      "           lC/Ub7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1w"
      "           bGU+iJAEExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtf"
      "           ozp14V6UTmPyMVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOm"
      "           sHOsd9qGsiZpgRnOdypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9R"
      "           iJsvawAfCPaQZoed8gK4OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzg"
      "           qbXCpDDYMiKRVitCsy203x3sE9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp1"
      "           4V6UTmPyMVUMT0fjjgUCXEcE6QIbDAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcx"
      "           rNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+QFs"
      "           mz55/lntWkwYWhmvOgE="
      ")");
static const char openpgpkey_generic_text[] =
  PAD("2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db._openpgpkey.openpgp.example. IN TYPE61 \\# 419 ("
      "           9833045c4704e916092b06010401da470f01010740ae35b0937140ab2885"
      "           6c504a4f84f35dc541a8f4c1de09b3942fd46fb3b5bb5db426416c696365"
      "           204c6f76656c616365203c616c696365406f70656e7067702e6578616d70"
      "           6c653e8890041316080038021b03050b0908070206150a09080b02041602"
      "           0301021e01021780162104eb85bb5fa33a75e15e944e63f231550c4f47e3"
      "           8e05025da59f3a000a0910f231550c4f47e38ee92b00fa039c7052a203a6"
      "           b073ac77da86b226698119ce772a6f6e6f90b5766ab61f6bbf00fd1dc0c2"
      "           d2d0be3c702c3bb3938754b54c2f51889b2f6b001f08f69066879df202b8"
      "           38045c4704e9120a2b06010401975501050101074042ff0621adab493ce0"
      "           a9b5c2a430d8322291562b42b32db4df1dec13df9ebe2203010807887804"
      "           1816080020162104eb85bb5fa33a75e15e944e63f231550c4f47e38e0502"
      "           5c4704e9021b0c000a0910f231550c4f47e38e59d00100c51d4b3a4c8731"
      "           acd4ed1191635059b53343c9d439e0fdc0d6e3137cd1fb27d10100db62ab"
      "           ed59028de0040b4f15493795f9016c9b3e79fe59ed5a4c185a19af3a01"
      ")");
static const rdata_t openpgpkey_rdata =
  RDATA(0x98, 0x33, 0x04, 0x5c, 0x47, 0x04, 0xe9, 0x16,
        0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47,
        0x0f, 0x01, 0x01, 0x07, 0x40, 0xae, 0x35, 0xb0,
        0x93, 0x71, 0x40, 0xab, 0x28, 0x85, 0x6c, 0x50,
        0x4a, 0x4f, 0x84, 0xf3, 0x5d, 0xc5, 0x41, 0xa8,
        0xf4, 0xc1, 0xde, 0x09, 0xb3, 0x94, 0x2f, 0xd4,
        0x6f, 0xb3, 0xb5, 0xbb, 0x5d, 0xb4, 0x26, 0x41,
        0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c, 0x6f, 0x76,
        0x65, 0x6c, 0x61, 0x63, 0x65, 0x20, 0x3c, 0x61,
        0x6c, 0x69, 0x63, 0x65, 0x40, 0x6f, 0x70, 0x65,
        0x6e, 0x70, 0x67, 0x70, 0x2e, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x3e, 0x88, 0x90, 0x04,
        0x13, 0x16, 0x08, 0x00, 0x38, 0x02, 0x1b, 0x03,
        0x05, 0x0b, 0x09, 0x08, 0x07, 0x02, 0x06, 0x15,
        0x0a, 0x09, 0x08, 0x0b, 0x02, 0x04, 0x16, 0x02,
        0x03, 0x01, 0x02, 0x1e, 0x01, 0x02, 0x17, 0x80,
        0x16, 0x21, 0x04, 0xeb, 0x85, 0xbb, 0x5f, 0xa3,
        0x3a, 0x75, 0xe1, 0x5e, 0x94, 0x4e, 0x63, 0xf2,
        0x31, 0x55, 0x0c, 0x4f, 0x47, 0xe3, 0x8e, 0x05,
        0x02, 0x5d, 0xa5, 0x9f, 0x3a, 0x00, 0x0a, 0x09,
        0x10, 0xf2, 0x31, 0x55, 0x0c, 0x4f, 0x47, 0xe3,
        0x8e, 0xe9, 0x2b, 0x00, 0xfa, 0x03, 0x9c, 0x70,
        0x52, 0xa2, 0x03, 0xa6, 0xb0, 0x73, 0xac, 0x77,
        0xda, 0x86, 0xb2, 0x26, 0x69, 0x81, 0x19, 0xce,
        0x77, 0x2a, 0x6f, 0x6e, 0x6f, 0x90, 0xb5, 0x76,
        0x6a, 0xb6, 0x1f, 0x6b, 0xbf, 0x00, 0xfd, 0x1d,
        0xc0, 0xc2, 0xd2, 0xd0, 0xbe, 0x3c, 0x70, 0x2c,
        0x3b, 0xb3, 0x93, 0x87, 0x54, 0xb5, 0x4c, 0x2f,
        0x51, 0x88, 0x9b, 0x2f, 0x6b, 0x00, 0x1f, 0x08,
        0xf6, 0x90, 0x66, 0x87, 0x9d, 0xf2, 0x02, 0xb8,
        0x38, 0x04, 0x5c, 0x47, 0x04, 0xe9, 0x12, 0x0a,
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01,
        0x05, 0x01, 0x01, 0x07, 0x40, 0x42, 0xff, 0x06,
        0x21, 0xad, 0xab, 0x49, 0x3c, 0xe0, 0xa9, 0xb5,
        0xc2, 0xa4, 0x30, 0xd8, 0x32, 0x22, 0x91, 0x56,
        0x2b, 0x42, 0xb3, 0x2d, 0xb4, 0xdf, 0x1d, 0xec,
        0x13, 0xdf, 0x9e, 0xbe, 0x22, 0x03, 0x01, 0x08,
        0x07, 0x88, 0x78, 0x04, 0x18, 0x16, 0x08, 0x00,
        0x20, 0x16, 0x21, 0x04, 0xeb, 0x85, 0xbb, 0x5f,
        0xa3, 0x3a, 0x75, 0xe1, 0x5e, 0x94, 0x4e, 0x63,
        0xf2, 0x31, 0x55, 0x0c, 0x4f, 0x47, 0xe3, 0x8e,
        0x05, 0x02, 0x5c, 0x47, 0x04, 0xe9, 0x02, 0x1b,
        0x0c, 0x00, 0x0a, 0x09, 0x10, 0xf2, 0x31, 0x55,
        0x0c, 0x4f, 0x47, 0xe3, 0x8e, 0x59, 0xd0, 0x01,
        0x00, 0xc5, 0x1d, 0x4b, 0x3a, 0x4c, 0x87, 0x31,
        0xac, 0xd4, 0xed, 0x11, 0x91, 0x63, 0x50, 0x59,
        0xb5, 0x33, 0x43, 0xc9, 0xd4, 0x39, 0xe0, 0xfd,
        0xc0, 0xd6, 0xe3, 0x13, 0x7c, 0xd1, 0xfb, 0x27,
        0xd1, 0x01, 0x00, 0xdb, 0x62, 0xab, 0xed, 0x59,
        0x02, 0x8d, 0xe0, 0x04, 0x0b, 0x4f, 0x15, 0x49,
        0x37, 0x95, 0xf9, 0x01, 0x6c, 0x9b, 0x3e, 0x79,
        0xfe, 0x59, 0xed, 0x5a, 0x4c, 0x18, 0x5a, 0x19,
        0xaf, 0x3a, 0x01);

static const char csync_text[] =
  PAD("example.com. 3600 IN CSYNC 66 3 A NS AAAA");
static const rdata_t csync_rdata =
  RDATA(/* serial */
        0x00, 0x00, 0x00, 0x42,
        /* flags */
        0x00, 0x03,
        /* type bit map */
        0x00, 0x04, 0x60, 0x00, 0x00, 0x08);

static const char zonemd_text[] =
  PAD("example.com. 86400 IN ZONEMD 2018031500 1 1 (\n"
      "    FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE\n"
      "    7EB1A7B641A47BA7FED2DD5B97AE499FAFA4F22C6BD647DE )");
static const char zonemd_generic_text[] =
  PAD("example.com. 86400 CLASS1 TYPE63 \\# 54 "
      /* serial */
      "7848b78c"
      /* scheme */
      "01"
      /* algorithm */
      "01"
      /* digest */
      "febe3d4ce2ec2ffa4ba99d46cd69d6d29711e55217057bee"
      "7eb1a7b641a47ba7fed2dd5b97ae499fafa4f22c6bd647de");
static const rdata_t zonemd_rdata =
  RDATA(0x78, 0x48, 0xb7, 0x8c, 0x01, 0x01, 0xfe, 0xbe,
        0x3d, 0x4c, 0xe2, 0xec, 0x2f, 0xfa, 0x4b, 0xa9,
        0x9d, 0x46, 0xcd, 0x69, 0xd6, 0xd2, 0x97, 0x11,
        0xe5, 0x52, 0x17, 0x05, 0x7b, 0xee, 0x7e, 0xb1,
        0xa7, 0xb6, 0x41, 0xa4, 0x7b, 0xa7, 0xfe, 0xd2,
        0xdd, 0x5b, 0x97, 0xae, 0x49, 0x9f, 0xaf, 0xa4,
        0xf2, 0x2c, 0x6b, 0xd6, 0x47, 0xde);

static const char svcb_text[] =
  PAD("foo. 1 IN SVCB 0 foo. key16= mandatory=key16");
static const rdata_t svcb_rdata =
  RDATA(0x00, 0x00,
        3, 'f', 'o', 'o', 0,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00);

static const char spf_text[] =
  PAD("foo. SPF \"v=spf1 +all\"");
static const char spf_generic_text[] =
  PAD("foo. SPF \\# 12 0b763d73706631202b616c6c");
static const rdata_t spf_rdata =
  RDATA(0x0b, 'v', '=', 's', 'p', 'f', '1', ' ', '+', 'a', 'l', 'l');

static const char nid_text[] =
  PAD("foo. NID 10 0014:4fff:ff20:ee64");
static const char nid_generic_text[] =
  PAD("foo. TYPE104 \\# 10 000a 0014 4fff ff20 ee64");
static const rdata_t nid_rdata =
  RDATA(0x00, 0x0a, 0x00, 0x14, 0x4f, 0xff, 0xff, 0x20, 0xee, 0x64);

static const char l32_text[] =
  PAD("foo. L32 10 10.1.2.0");
static const char l32_generic_text[] =
  PAD("foo. L32 \\# 6 000a 0a010200");
static const rdata_t l32_rdata =
  RDATA(0x00, 0x0a, 0x0a, 0x01, 0x02, 0x00);

static const char l64_text[] =
  PAD("foo. L64 10 2001:0DB8:1140:1000");
static const char l64_generic_text[] =
  PAD("foo. L64 \\# 10 000a 20010db811401000");
static const rdata_t l64_rdata =
  RDATA(0x00, 0x0a, 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x40, 0x10, 0x00);

static const char lp_text[] =
  PAD("foo. LP 10 l64-subnet1.example.com.");
static const char lp_generic_text[] =
  PAD("foo. LP \\# 27 000a 0b6c36342d7375626e657431076578616d706c6503636f6d00");
static const rdata_t lp_rdata =
  RDATA(0x00, 0x0a, 11, 'l', '6', '4', '-', 's', 'u', 'b', 'n', 'e', 't', '1', EXAMPLE_COM);

static const char eui48_text[] =
  PAD("foo. EUI48 00-00-5e-00-53-2a");
static const char eui48_generic_text[] =
  PAD("foo. EUI48 \\# 6 00005e00532a");
static const rdata_t eui48_rdata =
  RDATA(0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a);

static const char eui64_text[] =
  PAD("foo. EUI64 00-00-5e-ef-10-00-00-2a");
static const char eui64_generic_text[] =
  PAD("foo. EUI64 \\# 8 00005eef1000002a");
static const rdata_t eui64_rdata =
  RDATA(0x00, 0x00, 0x5e, 0xef, 0x10, 0x00, 0x00, 0x2a);

static const char uri_text[] =
  PAD("foo. URI 10 1 \"ftp://ftp1.example.com/public\"");
static const char uri_generic_text[] =
  PAD("foo. URI \\# 33 000a 0001 6674703a2f2f667470312e6578616d706c652e636f6d2f7075626c6963");
static const rdata_t uri_rdata =
  RDATA(0x00, 0x0a, 0x00, 0x01, 'f', 't', 'p', ':', '/', '/',
        'f', 't', 'p', '1', '.', 'e', 'x',
        'a', 'm', 'p', 'l', 'e', '.', 'c',
        'o', 'm', '/', 'p', 'u', 'b', 'l',
        'i', 'c' );

static const char caa_text[] =
  PAD("foo. CAA 0 issue \"ca1.example.net\"");
static const char caa_generic_text[] =
  PAD("foo. CAA \\# 22 00 056973737565 6361312e6578616d706c652e6e6574");
static const rdata_t caa_rdata =
  RDATA(/* flags */
        0,
        /* tag */
        5, 'i', 's', 's', 'u', 'e',
        /* target */
        'c', 'a', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'n', 'e', 't');

static const char avc_text[] =
  PAD("foo. AVC \"app-name:WOLFGANG|app-class:OAM\"");
static const char avc_generic_text[] =
  PAD("foo. AVC \\# 32 1f6170702d6e616d653a574f4c4647414e477c6170702d636c6173733a4f414d");
static const rdata_t avc_rdata =
  RDATA(31, 'a', 'p', 'p', '-', 'n', 'a', 'm', 'e',
            ':', 'W', 'O', 'L', 'F', 'G', 'A', 'N',
            'G', '|', 'a', 'p', 'p', '-', 'c', 'l',
            'a', 's', 's', ':', 'O', 'A', 'M');

static const char dlv_text[] =
  PAD("foo. DLV 58470 5 1 ( 3079F1593EBAD6DC121E202A8B766A6A4837206C )");
static const char dlv_generic_text[] =
  PAD("foo. DLV \\# 24 e466 05 01 3079f1593ebad6dc121e202a8b766a6a4837206c");

static const char type0_generic_text[] =
  PAD("foo. TYPE0 \\# 6 666f6f626172");
static const rdata_t type0_rdata =
  RDATA('f', 'o', 'o', 'b', 'a', 'r');

typedef struct test test_t;
struct test {
  const uint16_t type;
  const char *text;
  const rdata_t *rdata;
};


static const test_t tests[] = {
  { 0, type0_generic_text, &type0_rdata },
  { ZONE_A, a_text, &a_rdata },
  { ZONE_A, a_generic_text, &a_rdata },
  { ZONE_NS, ns_text, &ns_rdata },
  { ZONE_NS, ns_generic_text, &ns_rdata },
  { ZONE_MD, md_text, &ns_rdata },
  { ZONE_MD, md_generic_text, &ns_rdata },
  { ZONE_MF, mf_text, &ns_rdata },
  { ZONE_MF, mf_generic_text, &ns_rdata },
  { ZONE_CNAME, cname_text, &ns_rdata },
  { ZONE_CNAME, cname_generic_text, &ns_rdata },
  { ZONE_SOA, soa_text, &soa_rdata },
  { ZONE_SOA, soa_generic_text, &soa_rdata },
  { ZONE_MB, mb_text, &ns_rdata },
  { ZONE_MB, mb_generic_text, &ns_rdata },
  { ZONE_MG, mg_text, &mg_rdata },
  { ZONE_MG, mg_generic_text, &mg_rdata },
  { ZONE_MR, mr_text, &mg_rdata },
  { ZONE_MR, mr_generic_text, &mg_rdata },
  { ZONE_PTR, ptr_text, &ns_rdata },
  { ZONE_PTR, ptr_generic_text, &ns_rdata },
  { ZONE_WKS, wks_text, &wks_rdata },
  { ZONE_WKS, wks_generic_text, &wks_rdata },
  { ZONE_HINFO, hinfo_text, &hinfo_rdata },
  { ZONE_HINFO, hinfo_generic_text, &hinfo_rdata },
  { ZONE_MINFO, minfo_text, &minfo_rdata },
  { ZONE_MINFO, minfo_generic_text, &minfo_rdata },
  { ZONE_MX, mx_text, &mx_rdata },
  { ZONE_MX, mx_generic_text, &mx_rdata },
  { ZONE_TXT, txt_text, &txt_rdata },
  { ZONE_TXT, txt_generic_text, &txt_rdata },
  { ZONE_RP, rp_text, &rp_rdata },
  { ZONE_RP, rp_generic_text, &rp_rdata },
  { ZONE_AFSDB, afsdb_text, &afsdb_rdata },
  { ZONE_AFSDB, afsdb_generic_text, &afsdb_rdata },
  { ZONE_X25, x25_text, &x25_rdata },
  { ZONE_X25, x25_generic_text, &x25_rdata },
  { ZONE_ISDN, isdn_text, &isdn_rdata },
  { ZONE_ISDN, isdn_generic_text, &isdn_rdata },
  { ZONE_RT, rt_text, &rt_rdata },
  { ZONE_RT, rt_generic_text, &rt_rdata },
  { ZONE_NSAP, nsap_text, &nsap_rdata },
  { ZONE_NSAP, nsap_generic_text, &nsap_rdata },
  { ZONE_NSAP_PTR, nsap_ptr_text, &nsap_ptr_rdata },
  { ZONE_SIG, sig_text, &sig_rdata },
  { ZONE_KEY, key_text, &key_rdata },
  { ZONE_KEY, key_generic_text, &key_rdata },
  { ZONE_GPOS, gpos_text, &gpos_rdata },
  { ZONE_PX, px_text, &px_rdata },
  { ZONE_PX, px_generic_text, &px_rdata },
  { ZONE_LOC, loc_text, &loc_rdata },
  { ZONE_NXT, nxt_text, &nxt_rdata },
  { ZONE_NAPTR, naptr_text, &naptr_rdata },
  { ZONE_NAPTR, naptr_generic_text, &naptr_rdata },
  { ZONE_KX, kx_text, &kx_rdata },
  { ZONE_KX, kx_generic_text, &kx_rdata },
  { ZONE_CERT, cert_text, &cert_rdata },
  { ZONE_DNAME, dname_text, &dname_rdata },
  { ZONE_DNAME, dname_generic_text, &dname_rdata },
  { ZONE_APL, apl_text, &apl_rdata },
  { ZONE_SSHFP, sshfp_text, &sshfp_rdata },
  { ZONE_SSHFP, sshfp_generic_text, &sshfp_rdata },
  { ZONE_IPSECKEY, ipseckey_text, &ipseckey_rdata },
  { ZONE_IPSECKEY, ipseckey_ipv4_text, &ipseckey_ipv4_rdata },
  { ZONE_IPSECKEY, ipseckey_ipv6_text, &ipseckey_ipv6_rdata },
  { ZONE_IPSECKEY, ipseckey_name_text, &ipseckey_name_rdata },
  { ZONE_NSEC, nsec_text, &nsec_rdata },
  { ZONE_NSEC3, nsec3_no_data_text, &nsec3_no_data_rdata },
  { ZONE_DHCID, dhcid_text, &dhcid_rdata },
  { ZONE_DHCID, dhcid_generic_text, &dhcid_rdata },
  { ZONE_TLSA, tlsa_text, &tlsa_rdata },
  { ZONE_TLSA, tlsa_generic_text, &tlsa_rdata },
  { ZONE_SMIMEA, smimea_text, &smimea_rdata },
  { ZONE_SMIMEA, smimea_generic_text, &smimea_rdata },
  { ZONE_HIP, hip_text, &hip_rdata },
  { ZONE_CDS, cds_text, &cds_rdata },
  { ZONE_CDS, cds_generic_text, &cds_rdata },
  { ZONE_CDNSKEY, cdnskey_text, &cdnskey_rdata },
  { ZONE_CDNSKEY, cdnskey_generic_text, &cdnskey_rdata },
  { ZONE_OPENPGPKEY, openpgpkey_text, &openpgpkey_rdata },
  { ZONE_OPENPGPKEY, openpgpkey_generic_text, &openpgpkey_rdata },
  { ZONE_CSYNC, csync_text, &csync_rdata },
  { ZONE_ZONEMD, zonemd_text, &zonemd_rdata },
  { ZONE_ZONEMD, zonemd_generic_text, &zonemd_rdata },
  { ZONE_SVCB, svcb_text, &svcb_rdata },
  { ZONE_SPF, spf_text, &spf_rdata },
  { ZONE_SPF, spf_generic_text, &spf_rdata },
  { ZONE_NID, nid_text, &nid_rdata },
  { ZONE_NID, nid_generic_text, &nid_rdata },
  { ZONE_L32, l32_text, &l32_rdata },
  { ZONE_L32, l32_generic_text, &l32_rdata },
  { ZONE_L64, l64_text, &l64_rdata },
  { ZONE_L64, l64_generic_text, &l64_rdata },
  { ZONE_LP, lp_text, &lp_rdata },
  { ZONE_LP, lp_generic_text, &lp_rdata },
  { ZONE_EUI48, eui48_text, &eui48_rdata },
  { ZONE_EUI48, eui48_generic_text, &eui48_rdata },
  { ZONE_EUI64, eui64_text, &eui64_rdata },
  { ZONE_EUI64, eui64_generic_text, &eui64_rdata },
  { ZONE_URI, uri_text, &uri_rdata },
  { ZONE_URI, uri_generic_text, &uri_rdata },
  { ZONE_CAA, caa_text, &caa_rdata },
  { ZONE_CAA, caa_generic_text, &caa_rdata },
  { ZONE_AVC, avc_text, &avc_rdata },
  { ZONE_AVC, avc_generic_text, &avc_rdata },
  { ZONE_DLV, dlv_text, &cds_rdata },
  { ZONE_DLV, dlv_generic_text, &cds_rdata }
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
  (void)rdlength;
  (void)rdata;
  assert_int_equal(type, test->type);
  assert_int_equal(rdlength, test->rdata->length);
  assert_memory_equal(rdata, test->rdata->octets, rdlength);
  return ZONE_SUCCESS;
}

static uint8_t origin[] =
  { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

/*!cmocka */
void supported_types(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    test_t test = tests[i];
    zone_parser_t parser = { 0 };
    zone_name_buffer_t name;
    zone_rdata_buffer_t rdata;
    zone_buffers_t buffers = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    options.accept.callback = add_rr;
    options.origin.octets = origin;
    options.origin.length = sizeof(origin);
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    fprintf(stderr, "INPUT: '%s'\n", tests[i].text);

    result = zone_parse_string(&parser, &options, &buffers, tests[i].text, strlen(tests[i].text), &test);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
