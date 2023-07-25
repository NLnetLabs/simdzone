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
#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

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
  PAD(" A 192.0.2.1");
static const char a_generic_text[] =
  PAD(" A \\# 4 c0000201");
static const rdata_t a_rdata =
  RDATA(0xc0, 0x00, 0x02, 0x01);

static const char ns_text[] =
  PAD(" NS host.example.com.");
static const char ns_generic_text[] =
  PAD(" NS \\# 18 04686f7374076578616d706c6503636f6d00");
static const rdata_t ns_rdata =
  RDATA(HOST_EXAMPLE_COM);

static const char md_text[] =
  PAD(" MD host.example.com.");
static const char md_generic_text[] =
  PAD(" MD \\# 18 04686f7374076578616d706c6503636f6d00");
static const char mf_text[] =
  PAD(" MF host.example.com.");
static const char mf_generic_text[] =
  PAD(" MF \\# 18 04686f7374076578616d706c6503636f6d00");
static const char cname_text[] =
  PAD(" CNAME host.example.com.");
static const char cname_generic_text[] =
  PAD(" CNAME \\# 18 04686f7374076578616d706c6503636f6d00");

static const char soa_text[] =
  PAD(" SOA host.example.com. hostmaster.example.com. 2023063001 1 2 3 4");
static const char soa_generic_text[] =
  PAD(" SOA \\# 62 04686f7374076578616d706c6503636f6d00"
      "            0a686f73746d6173746572076578616d706c6503636f6d00"
      "            78957dd9"
      "            00000001"
      "            00000002"
      "            00000003"
      "            00000004");
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
  PAD(" MB host.example.com.");
static const char mb_generic_text[] =
  PAD(" MB \\# 18 04686f7374076578616d706c6503636f6d00");

static const char mg_text[] =
  PAD(" MG hostmaster.example.com.");
static const char mg_generic_text[] =
  PAD(" MG \\# 24 0a686f73746d6173746572076578616d706c6503636f6d00");
static const rdata_t mg_rdata = RDATA(HOSTMASTER_EXAMPLE_COM);

static const char mr_text[] =
  PAD(" MR hostmaster.example.com.");
static const char mr_generic_text[] =
  PAD(" MR \\# 24 0a686f73746d6173746572076578616d706c6503636f6d00");
static const char ptr_text[] =
  PAD(" PTR host.example.com.");
static const char ptr_generic_text[] =
  PAD(" PTR \\# 18 04686f7374076578616d706c6503636f6d00");

static const char hinfo_text[] =
  PAD(" HINFO amd64 linux");
static const char hinfo_generic_text[] =
  PAD(" HINFO \\# 12 05616d643634 056c696e7578");
static const rdata_t hinfo_rdata =
  RDATA(/* amd64 */
        5, 'a', 'm', 'd', '6', '4',
        /* linux */
        5, 'l', 'i', 'n', 'u', 'x');

static const char minfo_text[] =
  PAD(" MINFO hostmaster.example.com. hostmaster.example.com.");
static const char minfo_generic_text[] =
  PAD(" MINFO \\# 48 0a686f73746d6173746572076578616d706c6503636f6d00"
      "              0a686f73746d6173746572076578616d706c6503636f6d00");
static const rdata_t minfo_rdata =
  RDATA(HOSTMASTER_EXAMPLE_COM, HOSTMASTER_EXAMPLE_COM);

static const char mx_text[] =
  PAD(" MX 10 host.example.com.");
static const char mx_generic_text[] =
  PAD(" MX \\# 20 000a 04686f7374076578616d706c6503636f6d00");
static const rdata_t mx_rdata =
  RDATA(/* 10 */
        0x00, 0x0a,
        /* host.example.com. */
        HOST_EXAMPLE_COM);

static const char txt_text[] =
  PAD(" TXT example of TXT rdata");
static const char txt_generic_text[] =
  PAD(" TXT \\# 21 076578616d706c65 026f66 03545854 057264617461");
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
  PAD(" RP hostmaster.example.com. host.example.com.");
static const char rp_generic_text[] =
  PAD(" RP \\# 42 0a686f73746d6173746572076578616d706c6503636f6d00"
      "           04686f7374076578616d706c6503636f6d00");
static const rdata_t rp_rdata =
  RDATA(HOSTMASTER_EXAMPLE_COM, HOST_EXAMPLE_COM);

static const char afsdb_text[] =
  PAD(" AFSDB 1 host.example.com.");
static const char afsdb_generic_text[] =
  PAD(" AFSDB \\# 20 0001 04686f7374076578616d706c6503636f6d00");
static const rdata_t afsdb_rdata =
  RDATA(/* 1 */
        0x00, 0x01,
        /* host.example.com. */
        HOST_EXAMPLE_COM);

static const char x25_text[] =
  PAD(" X25 311061700956");
static const char x25_generic_text[] =
  PAD(" X25 \\# 13 0c333131303631373030393536");
static const rdata_t x25_rdata =
  RDATA(0x0c, 0x33, 0x31, 0x31, 0x30, 0x36, 0x31, 0x37,
        0x30, 0x30, 0x39, 0x35, 0x36);

static const char isdn_text[] =
  PAD(" ISDN 150862028003217 004");
static const char isdn_generic_text[] =
  PAD(" ISDN \\# 20 0f313530383632303238303033323137 03303034");
static const rdata_t isdn_rdata =
  RDATA(0x0f, 0x31, 0x35, 0x30, 0x38, 0x36, 0x32, 0x30,
        0x32, 0x38, 0x30, 0x30, 0x33, 0x32, 0x31, 0x37,
        0x03, 0x30, 0x30, 0x34);

static const char rt_text[] =
  PAD(" RT 10 relay.example.com.");
static const char rt_generic_text[] =
  PAD(" RT \\# 21 000a 0572656c6179076578616d706c6503636f6d00");
static const rdata_t rt_rdata =
  RDATA(/* 10 */
        0x00, 0x0a,
        /* relay.example.com. */
        0x05, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x07, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
        0x6f, 0x6d, 0x00);

static const char key_text[] =
  PAD(" KEY 0 0 0 Zm9vYmFy");
static const char key_generic_text[] =
  PAD(" KEY \\# 10 00000000666f6f626172");
static const rdata_t key_rdata =
  RDATA(0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72);

static const char naptr_text[] =
  PAD(" NAPTR 100 50 \"s\" \"http+I2L+I2C+I2R\" \"\"  _http._tcp.gatech.edu.");
static const char naptr_generic_text[] =
  PAD(" NAPTR \\# 47 0064"
      "              0032"
      "              0173"
      "              10687474702b49324c2b4932432b493252"
      "              00"
      "              055f68747470045f746370066761746563680365647500");
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
  PAD(" KX 10 kx-host");
static const char kx_generic_text[] =
  PAD(" KX \\# 23 000a 076b782d686f7374076578616d706c6503636f6d00");
static const rdata_t kx_rdata =
  RDATA(0x00, 0x0a, 0x07, 0x6b, 0x78, 0x2d, 0x68, 0x6f, 0x73, 0x74, EXAMPLE_COM);

static const char dname_text[] = PAD(" DNAME host.example.com.");
static const char dname_generic_text[] =
  PAD(" DNAME \\# 18 04686f7374076578616d706c6503636f6d00");
static const rdata_t dname_rdata = RDATA(HOST_EXAMPLE_COM);

static const char sshfp_text[] =
  PAD(" SSHFP 4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789");
static const char sshfp_generic_text[] =
  PAD(" SSHFP \\# 34 04 02"
      "           123456789abcdef6"
      "           7890123456789abc"
      "           def6789012345678"
      "           9abcdef123456789");
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

// https://www.rfc-editor.org/rfc/rfc4701.html#section-3.6.1
static const char dhcid_text[] =
  PAD(" DHCID   ( AAIBY2/AuCccgoJbsaxcQc9TUapptP69l"
      "           OjxfNuVAA2kjEA= )");
static const char dhcid_generic_text[] =
  PAD(" DHCID \\# 35 ( 000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cd"
      "          b95000da48c40 )");
static const rdata_t dhcid_rdata =
  RDATA(0x00, 0x02, 0x01, 0x63, 0x6f, 0xc0, 0xb8, 0x27,
        0x1c, 0x82, 0x82, 0x5b, 0xb1, 0xac, 0x5c, 0x41,
        0xcf, 0x53, 0x51, 0xaa, 0x69, 0xb4, 0xfe, 0xbd,
        0x94, 0xe8, 0xf1, 0x7c, 0xdb, 0x95, 0x00, 0x0d,
        0xa4, 0x8c, 0x40);

static const char cds_text[] =
  PAD(" CDS 58470 5 1 ( 3079F1593EBAD6DC121E202A8B766A6A4837206C )");
static const char cds_generic_text[] =
  PAD(" CDS \\# 24 e466 05 01 3079f1593ebad6dc121e202a8b766a6a4837206c");
static const rdata_t cds_rdata =
  RDATA(0xe4, 0x66,
        0x05,
        0x01,
        0x30, 0x79, 0xf1, 0x59, 0x3e, 0xba, 0xd6, 0xdc,
        0x12, 0x1e, 0x20, 0x2a, 0x8b, 0x76, 0x6a, 0x6a,
        0x48, 0x37, 0x20, 0x6c);

static const char cdnskey_text[] =
  PAD(" CDNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3"
      "                   Cbl+BBZH4b/0PY1kxkmvHjcZc8no"
      "                   kfzj31GajIQKY+5CptLr3buXA10h"
      "                   WqTkF7H6RfoRqXQeogmMHfpftf6z"
      "                   Mv1LyBUgia7za6ZEzOJBOztyvhjL"
      "                   742iU/TpPSEDhm2SNKLijfUppn1U"
      "                   aNvv4w== )");
static const char cdnskey_generic_text[] = PAD(
  " CDNSKEY \\# 134 0100 03 05"
  " 0103d22a6ca77f35"
  " b893206fd35e4c50"
  " 6d8378843709b97e"
  " 041647e1bff43d8d"
  " 64c649af1e371973"
  " c9e891fce3df519a"
  " 8c840a63ee42a6d2"
  " ebddbb97035d215a"
  " a4e417b1fa45fa11"
  " a9741ea2098c1dfa"
  " 5fb5feb332fd4bc8"
  " 152089aef36ba644"
  " cce2413b3b72be18"
  " cbef8da253f4e93d"
  " 2103866d9234a2e2"
  " 8df529a67d5468db"
  " efe3"
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

static const char spf_text[] =
  PAD(" SPF \"v=spf1 +all\"");
static const char spf_generic_text[] =
  PAD(" SPF \\# 12 0b763d73706631202b616c6c");
static const rdata_t spf_rdata =
  RDATA(0x0b, 'v', '=', 's', 'p', 'f', '1', ' ', '+', 'a', 'l', 'l');

static const char l32_text[] =
  PAD(" L32 10 10.1.2.0");
static const char l32_generic_text[] =
  PAD(" L32 \\# 6 000a 0a010200");
static const rdata_t l32_rdata =
  RDATA(0x00, 0x0a, 0x0a, 0x01, 0x02, 0x00);

static const char l64_text[] =
  PAD(" L64 10 2001:0DB8:1140:1000");
static const char l64_generic_text[] =
  PAD(" L64 \\# 10 000a 20010db811401000");
static const rdata_t l64_rdata =
  RDATA(0x00, 0x0a, 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x40, 0x10, 0x00);

static const char lp_text[] =
  PAD(" LP 10 l64-subnet1.example.com.");
static const char lp_generic_text[] =
  PAD(" LP \\# 27 000a 0b6c36342d7375626e657431076578616d706c6503636f6d00");
static const rdata_t lp_rdata =
  RDATA(0x00, 0x0a, 11, 'l', '6', '4', '-', 's', 'u', 'b', 'n', 'e', 't', '1', EXAMPLE_COM);

static const char uri_text[] =
  PAD(" URI 10 1 \"ftp://ftp1.example.com/public\"");
static const char uri_generic_text[] =
  PAD(" URI \\# 33 000a 0001 6674703a2f2f667470312e6578616d706c652e636f6d2f7075626c6963");
static const rdata_t uri_rdata =
  RDATA(0x00, 0x0a, 0x00, 0x01, 'f', 't', 'p', ':', '/', '/',
        'f', 't', 'p', '1', '.', 'e', 'x',
        'a', 'm', 'p', 'l', 'e', '.', 'c',
        'o', 'm', '/', 'p', 'u', 'b', 'l',
        'i', 'c' );

static const char caa_text[] =
  PAD(" CAA 0 issue \"ca1.example.net\"");
static const char caa_generic_text[] =
  PAD(" CAA \\# 22 00 056973737565 6361312e6578616d706c652e6e6574");
static const rdata_t caa_rdata =
  RDATA(/* flags */
        0,
        /* tag */
        5, 'i', 's', 's', 'u', 'e',
        /* target */
        'c', 'a', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'n', 'e', 't');

static const char avc_text[] =
  PAD(" AVC \"app-name:WOLFGANG|app-class:OAM\"");
static const char avc_generic_text[] =
  PAD(" AVC \\# 32 1f6170702d6e616d653a574f4c4647414e477c6170702d636c6173733a4f414d");
static const rdata_t avc_rdata =
  RDATA(31, 'a', 'p', 'p', '-', 'n', 'a', 'm', 'e',
            ':', 'W', 'O', 'L', 'F', 'G', 'A', 'N',
            'G', '|', 'a', 'p', 'p', '-', 'c', 'l',
            'a', 's', 's', ':', 'O', 'A', 'M');

static const char dlv_text[] =
  PAD(" DLV 58470 5 1 ( 3079F1593EBAD6DC121E202A8B766A6A4837206C )");
static const char dlv_generic_text[] =
  PAD(" DLV \\# 24 e466 05 01 3079f1593ebad6dc121e202a8b766a6a4837206c");

typedef struct test test_t;
struct test {
  const uint16_t type;
  const char *text;
  const rdata_t *rdata;
};


static const test_t tests[] = {
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
  { ZONE_KEY, key_text, &key_rdata },
  { ZONE_KEY, key_generic_text, &key_rdata },
  { ZONE_NAPTR, naptr_text, &naptr_rdata },
  { ZONE_NAPTR, naptr_generic_text, &naptr_rdata },
  { ZONE_KX, kx_text, &kx_rdata },
  { ZONE_KX, kx_generic_text, &kx_rdata },
  { ZONE_DNAME, dname_text, &dname_rdata },
  { ZONE_DNAME, dname_generic_text, &dname_rdata },
  { ZONE_SSHFP, sshfp_text, &sshfp_rdata },
  { ZONE_SSHFP, sshfp_generic_text, &sshfp_rdata },
  { ZONE_DHCID, dhcid_text, &dhcid_rdata },
  { ZONE_DHCID, dhcid_generic_text, &dhcid_rdata },
  { ZONE_CDS, cds_text, &cds_rdata },
  { ZONE_CDS, cds_generic_text, &cds_rdata },
  { ZONE_CDNSKEY, cdnskey_text, &cdnskey_rdata },
  { ZONE_CDNSKEY, cdnskey_generic_text, &cdnskey_rdata },
  { ZONE_SPF, spf_text, &spf_rdata },
  { ZONE_SPF, spf_generic_text, &spf_rdata },
  { ZONE_L32, l32_text, &l32_rdata },
  { ZONE_L32, l32_generic_text, &l32_rdata },
  { ZONE_L64, l64_text, &l64_rdata },
  { ZONE_L64, l64_generic_text, &l64_rdata },
  { ZONE_LP, lp_text, &lp_rdata },
  { ZONE_LP, lp_generic_text, &lp_rdata },
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

/*!cmocka */
void supported_types(void **state)
{
  (void)state;

  for (size_t i = 0, n = sizeof(tests)/sizeof(tests[0]); i < n; i++) {
    test_t test = tests[i];
    zone_parser_t parser = { 0 };
    zone_name_block_t name;
    zone_rdata_block_t rdata;
    zone_cache_t cache = { 1, &name, &rdata };
    zone_options_t options = { 0 };
    int32_t result;

    options.accept.add = add_rr;
    options.origin = "example.com.";
    options.default_ttl = 3600;
    options.default_class = ZONE_IN;

    fprintf(stderr, "INPUT: '%s'\n", tests[i].text);

    result = zone_parse_string(&parser, &options, &cache, tests[i].text, strlen(tests[i].text), &test);
    assert_int_equal(result, ZONE_SUCCESS);
  }
}
