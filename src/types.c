/*
 * types.c -- some useful description
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"

#define CLASS(name, code) \
  { { sizeof(name) - 1, name }, code }

#define UNKNOWN_CLASS(code) \
  { { 0, "" }, 0 }

static const zone_class_info_t classes[] = {
  UNKNOWN_CLASS(0),
  CLASS("IN", 1),
  CLASS("CS", 2),
  CLASS("CH", 3),
  CLASS("HS", 4)
};

const zone_class_info_t *zone_classes = classes;
const size_t zone_class_count = sizeof(classes)/sizeof(classes[0]);

#define SYMBOLS(symbols) \
  { (sizeof(symbols)/sizeof(symbols[0])), symbols }

#define SYMBOL(name, value) \
  { { sizeof(name) - 1, name }, value }

#define FIELDS(fields) \
  { (sizeof(fields)/sizeof(fields[0])), fields }

#define FIELD(name, type, /* qualifiers, symbols */ ...) \
  { { sizeof(name) - 1, name }, type, __VA_ARGS__ }

#define TYPE(name, code, options, fields) \
  { { sizeof(name) - 1, name }, code, options, fields }

#define UNKNOWN_TYPE(code) \
  { { 0, "" }, code, 0, { 0, NULL } }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static const zone_field_info_t a_rdata_fields[] = {
  FIELD("address", ZONE_IP4, 0)
};

static const zone_field_info_t ns_rdata_fields[] = {
  FIELD("host", ZONE_NAME, ZONE_COMPRESSED),
};

static const zone_field_info_t cname_rdata_fields[] = {
  FIELD("host", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t soa_rdata_fields[] = {
  FIELD("primary", ZONE_NAME, ZONE_COMPRESSED),
  FIELD("mailbox", ZONE_NAME, ZONE_MAILBOX),
  FIELD("serial", ZONE_INT32, 0),
  FIELD("refresh", ZONE_INT32, ZONE_TTL),
  FIELD("retry", ZONE_INT32, ZONE_TTL),
  FIELD("expire", ZONE_INT32, ZONE_TTL),
  FIELD("minimum", ZONE_INT32, ZONE_TTL),
};

static const zone_field_info_t wks_rdata_fields[] = {
  FIELD("address", ZONE_IP4, 0),
  FIELD("protocol", ZONE_INT8, 0),
  FIELD("bitmap", ZONE_WKS, 0)
};

static const zone_field_info_t mx_rdata_fields[] = {
  FIELD("priority", ZONE_INT16, 0),
  FIELD("hostname", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t txt_rdata_fields[] = {
  FIELD("text", ZONE_STRING, ZONE_SEQUENCE)
};

static const zone_field_info_t aaaa_rdata_fields[] = {
  FIELD("address", ZONE_IP6, 0)
};

static const zone_field_info_t srv_rdata_fields[] = {
  FIELD("priority", ZONE_INT16, 0),
  FIELD("weight", ZONE_INT16, 0),
  FIELD("port", ZONE_INT16, 0),
  FIELD("target", ZONE_NAME, 0)
};

static const zone_symbol_t ds_algorithm_symbols[] = {
  SYMBOL("DH", 2),
  SYMBOL("DSA", 3),
  SYMBOL("DSA-NSEC-SHA1", 6),
  SYMBOL("ECC", 4),
  SYMBOL("ECC-GOST", 12),
  SYMBOL("ECDSAP256SHA256", 13),
  SYMBOL("ECDSAP384SHA384", 14),
  SYMBOL("INDIRECT", 252),
  SYMBOL("PRIVATEDNS", 253),
  SYMBOL("PRIVATEOID", 254),
  SYMBOL("RSAMD5", 1),
  SYMBOL("RSASHA1", 5),
  SYMBOL("RSASHA1-NSEC3-SHA1", 7),
  SYMBOL("RSASHA256", 8),
  SYMBOL("RSASHA512", 10)
};

static const zone_symbol_t ds_digest_type_symbols[] = {
  SYMBOL("GOST", 3),
  SYMBOL("SHA-1", 1),
  SYMBOL("SHA-256", 2),
  SYMBOL("SHA-384", 4)
};

static const zone_field_info_t ds_rdata_fields[] = {
  FIELD("keytag", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(ds_algorithm_symbols)),
  FIELD("digtype", ZONE_INT8, 0, SYMBOLS(ds_digest_type_symbols)),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16)
};

static const zone_symbol_t dnssec_algorithm_symbols[] = {
  SYMBOL("DH", 2),
  SYMBOL("DSA", 3),
  SYMBOL("ECC", 4),
  SYMBOL("INDIRECT", 252),
  SYMBOL("PRIVATEDNS", 253),
  SYMBOL("PRIVATEOID", 254),
  SYMBOL("RSAMD5", 1),
  SYMBOL("RSASHA1", 5)
};

static const zone_field_info_t rrsig_rdata_fields[] = {
  FIELD("rrtype", ZONE_INT16, ZONE_TYPE),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("labels", ZONE_INT8, 0),
  FIELD("origttl", ZONE_INT32, ZONE_TTL),
  FIELD("expire", ZONE_INT32, ZONE_TIME),
  FIELD("inception", ZONE_INT32, ZONE_TIME),
  FIELD("keytag", ZONE_INT16, 0),
  FIELD("signer", ZONE_NAME, 0),
  FIELD("signature", ZONE_BLOB, ZONE_BASE64)
};

static const zone_field_info_t nsec_rdata_fields[] = {
  FIELD("next", ZONE_NAME, 0),
  FIELD("types", ZONE_NSEC, 0)
};

static const zone_field_info_t dnskey_rdata_fields[] = {
  FIELD("flags", ZONE_INT16, 0),
  FIELD("protocol", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("publickey", ZONE_BLOB, ZONE_BASE64)
};

static const zone_symbol_t nsec3_algorithm_symbols[] = {
  SYMBOL("SHA-1", 1)
};

static const zone_symbol_t nsec3_flags_symbols[] = {
  SYMBOL("OPTOUT", 1)
};

static const zone_field_info_t nsec3_rdata_fields[] = {
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("flags", ZONE_INT8, 0),
  FIELD("iterations", ZONE_INT16, 0),
  FIELD("salt", ZONE_STRING | ZONE_BASE16),
  FIELD("next", ZONE_STRING | ZONE_BASE32),
  FIELD("types", ZONE_NSEC, 0)
};

static const zone_field_info_t nsec3param_rdata_fields[] = {
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(nsec3_algorithm_symbols)),
  FIELD("flags", ZONE_INT8, 0, SYMBOLS(nsec3_flags_symbols)),
  FIELD("iterations", ZONE_INT16, 0),
  FIELD("salt", ZONE_STRING, ZONE_BASE16)
};

static const zone_field_info_t dlv_rdata_fields[] = {
  FIELD("key", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("type", ZONE_INT8, 0),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16)
};

static const zone_type_info_t types[] = {
  UNKNOWN_TYPE(0),

  TYPE("A", ZONE_A, ZONE_ANY, FIELDS(a_rdata_fields)),
  TYPE("NS", ZONE_NS, ZONE_ANY, FIELDS(ns_rdata_fields)),
  UNKNOWN_TYPE(3),
  UNKNOWN_TYPE(4),
  TYPE("CNAME", ZONE_CNAME, ZONE_ANY, FIELDS(cname_rdata_fields)),
  TYPE("SOA", ZONE_SOA, ZONE_ANY, FIELDS(soa_rdata_fields)),

  UNKNOWN_TYPE(7),
  UNKNOWN_TYPE(8),
  UNKNOWN_TYPE(9),
  UNKNOWN_TYPE(10),

  TYPE("WKS", ZONE_WKS, ZONE_IN, FIELDS(wks_rdata_fields)),

  UNKNOWN_TYPE(12),
  UNKNOWN_TYPE(13),
  UNKNOWN_TYPE(14),

  TYPE("MX", ZONE_MX, ZONE_ANY, FIELDS(mx_rdata_fields)),
  TYPE("TXT", ZONE_TXT, ZONE_ANY, FIELDS(txt_rdata_fields)),

  UNKNOWN_TYPE(17),
  UNKNOWN_TYPE(18),
  UNKNOWN_TYPE(19),
  UNKNOWN_TYPE(20),
  UNKNOWN_TYPE(21),
  UNKNOWN_TYPE(22),
  UNKNOWN_TYPE(23),
  UNKNOWN_TYPE(24),
  UNKNOWN_TYPE(25),
  UNKNOWN_TYPE(26),
  UNKNOWN_TYPE(27),

  TYPE("AAAA", ZONE_AAAA, ZONE_IN, FIELDS(aaaa_rdata_fields)),

  UNKNOWN_TYPE(29),
  UNKNOWN_TYPE(30),
  UNKNOWN_TYPE(31),
  UNKNOWN_TYPE(32),

  TYPE("SRV", ZONE_SRV, ZONE_IN, FIELDS(srv_rdata_fields)),

  UNKNOWN_TYPE(34),
  UNKNOWN_TYPE(35),
  UNKNOWN_TYPE(36),
  UNKNOWN_TYPE(37),
  UNKNOWN_TYPE(38),
  UNKNOWN_TYPE(39),
  UNKNOWN_TYPE(40),
  UNKNOWN_TYPE(41),
  UNKNOWN_TYPE(42),

  TYPE("DS", ZONE_DS, ZONE_ANY, FIELDS(ds_rdata_fields)),

  UNKNOWN_TYPE(44),
  UNKNOWN_TYPE(45),

  TYPE("RRSIG", ZONE_RRSIG, ZONE_ANY, FIELDS(rrsig_rdata_fields)),
  TYPE("NSEC", ZONE_NSEC, ZONE_ANY, FIELDS(nsec_rdata_fields)),
  TYPE("DNSKEY", ZONE_DNSKEY, ZONE_ANY, FIELDS(dnskey_rdata_fields)),

  UNKNOWN_TYPE(49),

  TYPE("NSEC3", 50, ZONE_ANY, FIELDS(nsec3_rdata_fields)),
  TYPE("NSEC3PARAM", 51, ZONE_ANY, FIELDS(nsec3param_rdata_fields)),

  UNKNOWN_TYPE(52),
  UNKNOWN_TYPE(53),
  UNKNOWN_TYPE(54),
  UNKNOWN_TYPE(55),
  UNKNOWN_TYPE(56),
  UNKNOWN_TYPE(57),
  UNKNOWN_TYPE(58),
  UNKNOWN_TYPE(59),
  UNKNOWN_TYPE(60),
  UNKNOWN_TYPE(61),
  UNKNOWN_TYPE(62),
  UNKNOWN_TYPE(63),
  UNKNOWN_TYPE(64),
  UNKNOWN_TYPE(65),
  UNKNOWN_TYPE(66),
  UNKNOWN_TYPE(67),
  UNKNOWN_TYPE(68),
  UNKNOWN_TYPE(69),
  UNKNOWN_TYPE(70),
  UNKNOWN_TYPE(71),
  UNKNOWN_TYPE(72),
  UNKNOWN_TYPE(73),
  UNKNOWN_TYPE(74),
  UNKNOWN_TYPE(75),
  UNKNOWN_TYPE(76),
  UNKNOWN_TYPE(77),
  UNKNOWN_TYPE(78),
  UNKNOWN_TYPE(79),
  UNKNOWN_TYPE(80),
  UNKNOWN_TYPE(81),
  UNKNOWN_TYPE(82),
  UNKNOWN_TYPE(83),
  UNKNOWN_TYPE(84),
  UNKNOWN_TYPE(85),
  UNKNOWN_TYPE(86),
  UNKNOWN_TYPE(87),
  UNKNOWN_TYPE(88),
  UNKNOWN_TYPE(89),
  UNKNOWN_TYPE(90),
  UNKNOWN_TYPE(91),
  UNKNOWN_TYPE(92),
  UNKNOWN_TYPE(93),
  UNKNOWN_TYPE(94),
  UNKNOWN_TYPE(95),
  UNKNOWN_TYPE(96),
  UNKNOWN_TYPE(97),
  UNKNOWN_TYPE(98),
  UNKNOWN_TYPE(99),
  UNKNOWN_TYPE(100),
  UNKNOWN_TYPE(101),
  UNKNOWN_TYPE(102),
  UNKNOWN_TYPE(103),
  UNKNOWN_TYPE(104),
  UNKNOWN_TYPE(105),
  UNKNOWN_TYPE(106),
  UNKNOWN_TYPE(107),
  UNKNOWN_TYPE(108),
  UNKNOWN_TYPE(109),

  TYPE("DLV", 32769, ZONE_ANY, FIELDS(dlv_rdata_fields))
};

#pragma GCC diagnostic pop

const zone_type_info_t *zone_types = types;
const size_t zone_type_count = sizeof(types)/sizeof(types[0]);

static const zone_hash_map_t type_class_map[32] = {
  // A[A=1,AFSDB=18,AAAA=28,A6=38,APL=42], span
  { { 199,210,202,155, 22,0,0,0, 0,0,0,0,0,0,0,0 },
    { &types[ZONE_A], &types[0], &types[ZONE_AAAA], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // B
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // C[CH=2,CS=3,CNAME=5,CERT=37,CDS=59,CDNSKEY=60,CSYNC=62,CAA=257]
  { { 249,70,231,79, 71,117,217,201, 0,0,0,0, 0,0,0,0 },
    { &classes[ZONE_CH], &classes[ZONE_CS], &types[ZONE_CNAME], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // D[DNAME=39,DS=43,DNSKEY=48,DHCID=49,DLV=32769]
  { { 231,70,116,224, 92,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[ZONE_DS], &types[ZONE_DNSKEY], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // E[EUI48=108,EUI64=109]
  { { 172,144,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // F
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // G[GPOS=27]
  { { 72,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // H[HS=4,HINFO=13,HIP=55,HTTPS=65]
  { { 70,45,50,73, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &classes[ZONE_HS], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // I[IN=2,ISDN=20,IPSECKEY=45]
  { { 35,37,118,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &classes[ZONE_IN], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // J
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // K[KEY=25,KX=36]
  { { 113,105,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // L[LOC=29,L32=105,L64=106,LP=107]
  { { 215,128,142,49, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // M[MD=3,MF=4,MB=7,MG=8,MR=9,MINFO=14,MX=15]
  { { 221,235,207,242, 63,45,105,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[ZONE_MX], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // N[NS=2,NSAP=22,NSAP-PTR=23,NXT=30,NAPTR=35,NSEC=47,NSEC3=50,NSEC3PARAM=51,NID=104]
  { { 70,51,69,78, 66,216,137,36, 222,0,0,0, 0,0,0,0 },
    { &types[ZONE_NS], &types[0], &types[0], &types[0],
      &types[0], &types[ZONE_NSEC], &types[ZONE_NSEC3], &types[ZONE_NSEC3PARAM],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // O[OPENPGPKEY=69]
  { { 120,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // P[PTR=12,PX=26]
  { { 64,105,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // Q
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // R[RP=17,RT=21,RRSIG=46]
  { { 49,77,245,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[ZONE_RRSIG], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // S[SOA=6,SIG=24,SRV=33,SSHFP=44,SMIMEA=53,SVCB=64,SPF=99]
  { { 201,243,92,52, 204,209,236,0, 0,0,0,0, 0,0,0,0  },
    { &types[ZONE_SOA], &types[0], &types[ZONE_SRV], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // T[TXT=16,TLSA=52]
  { { 78,202,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[ZONE_TXT], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // U[URI=256]
  { { 1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // V
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // W[WKS=11]
  { { 71,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // X[X25=19]
  { { 149,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // Y
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  // Z
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
  { { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 },
    { &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0],
      &types[0], &types[0], &types[0], &types[0] } },
};

const zone_hash_map_t *zone_type_class_map = type_class_map;
