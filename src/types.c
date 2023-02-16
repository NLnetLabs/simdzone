/*
 * types.h -- some useful description
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"

#define TYPE(name, code) { { sizeof(name) - 1, name }, (ZONE_TYPE << 16) | code }
#define CLASS(name, code) { { sizeof(name) - 1, name }, (ZONE_CLASS << 16) | code }

static const zone_symbol_t x[] = {
  /*  0 */  TYPE("A", ZONE_A),
  /*  1 */  TYPE("A6", ZONE_A6),
  /*  2 */  TYPE("AAAA", ZONE_AAAA),
  /*  3 */  TYPE("AFSDB", ZONE_AFSDB),
  /*  4 */  TYPE("APL", ZONE_APL),

  /*  5 */  TYPE("CAA", ZONE_CAA),
  /*  6 */  TYPE("CDS", ZONE_CDS),
  /*  7 */  TYPE("CDNSKEY", ZONE_CDNSKEY),
  /*  8 */  TYPE("CERT", ZONE_CERT),
  /*  9 */  CLASS("CH", ZONE_CH),
  /* 10 */  TYPE("CNAME", ZONE_CNAME),
  /* 11 */  CLASS("CS", ZONE_CS),
  /* 12 */  TYPE("CSYNC", ZONE_CSYNC),

  /* 13 */  TYPE("DHCID", ZONE_DHCID),
  /* 14 */  TYPE("DLV", ZONE_DLV),
  /* 15 */  TYPE("DNAME", ZONE_DNAME),
  /* 16 */  TYPE("DNSKEY", ZONE_DNSKEY),
  /* 17 */  TYPE("DS", ZONE_DS),

  /* 18 */  TYPE("EUI48", ZONE_EUI48),
  /* 19 */  TYPE("EUI64", ZONE_EUI64),

  /* 20 */  TYPE("GPOS", ZONE_GPOS),

  /* 21 */  TYPE("HINFO", ZONE_HINFO),
  /* 22 */  TYPE("HIP", ZONE_HIP),
  /* 23 */  CLASS("HS", ZONE_HS),
  /* 24 */  TYPE("HTTPS", ZONE_HTTPS),

  /* 25 */  CLASS("IN", ZONE_IN),
  /* 26 */  TYPE("IPSECKEY", ZONE_IPSECKEY),
  /* 27 */  TYPE("ISDN", ZONE_ISDN),

  /* 28 */  TYPE("KEY", ZONE_KEY),
  /* 29 */  TYPE("KX", ZONE_KX),

  /* 30 */  TYPE("L32", ZONE_L32),
  /* 31 */  TYPE("L64", ZONE_L64),
  /* 32 */  TYPE("LOC", ZONE_LOC),
  /* 33 */  TYPE("LP", ZONE_LP),

  /* 34 */  TYPE("MB", ZONE_MB),
  /* 35 */  TYPE("MD", ZONE_MD),
  /* 36 */  TYPE("MF", ZONE_MF),
  /* 37 */  TYPE("MG", ZONE_MG),
  /* 38 */  TYPE("MINFO", ZONE_MINFO),
  /* 39 */  TYPE("MR", ZONE_MR),
  /* 40 */  TYPE("MX", ZONE_MX),

  /* 41 */ TYPE("NAPTR", ZONE_NAPTR),
  /* 42 */ TYPE("NID", ZONE_NID),
  /* 43 */ TYPE("NS", ZONE_NS),
  /* 44 */ TYPE("NSAP", ZONE_NSAP),
  /* 45 */ TYPE("NSAP-PTR", ZONE_NSAP_PTR),
  /* 46 */ TYPE("NSEC", ZONE_NSEC),
  /* 47 */ TYPE("NSEC3", ZONE_NSEC3),
  /* 48 */ TYPE("NSEC3PARAM", ZONE_NSEC3PARAM),
  /* 49 */ TYPE("NULL", ZONE_NULL),
  /* 50 */ TYPE("NXT", ZONE_NXT),

  /* 51 */ TYPE("OPENPGPKEY", ZONE_OPENPGPKEY),
  /* 52 */ TYPE("OPT", ZONE_OPT),

  /* 53 */ TYPE("PTR", ZONE_PTR),
  /* 54 */ TYPE("PX", ZONE_PX),

  /* 55 */ TYPE("RP", ZONE_RP),
  /* 56 */ TYPE("RRSIG", ZONE_RRSIG),
  /* 57 */ TYPE("RT", ZONE_RT),

  /* 58 */ TYPE("SIG", ZONE_SIG),
  /* 59 */ TYPE("SMIMEA", ZONE_SMIMEA),
  /* 60 */ TYPE("SOA", ZONE_SOA),
  /* 61 */ TYPE("SPF", ZONE_SPF),
  /* 62 */ TYPE("SRV", ZONE_SRV),
  /* 63 */ TYPE("SSHFP", ZONE_SSHFP),
  /* 64 */ TYPE("SVCB", ZONE_SVCB),

  /* 65 */ TYPE("TLSA", ZONE_TLSA),
  /* 66 */ TYPE("TXT", ZONE_TXT),

  /* 67 */ TYPE("URI", ZONE_URI),

  /* 68 */ TYPE("WKS", ZONE_WKS),

  /* 69 */ TYPE("X25", ZONE_X25),

  /* 70 */ TYPE("ZONEMD", ZONE_MD)
};

#undef CLASS
#undef TYPE

static const zone_table_t identifiers = { sizeof(x)/sizeof(x[0]), x };

static const zone_fast_table_t fast_identifiers[32] = {
  // A[A,A6,AAAA,AFSDB,APL]
  { { 200, 156, 203, 211, 23 },
    { &x[0], &x[1], &x[2], &x[3], &x[4] } },
  // B
  { { 0 }, { NULL } },
  // C[CAA,CDS,CDNSKEY,CERT,CH,CNAME,CS,CSYNC]
  { { 202, 72, 118, 80, 250, 232, 71, 218 },
    { &x[5], &x[6], &x[7], &x[8], &x[9], &x[10], &x[11], &x[12] } },
  // D[DHCID, DLV, DNAME, DNSKEY, DS]
  { { 225, 93, 232, 117, 71 },
    { &x[13], &x[14], &x[15], &x[16], &x[17] } },
  // E[EUI48=108,EUI64=109]
  { { 173, 145 },
    { &x[18], &x[19] } },
  // F
  { { 0 }, { NULL } },
  // G[GPOS=27]
  { { 73 },
    { &x[20] } },
  // H[HINFO,HIP,HS,HTTPS]
  { { 46,51,71,74 },
    { &x[21], &x[22], &x[23], &x[24] } },
  // I[IN,IPSECKEY,ISDN]
  { { 36, 119, 38 },
    { &x[25], &x[26], &x[27] } },
  // J
  { { 0 }, { NULL } },
  // K[KEY,KX]
  { { 114, 106 },
    { &x[28], &x[29] } },
  // L[L32,L64,LOC,LP]
  { { 129, 143, 216, 50 },
    { &x[30], &x[31], &x[32], &x[33] } },
  // M[MB,MD,MF,MG,MINFO,MR,MX]
  { { 208, 222, 236, 243, 46, 64, 106 },
    { &x[34], &x[35], &x[36], &x[37], &x[38], &x[39], &x[40] } },
  // N[NAPTR,NID,NS,NSAP,NSAP-PTR,NSEC,NSEC3,NSEC3PARAM,NULL,NXT]
  { { 67, 223, 71, 52, 70, 217, 138, 37, 24, 79},
    { &x[41], &x[42], &x[43], &x[44], &x[45], &x[46], &x[47], &x[48], &x[49],
      &x[50] } },
  // O[OPENPGPKEY,OPT]
  { { 121, 79 },
    { &x[51], &x[52] } },
  // P[PTR=12,PX=26]
  { { 65, 106 },
    { &x[53], &x[54] } },
  // Q
  { { 0 }, { NULL } },
  // R[RP,RRSIG,RT]
  { { 50, 246, 78 },
    { &x[55], &x[56], &x[57] } },
  // S[SIG,SMIMEA,SOA,SPF,SRV,SSHFP,SVCB]
  { { 244, 205, 202, 237, 93, 53, 210 },
    { &x[58], &x[59], &x[60], &x[61], &x[62], &x[63], &x[64] } },
  // T[TLSA,TXT]
  { { 203, 79 },
    { &x[65], &x[66] } },
  // U[URI]
  { { 2 },
    { &x[67] } },
  // V
  { { 0 }, { NULL } },
  // W[WKS]
  { { 66 },
    { &x[68] } },
  // X[X25]
  { { 150 },
    { &x[69] } },
  // Y
  { { 0 }, { NULL } },
  // Z[ZONEMD]
  { { 226 },
    { &x[70] } },
  { { 0 }, { NULL } },
  { { 0 }, { NULL } },
  { { 0 }, { NULL } },
  { { 0 }, { NULL } },
  { { 0 }, { NULL } },
  { { 0 }, { NULL } },
};

const zone_table_t *zone_identifiers = &identifiers;
const zone_fast_table_t *zone_fast_identifiers = fast_identifiers;
