/*
 * classes.h -- name to RR type map
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef TYPES_H
#define TYPES_H

#define TYPE(id, name) { id, #name, (sizeof(#name) - 1) }

#define TYPE_RRSIG (46)
#define TYPE_NS (2)
#define TYPE_NSEC (47)
#define TYPE_NSEC3 (50)
#define TYPE_NSEC3PARAM (51)
#define TYPE_DS (43)
#define TYPE_DNSKEY (48)
#define TYPE_A (1)
#define TYPE_AAAA (28)
#define TYPE_SOA (6)
#define TYPE_TXT (16)
#define TYPE_SVCB (64)

struct map {
  const uint16_t type;
  const char *name;
  const size_t namelen;
};

static const struct map types[] = {
  TYPE(1, A),
  TYPE(28, AAAA),
  TYPE(18, AFSDB),
  TYPE(42, APL),
  TYPE(258, AVC),
  TYPE(257, CAA),
  TYPE(60, CDNSKEY),
  TYPE(59, CDS),
  TYPE(37, CERT),
  TYPE(5, CNAME),
  TYPE(62, CSYNC),
  TYPE(49, DHCID),
  TYPE(32769, DLV),
  TYPE(39, DNAME),
  TYPE(48, DNSKEY),
  TYPE(43, DS),
  TYPE(108, EUI48),
  TYPE(109, EUI64),
  TYPE(13, HINFO),
  TYPE(45, IPSECKEY),
  TYPE(20, ISDN),
  TYPE(25, KEY),
  TYPE(36, KX),
  TYPE(105, L32),
  TYPE(106, L64),
  TYPE(29, LOC),
  TYPE(107, LP),
  TYPE(7, MB),
  TYPE(3, MD),
  TYPE(4, MF),
  TYPE(8, MG),
  TYPE(14, MINFO),
  TYPE(9, MR),
  TYPE(15, MX),
  TYPE(35, NAPTR),
  TYPE(104, NID),
  TYPE(2, NS),
  TYPE(22, NSAP),
  TYPE(47, NSEC),
  TYPE(50, NSEC3),
  TYPE(51, NSEC3PARAM),
  TYPE(30, NXT),
  TYPE(61, OPENPGPKEY),
  TYPE(41, OPT),
  TYPE(12, PTR),
  TYPE(26, PX),
  TYPE(17, RP),
  TYPE(46, RRSIG),
  TYPE(21, RT),
  TYPE(24, SIG),
  TYPE(53, SMIMEA),
  TYPE(6, SOA),
  TYPE(99, SPF),
  TYPE(33, SRV),
  TYPE(44, SSHFP),
  TYPE(64, SVCB),
  TYPE(52, TLSA),
  TYPE(16, TXT),
  TYPE(256, URI),
  TYPE(11, WKS),
  TYPE(19, X25)
};

#undef TYPE

#endif // TYPES_H
