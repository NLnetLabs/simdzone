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

zone_return_t zone_parse_period(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_time(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_int8(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_int16(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_int32(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_generic_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_generic_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t parse_name(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_algorithm(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_certificate(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_type(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_base64(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_domain_name(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

zone_return_t zone_parse_generic_string(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

#define NO_TYPE {NULL, 0, 0, (struct rdata_descriptor[]){{ { 0, 0, 0 }, 0, 0 }} }

TYPES(
  NO_TYPE,
  TYPE("A", 1, 0, RDATA( IP4("ADDRESS", 0, FUNCTIONS(0, 0)) )),
  TYPE("NS", 2, ANY, RDATA( NAME("NSDNAME", COMPRESSED, FUNCTIONS(0,0)) )),
  TYPE("MD", 3, ANY|OBSOLETE, RDATA( NAME("MADNAME", COMPRESSED, FUNCTIONS(0,0)) )),
  TYPE("MF", 4, ANY|OBSOLETE, RDATA( NAME("MADNAME", COMPRESSED, FUNCTIONS(0,0)) )),
  TYPE("CNAME", 5, 0, RDATA( NAME("CNAME", COMPRESSED, FUNCTIONS(0,0)) )),

  TYPE("SOA", 6, 0,
    RDATA(
      NAME("MNAME", COMPRESSED, FUNCTIONS(0, 0)),
      NAME("RNAME", MAILBOX, FUNCTIONS(0, 0)),
      INT32("SERIAL", 0, FUNCTIONS(0, 0)),
      INT32("REFRESH", 0, FUNCTIONS(zone_parse_period, 0)),
      INT32("RETRY", 0, FUNCTIONS(zone_parse_period, 0)),
      INT32("EXPIRE", 0, FUNCTIONS(zone_parse_period, 0)),
      INT32("MINIMUM", 0, FUNCTIONS(zone_parse_period,0)))),

  TYPE("MB", 7, ANY|EXPERIMENTAL, RDATA( NAME("MADNAME", COMPRESSED, FUNCTIONS(0,0)) )),
  TYPE("MG", 8, ANY|EXPERIMENTAL, RDATA( NAME("MGMNAME", MAILBOX, FUNCTIONS(0,0)) )),
  TYPE("MR", 9, ANY|EXPERIMENTAL, RDATA( NAME("NEWNAME", MAILBOX, FUNCTIONS(0,0)) )),
  NO_TYPE, // NULL
  NO_TYPE, // WKS
  TYPE("PTR", 12, 0, RDATA( NAME("PTR", COMPRESSED, FUNCTIONS(0,0)) )),
  TYPE("HINFO", 13, 0,
    RDATA(
      STRING("CPU", 0, FUNCTIONS(0,0)),
      STRING("OS", 0, FUNCTIONS(0,0)) )),
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  TYPE("SIG", 24, 0,
    RDATA(
      INT16("type covered", 0, FUNCTIONS(zone_parse_type, 0)),
      INT8("algorithm", 0, FUNCTIONS(zone_parse_algorithm, 0)),
      INT8("labels", 0, FUNCTIONS(0, 0)),
      INT32("original TTL", 0, FUNCTIONS(zone_parse_period, 0)),
      INT32("signature expiration", 0, FUNCTIONS(zone_parse_time, 0)),
      INT32("signature inception", 0, FUNCTIONS(zone_parse_time, 0)),
      INT16("key tag", 0, FUNCTIONS(0, 0)),
      NAME("signer's name", 0, FUNCTIONS(0, 0)),
      BASE64("signature", 0, FUNCTIONS(0, 0)))),
  NO_TYPE,
  NO_TYPE,
  NO_TYPE,
  TYPE("AAAA", 28, 0, RDATA( IP6("ADDRESS", 0, FUNCTIONS(0, 0)) ))
)

#endif // ZONE_TYPES_H
