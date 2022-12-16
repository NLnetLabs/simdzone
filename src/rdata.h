/*
 * rdata.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef RDATA_H
#define RDATA_H

#define FIELD(type, info, size, rdatax) \
  { ZONE_RDATA | type, { .rdata = info }, size, { .octets = rdatax } }

zone_always_inline()
static inline zone_return_t parse_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_ip4(parser, &zone_types[ZONE_A].rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in A record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_NS].rdata.fields, &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in NS record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_cname_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_CNAME].rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in CNAME record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_SOA].rdata.fields[0], &token);

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_SOA].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int32(parser, &zone_types[ZONE_SOA].rdata.fields[2], &token);

  lex(parser, &token);
  parse_ttl(parser, &zone_types[ZONE_SOA].rdata.fields[3], &token);

  lex(parser, &token);
  parse_ttl(parser, &zone_types[ZONE_SOA].rdata.fields[4], &token);

  lex(parser, &token);
  parse_ttl(parser, &zone_types[ZONE_SOA].rdata.fields[5], &token);

  lex(parser, &token);
  parse_ttl(parser, &zone_types[ZONE_SOA].rdata.fields[6], &token);

  if (lex(parser, &token))
      SYNTAX_ERROR(parser, "Trailing data in SOA record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_MX].rdata.fields[0], &token);

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_MX].rdata.fields[1], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in MX record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_string(parser, &zone_types[ZONE_TXT].rdata.fields[0], &token);

  while (lex(parser, &token))
    if (parse_string(parser, &zone_types[ZONE_TXT].rdata.fields[0], &token))
      break;

  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_ip6(parser, &zone_types[ZONE_AAAA].rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in AAAA record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;
  
  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_SRV].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_SRV].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_SRV].rdata.fields[2], &token);

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_SRV].rdata.fields[3], &token);

  if (lex(parser, &token))
    SEMANTIC_ERROR(parser, "Trailing data in SRV record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;
  
  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_DS].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_DS].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_DS].rdata.fields[2], &token);

  while (lex(parser, &token))
    parse_base16(parser, &zone_types[ZONE_DS].rdata.fields[3], &token);

  if (parser->rdlength <= 4)
    SYNTAX_ERROR(parser, "Missing digest in DS record");
  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_type(parser, &zone_types[ZONE_RRSIG].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_RRSIG].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_RRSIG].rdata.fields[2], &token);

  lex(parser, &token);
  parse_ttl(parser, &zone_types[ZONE_RRSIG].rdata.fields[3], &token);

  lex(parser, &token);
  parse_time(parser, &zone_types[ZONE_RRSIG].rdata.fields[4], &token);

  lex(parser, &token);
  parse_time(parser, &zone_types[ZONE_RRSIG].rdata.fields[5], &token);

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_RRSIG].rdata.fields[6], &token);

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_RRSIG].rdata.fields[7], &token);

  while (lex(parser, &token))
    parse_base64(parser, &zone_types[ZONE_RRSIG].rdata.fields[8], &token);

  accept_base64(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &zone_types[ZONE_NSEC].rdata.fields[0], &token);

  while (lex(parser, &token))
    parse_nsec(parser, &zone_types[ZONE_NSEC].rdata.fields[1], &token);

  accept_nsec(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_DNSKEY].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_DNSKEY].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_DNSKEY].rdata.fields[2], &token);

  while (lex(parser, &token))
    parse_base64(parser, &zone_types[ZONE_DNSKEY].rdata.fields[3], &token);

  accept_base64(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_NSEC3].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_NSEC3].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_NSEC3].rdata.fields[2], &token);

  lex(parser, &token);
  parse_salt(parser, &zone_types[ZONE_NSEC3].rdata.fields[3], &token);

  lex(parser, &token);
  parse_base32(parser, &zone_types[ZONE_NSEC3].rdata.fields[4], &token);

  while (lex(parser, &token))
    parse_nsec(parser, &zone_types[ZONE_NSEC3].rdata.fields[5], &token);

  return accept_rr(parser, NULL, user_data);
}

zone_always_inline()
static inline zone_return_t parse_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_NSEC3PARAM].rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &zone_types[ZONE_NSEC3PARAM].rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &zone_types[ZONE_NSEC3PARAM].rdata.fields[2], &token);

  lex(parser, &token);
  parse_salt(parser, &zone_types[ZONE_NSEC3PARAM].rdata.fields[3], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in NSEC3PARAM record");

  return accept_rr(parser, NULL, user_data);
}

zone_never_inline()
static zone_return_t parse_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  (void)parser;
  (void)info;
  (void)user_data;
  abort();
  return 0;
}

#endif // RDATA_H
