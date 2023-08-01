/*
 * types.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TYPES_H
#define TYPES_H

zone_nonnull_all
static zone_really_inline int32_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol);

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol);

zone_nonnull_all
static zone_really_inline int32_t parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token);

zone_nonnull_all
extern int32_t zone_check_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_ip4(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_name(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_name(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int32(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ttl(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ttl(parser, type, &type->rdata.fields[4], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ttl(parser, type, &type->rdata.fields[5], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ttl(parser, type, &type->rdata.fields[6], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_hinfo_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_hinfo_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_string(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_string(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_minfo_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_minfo_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_name(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  do {
    if ((r = parse_string(parser, type, &type->rdata.fields[0], token)) < 0)
      return r;
    lex(parser, token);
  } while (token->code & (CONTIGUOUS | QUOTED));

  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_x25_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_x25_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_string(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_isdn_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_isdn_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_string(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);

  // subaddress is optional
  if (token->code & (CONTIGUOUS | QUOTED)) {
    if ((r = parse_string(parser, type, &type->rdata.fields[1], token)) < 0)
      return r;
    lex(parser, token);
  }

  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_rt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_rt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_key_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_key_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base64(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return zone_check_key_rdata(parser, type);
}

zone_nonnull_all
extern int32_t zone_check_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_ip6(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_naptr_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_naptr_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_string(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_string(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_string(parser, type, &type->rdata.fields[4], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[5], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base16(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_sshfp_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_sshfp_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base16(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;

  return zone_check_sshfp_rdata(parser, type);
}

zone_nonnull_all
extern int32_t zone_check_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_type(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ttl(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_time(parser, type, &type->rdata.fields[4], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_time(parser, type, &type->rdata.fields[5], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[6], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[7], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base64(parser, type, &type->rdata.fields[8], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_name(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_nsec(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base64(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_dhcid_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_dhcid_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_base64(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;

  return zone_check_dhcid_rdata(parser, type);
}

zone_nonnull_all
extern int32_t zone_check_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_symbol(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_salt(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base32(parser, type, &type->rdata.fields[4], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_nsec(parser, type, &type->rdata.fields[5], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_symbol(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_salt(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_tlsa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_tlsa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base16(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_openpgpkey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_openpgpkey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_base64(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_zonemd_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_zonemd_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int32(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base16(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_l32_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_l32_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ip4(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_l64_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_l64_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_ilnp64(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_eui48_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_eui48_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_eui48(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_eui64_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_eui64_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_eui64(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_uri_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_uri_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_quoted_text(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

zone_nonnull_all
extern int32_t zone_check_caa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_caa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_caa_tag(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_text(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser);
}

typedef struct type_descriptor type_descriptor_t;
struct type_descriptor {
  zone_type_info_t info;
  int32_t (*check)(zone_parser_t *, const zone_type_info_t *);
  int32_t (*parse)(zone_parser_t *, const zone_type_info_t *, token_t *);
};

zone_nonnull_all
extern int32_t zone_check_generic_rdata(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_generic_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  static const zone_field_info_t fields[2] = {
    { { 12, "RDATA length" }, ZONE_INT16, 0, { 0, NULL } },
    { { 5, "RDATA" }, ZONE_BLOB, 0, { 0, NULL } }
  };

  int32_t r;

  lex(parser, token); // discard "\\#"
  if ((r = have_contiguous(parser, type, &fields[0], token)) < 0)
    return r;

  size_t n = 0;
  const char *p = token->data;
  for (;; p++) {
    const size_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 +d;
  }

  if (n > UINT16_MAX || p - token->data > 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), TNAME(type));

  lex(parser, token);
  if (n)
    r = parse_base16(parser, type, &fields[1], token);
  else
    r = have_delimiter(parser, type, token);
  if (r < 0)
    return r;
  if (parser->rdata->length != n)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), TNAME(type));
  return ((const type_descriptor_t *)type)->check(parser, type);
}

zone_nonnull_all
static int32_t parse_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  (void)type;
  (void)token;
  SYNTAX_ERROR(parser, "Unknown record type");
}

#define SYMBOLS(symbols) \
  { (sizeof(symbols)/sizeof(symbols[0])), symbols }

#define SYMBOL(name, value) \
  { { name,  sizeof(name) - 1 }, value }

#define FIELDS(fields) \
  { (sizeof(fields)/sizeof(fields[0])), fields }

#define FIELD(name, type, /* qualifiers, symbols */ ...) \
  { { sizeof(name) - 1, name }, type, __VA_ARGS__ }

#define CLASS(name, code) \
  { { { name, sizeof(name) - 1 }, code } }

#define UNKNOWN_CLASS(code) \
  { { { "", 0 }, code } }

#define TYPE(name, code, options, fields, check, parse) \
  { { { { name, sizeof(name) - 1 }, code }, options, fields }, check, parse }

#define UNKNOWN_TYPE(code) \
  { { { { "", 0 }, code }, 0, { 0, NULL } }, \
    zone_check_generic_rdata, parse_unknown_rdata }

diagnostic_push()
gcc_diagnostic_ignored(missing-field-initializers)
clang_diagnostic_ignored(missing-field-initializers)

typedef struct class_descriptor class_descriptor_t;
struct class_descriptor {
  zone_symbol_t name;
};

static const class_descriptor_t classes[] = {
  UNKNOWN_CLASS(0),
  CLASS("IN", 1),
  CLASS("CS", 2),
  CLASS("CH", 3),
  CLASS("HS", 4)
};

static const zone_field_info_t a_rdata_fields[] = {
  FIELD("address", ZONE_IP4, 0)
};

static const zone_field_info_t ns_rdata_fields[] = {
  FIELD("host", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t md_rdata_fields[] = {
  FIELD("madname", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t mf_rdata_fields[] = {
  FIELD("madname", ZONE_NAME, ZONE_COMPRESSED)
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
  FIELD("minimum", ZONE_INT32, ZONE_TTL)
};

static const zone_field_info_t mb_rdata_fields[] = {
  FIELD("madname", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t mg_rdata_fields[] = {
  FIELD("mgmname", ZONE_NAME, ZONE_MAILBOX)
};

static const zone_field_info_t mr_rdata_fields[] = {
  FIELD("newname", ZONE_NAME, ZONE_MAILBOX)
};

static const zone_field_info_t ptr_rdata_fields[] = {
  FIELD("ptrdname", ZONE_NAME, ZONE_COMPRESSED)
};

static const zone_field_info_t hinfo_rdata_fields[] = {
  FIELD("cpu", ZONE_STRING, 0),
  FIELD("os", ZONE_STRING, 0)
};

static const zone_field_info_t minfo_rdata_fields[] = {
  FIELD("rmailbx", ZONE_NAME, ZONE_MAILBOX),
  FIELD("emailbx", ZONE_NAME, ZONE_MAILBOX)
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

static const zone_field_info_t rp_rdata_fields[] = {
  FIELD("mailbox", ZONE_NAME, ZONE_MAILBOX),
  FIELD("text", ZONE_NAME, 0)
};

static const zone_field_info_t afsdb_rdata_fields[] = {
  FIELD("subtype", ZONE_INT16, 0),
  FIELD("hostname", ZONE_NAME, 0)
};

static const zone_field_info_t x25_rdata_fields[] = {
  FIELD("address", ZONE_STRING, 0)
};

static const zone_field_info_t isdn_rdata_fields[] = {
  FIELD("address", ZONE_STRING, 0),
  FIELD("subaddress", ZONE_STRING, 0)
};

static const zone_field_info_t rt_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("hostname", ZONE_NAME, 0)
};

static const zone_field_info_t key_rdata_fields[] = {
  FIELD("flags", ZONE_INT16, 0),
  FIELD("protocol", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("publickey", ZONE_BLOB, ZONE_BASE64)
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

static const zone_field_info_t naptr_rdata_fields[] = {
  FIELD("order", ZONE_INT16, 0),
  FIELD("preference", ZONE_INT16, 0),
  FIELD("flags", ZONE_STRING, 0),
  FIELD("services", ZONE_STRING, 0),
  FIELD("regex", ZONE_STRING, 0),
  FIELD("replacement", ZONE_NAME, 0),
};

static const zone_field_info_t kx_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("exchanger", ZONE_NAME, 0)
};

static const zone_field_info_t dname_rdata_fields[] = {
  FIELD("source", ZONE_NAME, 0)
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

static const zone_field_info_t sshfp_rdata_fields[] = {
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("ftype", ZONE_INT8, 0),
  FIELD("fingerprint", ZONE_BLOB, ZONE_BASE16)
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

static const zone_field_info_t dhcid_rdata_fields[] = {
  FIELD("dhcpinfo", ZONE_BLOB, ZONE_BASE64)
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

static const zone_field_info_t tlsa_rdata_fields[] = {
  FIELD("usage", ZONE_INT8, 0),
  FIELD("selector", ZONE_INT8, 0),
  FIELD("matching type", ZONE_INT8, 0),
  FIELD("certificate association data", ZONE_BLOB, ZONE_BASE16)
};

static const zone_field_info_t smimea_rdata_fields[] = {
  FIELD("usage", ZONE_INT8, 0),
  FIELD("selector", ZONE_INT8, 0),
  FIELD("matching type", ZONE_INT8, 0),
  FIELD("certificate association data", ZONE_BLOB, ZONE_BASE16)
};

static const zone_field_info_t cds_rdata_fields[] = {
  FIELD("keytag", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(ds_algorithm_symbols)),
  FIELD("digtype", ZONE_INT8, 0, SYMBOLS(ds_digest_type_symbols)),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16)
};

static const zone_field_info_t cdnskey_rdata_fields[] = {
  FIELD("flags", ZONE_INT16, 0),
  FIELD("protocol", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("publickey", ZONE_BLOB, ZONE_BASE64)
};

static const zone_field_info_t openpgpkey_rdata_fields[] = {
  FIELD("key", ZONE_BLOB, ZONE_BASE64)
};

static const zone_field_info_t zonemd_rdata_fields[] = {
  FIELD("serial", ZONE_INT32, 0),
  FIELD("scheme", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16),
};

static const zone_field_info_t spf_rdata_fields[] = {
  FIELD("text", ZONE_STRING, ZONE_SEQUENCE)
};

// RFC6742 specifies the syntax for the locator is compatible with the syntax
// for IPv4 addresses, but then proceeds to provide an example with leading
// zeroes. The example is corrected in the errata.
static const zone_field_info_t l32_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("locator", ZONE_IP4, 0)
};

static const zone_field_info_t l64_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("locator", ZONE_ILNP64, 0)
};

static const zone_field_info_t lp_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("pointer", ZONE_NAME, 0)
};

static const zone_field_info_t eui48_rdata_fields[] = {
  FIELD("address", ZONE_EUI48, 0)
};

static const zone_field_info_t eui64_rdata_fields[] = {
  FIELD("address", ZONE_EUI64, 0)
};

static const zone_field_info_t uri_rdata_fields[] = {
  FIELD("priority", ZONE_INT16, 0),
  FIELD("weight", ZONE_INT16, 0),
  FIELD("target", ZONE_BLOB, 0)
};

static const zone_field_info_t caa_rdata_fields[] = {
  FIELD("flags", ZONE_INT8, 0),
  FIELD("tag", ZONE_STRING, ZONE_CAA_TAG),
  FIELD("value", ZONE_BLOB, 0)
};

// https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template
static const zone_field_info_t avc_rdata_fields[] = {
  FIELD("text", ZONE_STRING, ZONE_SEQUENCE)
};

static const zone_field_info_t dlv_rdata_fields[] = {
  FIELD("key", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("type", ZONE_INT8, 0),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16)
};

static const type_descriptor_t types[] = {
  UNKNOWN_TYPE(0),

  TYPE("A", ZONE_A, ZONE_ANY, FIELDS(a_rdata_fields),
            zone_check_a_rdata, parse_a_rdata),
  TYPE("NS", ZONE_NS, ZONE_ANY, FIELDS(ns_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  TYPE("MD", ZONE_MD, ZONE_ANY | ZONE_OBSOLETE, FIELDS(md_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  TYPE("MF", ZONE_MF, ZONE_ANY | ZONE_OBSOLETE, FIELDS(mf_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  TYPE("CNAME", ZONE_CNAME, ZONE_ANY, FIELDS(cname_rdata_fields),
                zone_check_ns_rdata, parse_ns_rdata),
  TYPE("SOA", ZONE_SOA, ZONE_ANY, FIELDS(soa_rdata_fields),
              zone_check_soa_rdata, parse_soa_rdata),
  TYPE("MB", ZONE_MB, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mb_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  TYPE("MG", ZONE_MG, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mg_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  TYPE("MR", ZONE_MR, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mr_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),

  UNKNOWN_TYPE(10),

  TYPE("WKS", ZONE_WKS, ZONE_IN, FIELDS(wks_rdata_fields), 0, 0),
  TYPE("PTR", ZONE_PTR, ZONE_ANY, FIELDS(ptr_rdata_fields),
              zone_check_ns_rdata, parse_ns_rdata),
  TYPE("HINFO", ZONE_HINFO, ZONE_ANY, FIELDS(hinfo_rdata_fields),
                zone_check_hinfo_rdata, parse_hinfo_rdata),
  TYPE("MINFO", ZONE_MINFO, ZONE_ANY, FIELDS(minfo_rdata_fields),
                zone_check_minfo_rdata, parse_minfo_rdata),
  TYPE("MX", ZONE_MX, ZONE_ANY, FIELDS(mx_rdata_fields),
             zone_check_mx_rdata, parse_mx_rdata),
  TYPE("TXT", ZONE_TXT, ZONE_ANY, FIELDS(txt_rdata_fields),
              zone_check_txt_rdata, parse_txt_rdata),
  TYPE("RP", ZONE_RP, ZONE_ANY, FIELDS(rp_rdata_fields),
             zone_check_minfo_rdata, parse_minfo_rdata),
  TYPE("AFSDB", ZONE_AFSDB, ZONE_ANY, FIELDS(afsdb_rdata_fields),
                zone_check_mx_rdata, parse_mx_rdata),
  TYPE("X25", ZONE_X25, ZONE_ANY, FIELDS(x25_rdata_fields),
              zone_check_x25_rdata, parse_x25_rdata),
  TYPE("ISDN", ZONE_ISDN, ZONE_ANY, FIELDS(isdn_rdata_fields),
               zone_check_isdn_rdata, parse_isdn_rdata),
  TYPE("RT", ZONE_RT, ZONE_ANY, FIELDS(rt_rdata_fields),
             zone_check_rt_rdata, parse_rt_rdata),

  UNKNOWN_TYPE(22),
  UNKNOWN_TYPE(23),
  UNKNOWN_TYPE(24),

  TYPE("KEY", ZONE_KEY, ZONE_ANY, FIELDS(key_rdata_fields),
              zone_check_key_rdata, parse_key_rdata),

  UNKNOWN_TYPE(26),
  UNKNOWN_TYPE(27),

  TYPE("AAAA", ZONE_AAAA, ZONE_IN, FIELDS(aaaa_rdata_fields),
               zone_check_aaaa_rdata, parse_aaaa_rdata),

  UNKNOWN_TYPE(29),
  UNKNOWN_TYPE(30),
  UNKNOWN_TYPE(31),
  UNKNOWN_TYPE(32),

  TYPE("SRV", ZONE_SRV, ZONE_IN, FIELDS(srv_rdata_fields),
              zone_check_srv_rdata, parse_srv_rdata),

  UNKNOWN_TYPE(34),

  TYPE("NAPTR", ZONE_NAPTR, ZONE_IN, FIELDS(naptr_rdata_fields),
                zone_check_naptr_rdata, parse_naptr_rdata),
  TYPE("KX", ZONE_KX, ZONE_IN, FIELDS(kx_rdata_fields),
             zone_check_mx_rdata, parse_mx_rdata),

  UNKNOWN_TYPE(37),
  UNKNOWN_TYPE(38),

  TYPE("DNAME", ZONE_DNAME, ZONE_ANY, FIELDS(dname_rdata_fields),
                zone_check_ns_rdata, parse_ns_rdata),

  UNKNOWN_TYPE(40),
  UNKNOWN_TYPE(41),
  UNKNOWN_TYPE(42),

  TYPE("DS", ZONE_DS, ZONE_ANY, FIELDS(ds_rdata_fields),
             zone_check_ds_rdata, parse_ds_rdata),
  TYPE("SSHFP", ZONE_SSHFP, ZONE_ANY, FIELDS(sshfp_rdata_fields),
                zone_check_sshfp_rdata, parse_sshfp_rdata),

  UNKNOWN_TYPE(45), // IPSECKEY

  TYPE("RRSIG", ZONE_RRSIG, ZONE_ANY, FIELDS(rrsig_rdata_fields),
                zone_check_rrsig_rdata, parse_rrsig_rdata),
  TYPE("NSEC", ZONE_NSEC, ZONE_ANY, FIELDS(nsec_rdata_fields),
               zone_check_nsec_rdata, parse_nsec_rdata),
  TYPE("DNSKEY", ZONE_DNSKEY, ZONE_ANY, FIELDS(dnskey_rdata_fields),
                 zone_check_dnskey_rdata, parse_dnskey_rdata),
  TYPE("DHCID", ZONE_DHCID, ZONE_IN, FIELDS(dhcid_rdata_fields),
                zone_check_dhcid_rdata, parse_dhcid_rdata),
  TYPE("NSEC3", ZONE_NSEC3, ZONE_ANY, FIELDS(nsec3_rdata_fields),
                zone_check_nsec3_rdata, parse_nsec3_rdata),
  TYPE("NSEC3PARAM", ZONE_NSEC3PARAM, ZONE_ANY, FIELDS(nsec3param_rdata_fields),
                     zone_check_nsec3param_rdata, parse_nsec3param_rdata),
  TYPE("TLSA", ZONE_TLSA, ZONE_ANY, FIELDS(tlsa_rdata_fields),
               zone_check_tlsa_rdata, parse_tlsa_rdata),
  TYPE("SMIMEA", ZONE_SMIMEA, ZONE_ANY, FIELDS(smimea_rdata_fields),
                 zone_check_tlsa_rdata, parse_tlsa_rdata),

  UNKNOWN_TYPE(54),
  UNKNOWN_TYPE(55), // HIP
  UNKNOWN_TYPE(56),
  UNKNOWN_TYPE(57),
  UNKNOWN_TYPE(58),

  TYPE("CDS", ZONE_CDS, ZONE_ANY, FIELDS(cds_rdata_fields),
              zone_check_ds_rdata, parse_ds_rdata),
  TYPE("CDNSKEY", ZONE_CDNSKEY, ZONE_ANY, FIELDS(cdnskey_rdata_fields),
                  zone_check_dnskey_rdata, parse_dnskey_rdata),
  TYPE("OPENPGPKEY", ZONE_OPENPGPKEY, ZONE_ANY, FIELDS(openpgpkey_rdata_fields),
                     zone_check_openpgpkey_rdata, parse_openpgpkey_rdata),

  UNKNOWN_TYPE(62),

  TYPE("ZONEMD", ZONE_ZONEMD, ZONE_ANY, FIELDS(zonemd_rdata_fields),
                 zone_check_zonemd_rdata, parse_zonemd_rdata),

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

  TYPE("SPF", ZONE_SPF, ZONE_ANY | ZONE_OBSOLETE, FIELDS(spf_rdata_fields),
              zone_check_txt_rdata, parse_txt_rdata),

  UNKNOWN_TYPE(100),
  UNKNOWN_TYPE(101),
  UNKNOWN_TYPE(102),
  UNKNOWN_TYPE(103),
  UNKNOWN_TYPE(104),

  TYPE("L32", ZONE_L32, ZONE_ANY, FIELDS(l32_rdata_fields),
              zone_check_l32_rdata, parse_l32_rdata),
  TYPE("L64", ZONE_L64, ZONE_ANY, FIELDS(l64_rdata_fields),
              zone_check_l64_rdata, parse_l64_rdata),
  TYPE("LP", ZONE_LP, ZONE_ANY, FIELDS(lp_rdata_fields),
             zone_check_mx_rdata, parse_mx_rdata),
  TYPE("EUI48", ZONE_EUI48, ZONE_ANY, FIELDS(eui48_rdata_fields),
                zone_check_eui48_rdata, parse_eui48_rdata),
  TYPE("EUI64", ZONE_EUI64, ZONE_ANY, FIELDS(eui64_rdata_fields),
                zone_check_eui64_rdata, parse_eui64_rdata),

  UNKNOWN_TYPE(110),
  UNKNOWN_TYPE(111),
  UNKNOWN_TYPE(112),
  UNKNOWN_TYPE(113),
  UNKNOWN_TYPE(114),
  UNKNOWN_TYPE(115),
  UNKNOWN_TYPE(116),
  UNKNOWN_TYPE(117),
  UNKNOWN_TYPE(118),
  UNKNOWN_TYPE(119),
  UNKNOWN_TYPE(120),
  UNKNOWN_TYPE(121),
  UNKNOWN_TYPE(122),
  UNKNOWN_TYPE(123),
  UNKNOWN_TYPE(124),
  UNKNOWN_TYPE(125),
  UNKNOWN_TYPE(126),
  UNKNOWN_TYPE(127),
  UNKNOWN_TYPE(128),
  UNKNOWN_TYPE(129),
  UNKNOWN_TYPE(130),
  UNKNOWN_TYPE(131),
  UNKNOWN_TYPE(132),
  UNKNOWN_TYPE(133),
  UNKNOWN_TYPE(134),
  UNKNOWN_TYPE(135),
  UNKNOWN_TYPE(136),
  UNKNOWN_TYPE(137),
  UNKNOWN_TYPE(138),
  UNKNOWN_TYPE(139),
  UNKNOWN_TYPE(140),
  UNKNOWN_TYPE(141),
  UNKNOWN_TYPE(142),
  UNKNOWN_TYPE(143),
  UNKNOWN_TYPE(144),
  UNKNOWN_TYPE(145),
  UNKNOWN_TYPE(146),
  UNKNOWN_TYPE(147),
  UNKNOWN_TYPE(148),
  UNKNOWN_TYPE(149),
  UNKNOWN_TYPE(150),
  UNKNOWN_TYPE(151),
  UNKNOWN_TYPE(152),
  UNKNOWN_TYPE(153),
  UNKNOWN_TYPE(154),
  UNKNOWN_TYPE(155),
  UNKNOWN_TYPE(156),
  UNKNOWN_TYPE(157),
  UNKNOWN_TYPE(158),
  UNKNOWN_TYPE(159),
  UNKNOWN_TYPE(160),
  UNKNOWN_TYPE(161),
  UNKNOWN_TYPE(162),
  UNKNOWN_TYPE(163),
  UNKNOWN_TYPE(164),
  UNKNOWN_TYPE(165),
  UNKNOWN_TYPE(166),
  UNKNOWN_TYPE(167),
  UNKNOWN_TYPE(168),
  UNKNOWN_TYPE(169),
  UNKNOWN_TYPE(170),
  UNKNOWN_TYPE(171),
  UNKNOWN_TYPE(172),
  UNKNOWN_TYPE(173),
  UNKNOWN_TYPE(174),
  UNKNOWN_TYPE(175),
  UNKNOWN_TYPE(176),
  UNKNOWN_TYPE(177),
  UNKNOWN_TYPE(178),
  UNKNOWN_TYPE(179),
  UNKNOWN_TYPE(180),
  UNKNOWN_TYPE(181),
  UNKNOWN_TYPE(182),
  UNKNOWN_TYPE(183),
  UNKNOWN_TYPE(184),
  UNKNOWN_TYPE(185),
  UNKNOWN_TYPE(186),
  UNKNOWN_TYPE(187),
  UNKNOWN_TYPE(188),
  UNKNOWN_TYPE(189),
  UNKNOWN_TYPE(190),
  UNKNOWN_TYPE(191),
  UNKNOWN_TYPE(192),
  UNKNOWN_TYPE(193),
  UNKNOWN_TYPE(194),
  UNKNOWN_TYPE(195),
  UNKNOWN_TYPE(196),
  UNKNOWN_TYPE(197),
  UNKNOWN_TYPE(198),
  UNKNOWN_TYPE(199),
  UNKNOWN_TYPE(200),
  UNKNOWN_TYPE(201),
  UNKNOWN_TYPE(202),
  UNKNOWN_TYPE(203),
  UNKNOWN_TYPE(204),
  UNKNOWN_TYPE(205),
  UNKNOWN_TYPE(206),
  UNKNOWN_TYPE(207),
  UNKNOWN_TYPE(208),
  UNKNOWN_TYPE(209),
  UNKNOWN_TYPE(210),
  UNKNOWN_TYPE(211),
  UNKNOWN_TYPE(212),
  UNKNOWN_TYPE(213),
  UNKNOWN_TYPE(214),
  UNKNOWN_TYPE(215),
  UNKNOWN_TYPE(216),
  UNKNOWN_TYPE(217),
  UNKNOWN_TYPE(218),
  UNKNOWN_TYPE(219),
  UNKNOWN_TYPE(220),
  UNKNOWN_TYPE(221),
  UNKNOWN_TYPE(222),
  UNKNOWN_TYPE(223),
  UNKNOWN_TYPE(224),
  UNKNOWN_TYPE(225),
  UNKNOWN_TYPE(226),
  UNKNOWN_TYPE(227),
  UNKNOWN_TYPE(228),
  UNKNOWN_TYPE(229),
  UNKNOWN_TYPE(230),
  UNKNOWN_TYPE(231),
  UNKNOWN_TYPE(232),
  UNKNOWN_TYPE(233),
  UNKNOWN_TYPE(234),
  UNKNOWN_TYPE(235),
  UNKNOWN_TYPE(236),
  UNKNOWN_TYPE(237),
  UNKNOWN_TYPE(238),
  UNKNOWN_TYPE(239),
  UNKNOWN_TYPE(240),
  UNKNOWN_TYPE(241),
  UNKNOWN_TYPE(242),
  UNKNOWN_TYPE(243),
  UNKNOWN_TYPE(244),
  UNKNOWN_TYPE(245),
  UNKNOWN_TYPE(246),
  UNKNOWN_TYPE(247),
  UNKNOWN_TYPE(248),
  UNKNOWN_TYPE(249),
  UNKNOWN_TYPE(250),
  UNKNOWN_TYPE(251),
  UNKNOWN_TYPE(252),
  UNKNOWN_TYPE(253),
  UNKNOWN_TYPE(254),
  UNKNOWN_TYPE(255),

  TYPE("URI", ZONE_URI, ZONE_ANY, FIELDS(uri_rdata_fields),
              zone_check_uri_rdata, parse_uri_rdata),
  TYPE("CAA", ZONE_CAA, ZONE_ANY, FIELDS(caa_rdata_fields),
              zone_check_caa_rdata, parse_caa_rdata),
  TYPE("AVC", ZONE_AVC, ZONE_ANY, FIELDS(avc_rdata_fields),
              zone_check_txt_rdata, parse_txt_rdata),
  TYPE("DLV", ZONE_DLV, ZONE_ANY | ZONE_OBSOLETE, FIELDS(dlv_rdata_fields),
              zone_check_ds_rdata, parse_ds_rdata)
};

#undef UNKNOWN_CLASS
#undef CLASS
#undef UNKNOWN_TYPE
#undef TYPE

diagnostic_pop()

#endif // TYPES_H
