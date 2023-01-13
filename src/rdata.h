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

static zone_return_t parse_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_ip4(parser, &info->rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in A record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in NS record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_cname_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in CNAME record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int32(parser, &info->rdata.fields[2], &token);

  lex(parser, &token);
  parse_ttl(parser, &info->rdata.fields[3], &token);

  lex(parser, &token);
  parse_ttl(parser, &info->rdata.fields[4], &token);

  lex(parser, &token);
  parse_ttl(parser, &info->rdata.fields[5], &token);

  lex(parser, &token);
  parse_ttl(parser, &info->rdata.fields[6], &token);

  if (lex(parser, &token))
      SYNTAX_ERROR(parser, "Trailing data in SOA record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[1], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in MX record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_string(parser, &info->rdata.fields[0], &token);

  while (lex(parser, &token))
    if (parse_string(parser, &info->rdata.fields[0], &token))
      break;

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_ip6(parser, &info->rdata.fields[0], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in AAAA record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;
  
  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[2], &token);

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[3], &token);

  if (lex(parser, &token))
    SEMANTIC_ERROR(parser, "Trailing data in SRV record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;
  
  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[2], &token);

  while (lex(parser, &token))
    parse_base16(parser, &info->rdata.fields[3], &token);

  if (parser->rdlength <= 4)
    SYNTAX_ERROR(parser, "Missing digest in DS record");
  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_type(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[2], &token);

  lex(parser, &token);
  parse_ttl(parser, &info->rdata.fields[3], &token);

  lex(parser, &token);
  parse_time(parser, &info->rdata.fields[4], &token);

  lex(parser, &token);
  parse_time(parser, &info->rdata.fields[5], &token);

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[6], &token);

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[7], &token);

  while (lex(parser, &token))
    parse_base64(parser, &info->rdata.fields[8], &token);

  accept_base64(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  (void)info;

  lex(parser, &token);
  parse_name(parser, &info->rdata.fields[0], &token);

  while (lex(parser, &token))
    parse_nsec(parser, &info->rdata.fields[1], &token);

  accept_nsec(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[2], &token);

  while (lex(parser, &token))
    parse_base64(parser, &info->rdata.fields[3], &token);

  accept_base64(parser, user_data);

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[2], &token);

  lex(parser, &token);
  parse_salt(parser, &info->rdata.fields[3], &token);

  lex(parser, &token);
  parse_base32(parser, &info->rdata.fields[4], &token);

  while (lex(parser, &token))
    parse_nsec(parser, &info->rdata.fields[5], &token);

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  zone_token_t token;

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[0], &token);

  lex(parser, &token);
  parse_int8(parser, &info->rdata.fields[1], &token);

  lex(parser, &token);
  parse_int16(parser, &info->rdata.fields[2], &token);

  lex(parser, &token);
  parse_salt(parser, &info->rdata.fields[3], &token);

  if (lex(parser, &token))
    SYNTAX_ERROR(parser, "Trailing data in NSEC3PARAM record");

  return accept_rr(parser, NULL, user_data);
}

static zone_return_t parse_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *info, void *user_data)
{
  (void)parser;
  (void)info;
  (void)user_data;
  abort();
  return 0;
}

#define SYMBOLS(symbols) \
  { (sizeof(symbols)/sizeof(symbols[0])), symbols }

#define SYMBOL(name, value) \
  { { sizeof(name) - 1, name }, value }

#define FIELDS(fields) \
  { (sizeof(fields)/sizeof(fields[0])), fields }

#define FIELD(name, type, /* qualifiers, symbols */ ...) \
  { { sizeof(name) - 1, name }, type, __VA_ARGS__ }

#define TYPE(name, code, options, fields, parse) \
  { { { sizeof(name) - 1, name }, code, options, fields }, parse }

#define UNKNOWN_TYPE(code) \
  { { { 0, "" }, code, 0, { 0, NULL } }, parse_unknown_rdata }

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

static const zone_type_descriptor_t types[] = {
  UNKNOWN_TYPE(0),

  TYPE("A", ZONE_A, ZONE_ANY, FIELDS(a_rdata_fields), parse_a_rdata),
  TYPE("NS", ZONE_NS, ZONE_ANY, FIELDS(ns_rdata_fields), parse_ns_rdata),
  UNKNOWN_TYPE(3),
  UNKNOWN_TYPE(4),
  TYPE("CNAME", ZONE_CNAME, ZONE_ANY, FIELDS(cname_rdata_fields), parse_cname_rdata),
  TYPE("SOA", ZONE_SOA, ZONE_ANY, FIELDS(soa_rdata_fields), parse_soa_rdata),

  UNKNOWN_TYPE(7),
  UNKNOWN_TYPE(8),
  UNKNOWN_TYPE(9),
  UNKNOWN_TYPE(10),

  TYPE("WKS", ZONE_WKS, ZONE_IN, FIELDS(wks_rdata_fields), 0),

  UNKNOWN_TYPE(12),
  UNKNOWN_TYPE(13),
  UNKNOWN_TYPE(14),

  TYPE("MX", ZONE_MX, ZONE_ANY, FIELDS(mx_rdata_fields), parse_mx_rdata),
  TYPE("TXT", ZONE_TXT, ZONE_ANY, FIELDS(txt_rdata_fields), parse_txt_rdata),

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

  TYPE("AAAA", ZONE_AAAA, ZONE_IN, FIELDS(aaaa_rdata_fields), parse_aaaa_rdata),

  UNKNOWN_TYPE(29),
  UNKNOWN_TYPE(30),
  UNKNOWN_TYPE(31),
  UNKNOWN_TYPE(32),

  TYPE("SRV", ZONE_SRV, ZONE_IN, FIELDS(srv_rdata_fields), parse_srv_rdata),

  UNKNOWN_TYPE(34),
  UNKNOWN_TYPE(35),
  UNKNOWN_TYPE(36),
  UNKNOWN_TYPE(37),
  UNKNOWN_TYPE(38),
  UNKNOWN_TYPE(39),
  UNKNOWN_TYPE(40),
  UNKNOWN_TYPE(41),
  UNKNOWN_TYPE(42),

  TYPE("DS", ZONE_DS, ZONE_ANY, FIELDS(ds_rdata_fields), parse_ds_rdata),

  UNKNOWN_TYPE(44),
  UNKNOWN_TYPE(45),

  TYPE("RRSIG", ZONE_RRSIG, ZONE_ANY, FIELDS(rrsig_rdata_fields), parse_rrsig_rdata),
  TYPE("NSEC", ZONE_NSEC, ZONE_ANY, FIELDS(nsec_rdata_fields), parse_nsec_rdata),
  TYPE("DNSKEY", ZONE_DNSKEY, ZONE_ANY, FIELDS(dnskey_rdata_fields), parse_dnskey_rdata),

  UNKNOWN_TYPE(49),

  TYPE("NSEC3", 50, ZONE_ANY, FIELDS(nsec3_rdata_fields), parse_nsec3_rdata),
  TYPE("NSEC3PARAM", 51, ZONE_ANY, FIELDS(nsec3param_rdata_fields), parse_nsec3param_rdata),

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

  TYPE("DLV", 32769, ZONE_ANY, FIELDS(dlv_rdata_fields), 0)
};

#undef UNKNOWN_TYPE
#undef TYPE

#pragma GCC diagnostic pop

#endif // RDATA_H
