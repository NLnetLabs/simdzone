/*
 * parser.h -- recursive descent parser for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef PARSER_H
#define PARSER_H

static inline zone_return_t accept_rr(
  zone_parser_t *parser, zone_field_t *fields, void *user_data)
{
  // FIXME: handle fields a little different (only pass type info)
  parser->rdata_items = fields;
  return parser->options.accept(
    parser,
   &parser->items[0],
   &parser->items[3],
   &parser->items[2],
   &parser->items[1],
    parser->rdata_items,
    parser->rdlength,
    parser->rdata,
    user_data);
}

zone_nonnull((1,2))
extern void zone_check_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_a_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_ip4(parser, type, &type->rdata.fields[0], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_ns_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_name(parser, type, &type->rdata.fields[0], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_cname_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_cname_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_name(parser, type, &type->rdata.fields[0], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_soa_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_name(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_name(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int32(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_ttl(parser, type, &type->rdata.fields[3], token);

  lex_field(parser, type, &type->rdata.fields[4], token);
  parse_ttl(parser, type, &type->rdata.fields[4], token);

  lex_field(parser, type, &type->rdata.fields[5], token);
  parse_ttl(parser, type, &type->rdata.fields[5], token);

  lex_field(parser, type, &type->rdata.fields[6], token);
  parse_ttl(parser, type, &type->rdata.fields[6], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_mx_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int16(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_name(parser, type, &type->rdata.fields[1], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_txt_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_string(parser, type, &type->rdata.fields[0], token);

  while (lex(parser, token))
    parse_string(parser, type, &type->rdata.fields[0], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_aaaa_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_ip6(parser, type, &type->rdata.fields[0], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_srv_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int16(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int16(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int16(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_name(parser, type, &type->rdata.fields[3], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_ds_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int16(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int8(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int8(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_base16(parser, type, &type->rdata.fields[3], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_rrsig_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_type(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int8(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int8(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_ttl(parser, type, &type->rdata.fields[3], token);

  lex_field(parser, type, &type->rdata.fields[4], token);
  parse_time(parser, type, &type->rdata.fields[4], token);

  lex_field(parser, type, &type->rdata.fields[5], token);
  parse_time(parser, type, &type->rdata.fields[5], token);

  lex_field(parser, type, &type->rdata.fields[6], token);
  parse_int16(parser, type, &type->rdata.fields[6], token);

  lex_field(parser, type, &type->rdata.fields[7], token);
  parse_name(parser, type, &type->rdata.fields[7], token);

  lex_field(parser, type, &type->rdata.fields[8], token);
  parse_base64(parser, type, &type->rdata.fields[8], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_nsec_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_name(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_nsec(parser, type, &type->rdata.fields[1], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_dnskey_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int16(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int8(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int8(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_base64(parser, type, &type->rdata.fields[3], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_nsec3_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int8(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int8(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int16(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_salt(parser, type, &type->rdata.fields[3], token);

  lex_field(parser, type, &type->rdata.fields[4], token);
  parse_base32(parser, type, &type->rdata.fields[4], token);

  lex_field(parser, type, &type->rdata.fields[5], token);
  parse_nsec(parser, type, &type->rdata.fields[5], token);

  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_nsec3param_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  parse_int8(parser, type, &type->rdata.fields[0], token);

  lex_field(parser, type, &type->rdata.fields[1], token);
  parse_int8(parser, type, &type->rdata.fields[1], token);

  lex_field(parser, type, &type->rdata.fields[2], token);
  parse_int16(parser, type, &type->rdata.fields[2], token);

  lex_field(parser, type, &type->rdata.fields[3], token);
  parse_salt(parser, type, &type->rdata.fields[3], token);

  lex_delimiter(parser, type, token);
  accept_rr(parser, NULL, user_data);
}

zone_nonnull((1,2))
extern void zone_check_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data);

zone_nonnull((1,2,3))
static void parse_unknown_rdata(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token,
  void *user_data)
{
  (void)user_data;
  parse_base16(parser, type, &type->rdata.fields[0], token);
}

#define SYMBOLS(symbols) \
  { (sizeof(symbols)/sizeof(symbols[0])), symbols }

#define SYMBOL(name, value) \
  { { sizeof(name) - 1, name }, value }

#define FIELDS(fields) \
  { (sizeof(fields)/sizeof(fields[0])), fields }

#define FIELD(name, type, /* qualifiers, symbols */ ...) \
  { { sizeof(name) - 1, name }, type, __VA_ARGS__ }

#define TYPE(name, code, options, fields, check, parse) \
  { { { sizeof(name) - 1, name }, code, options, fields }, check, parse }

#define UNKNOWN_TYPE(code) \
  { { { 0, "" }, code, 0, { 0, NULL } }, 0, 0 }

typedef struct zone_type_descriptor zone_type_descriptor_t;
struct zone_type_descriptor {
  zone_type_info_t info;
  void (*check)(zone_parser_t *, const zone_type_info_t *, void *);
  void (*parse)(zone_parser_t *, const zone_type_info_t *, zone_token_t *, void *);
};

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

  TYPE("A", ZONE_A, ZONE_ANY, FIELDS(a_rdata_fields),
            zone_check_a_rdata, parse_a_rdata),
  TYPE("NS", ZONE_NS, ZONE_ANY, FIELDS(ns_rdata_fields),
             zone_check_ns_rdata, parse_ns_rdata),
  UNKNOWN_TYPE(3),
  UNKNOWN_TYPE(4),
  TYPE("CNAME", ZONE_CNAME, ZONE_ANY, FIELDS(cname_rdata_fields),
                zone_check_cname_rdata, parse_cname_rdata),
  TYPE("SOA", ZONE_SOA, ZONE_ANY, FIELDS(soa_rdata_fields),
              zone_check_soa_rdata, parse_soa_rdata),

  UNKNOWN_TYPE(7),
  UNKNOWN_TYPE(8),
  UNKNOWN_TYPE(9),
  UNKNOWN_TYPE(10),

  TYPE("WKS", ZONE_WKS, ZONE_IN, FIELDS(wks_rdata_fields), 0, 0),

  UNKNOWN_TYPE(12),
  UNKNOWN_TYPE(13),
  UNKNOWN_TYPE(14),

  TYPE("MX", ZONE_MX, ZONE_ANY, FIELDS(mx_rdata_fields),
             zone_check_mx_rdata, parse_mx_rdata),
  TYPE("TXT", ZONE_TXT, ZONE_ANY, FIELDS(txt_rdata_fields),
              zone_check_txt_rdata, parse_txt_rdata),

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

  TYPE("AAAA", ZONE_AAAA, ZONE_IN, FIELDS(aaaa_rdata_fields),
               zone_check_aaaa_rdata, parse_aaaa_rdata),

  UNKNOWN_TYPE(29),
  UNKNOWN_TYPE(30),
  UNKNOWN_TYPE(31),
  UNKNOWN_TYPE(32),

  TYPE("SRV", ZONE_SRV, ZONE_IN, FIELDS(srv_rdata_fields),
              zone_check_srv_rdata, parse_srv_rdata),

  UNKNOWN_TYPE(34),
  UNKNOWN_TYPE(35),
  UNKNOWN_TYPE(36),
  UNKNOWN_TYPE(37),
  UNKNOWN_TYPE(38),
  UNKNOWN_TYPE(39),
  UNKNOWN_TYPE(40),
  UNKNOWN_TYPE(41),
  UNKNOWN_TYPE(42),

  TYPE("DS", ZONE_DS, ZONE_ANY, FIELDS(ds_rdata_fields),
             zone_check_ds_rdata, parse_ds_rdata),

  UNKNOWN_TYPE(44),
  UNKNOWN_TYPE(45),

  TYPE("RRSIG", ZONE_RRSIG, ZONE_ANY, FIELDS(rrsig_rdata_fields),
                zone_check_rrsig_rdata, parse_rrsig_rdata),
  TYPE("NSEC", ZONE_NSEC, ZONE_ANY, FIELDS(nsec_rdata_fields),
               zone_check_nsec_rdata, parse_nsec_rdata),
  TYPE("DNSKEY", ZONE_DNSKEY, ZONE_ANY, FIELDS(dnskey_rdata_fields),
                 zone_check_dnskey_rdata, parse_dnskey_rdata),

  UNKNOWN_TYPE(49),

  TYPE("NSEC3", ZONE_NSEC3, ZONE_ANY, FIELDS(nsec3_rdata_fields),
                zone_check_nsec3_rdata, parse_nsec3_rdata),
  TYPE("NSEC3PARAM", ZONE_NSEC3PARAM, ZONE_ANY, FIELDS(nsec3param_rdata_fields),
                     zone_check_nsec3param_rdata, parse_nsec3param_rdata),

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

  TYPE("DLV", 32769, ZONE_ANY, FIELDS(dlv_rdata_fields), 0, 0)
};

#undef UNKNOWN_TYPE
#undef TYPE

#pragma GCC diagnostic pop
zone_always_inline()
static inline void parse_rr(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_type_info_t unknown =
    { { 6, "record" }, 0, 0, { 0, NULL } };
  static const zone_field_info_t owner =
    { { 5, "owner" }, ZONE_OWNER|ZONE_NAME, 0, { 0 } };
  static const zone_field_info_t ttl =
    { { 3, "ttl" }, ZONE_TTL|ZONE_INT32, 0, { 0 } };
  static const zone_field_info_t type =
    { { 4, "type" }, ZONE_TYPE|ZONE_INT16, 0, { 0 } };

  const zone_type_descriptor_t *descriptor;
  uint16_t code;
  uint32_t epoch;

  if (parser->file->start_of_line) {
    parse_owner(parser, &unknown, &owner, token);
    lex_field(parser, &unknown, &type, token);
  }

  if ((uint8_t)token->data[0] - '0' <= 9) {
    scan_ttl(parser, &unknown, &ttl, token, &epoch);
    goto class_or_type;
  }
  
  switch (scan_type_or_class(parser, &unknown, &type, token, &code)) {
    case ZONE_CLASS:
      parser->file->last_class = code;
      goto ttl_or_type;
    default:
      parser->file->last_type = code;
      goto rdata;
  }

ttl_or_type:
  lex_field(parser, &unknown, &type, token);
  if ((uint8_t)token->data[0] - '0' <= 9) {
    scan_ttl(parser, &unknown, &ttl, token, &epoch);
    goto type;
  } else {
    scan_type(parser, &unknown, &type, token, &code);
    parser->file->last_type = code;
    goto rdata;
  }

class_or_type:
  lex_field(parser, &unknown, &type, token);
  switch (scan_type_or_class(parser, &unknown, &type, token, &code)) {
    case ZONE_CLASS:
      parser->file->last_class = code;
      goto type;
    default:
      parser->file->last_type = code;
      goto rdata;
  }

type:
  lex_field(parser, &unknown, &type, token);
  scan_type(parser, &unknown, &type, token, &code);
  parser->file->last_type = code;

rdata:
  // FIXME: check if type is directly indexable
  descriptor = &types[code];

  // check if rdata starts with "\#" and, if so, parse generic rdata
  lex_field(parser, &descriptor->info, &descriptor->info.rdata.fields[0], token);

  parser->rdlength = 0;

  if (token->length == 2 && strncmp(token->data, "\\#", 2) == 0) {
    parse_unknown_rdata(parser, &descriptor->info, token, user_data);
    descriptor->check(parser, &descriptor->info, user_data);
  } else if (descriptor->parse) {
    descriptor->parse(parser, &descriptor->info, token, user_data);
  } else {
    SEMANTIC_ERROR(parser, "Unknown record type in record");
  }
}

// RFC1035 section 5.1
// $INCLUDE <file-name> [<domain-name>] [<comment>]
static inline void parse_dollar_include(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  (void)parser;
  (void)token;
  (void)user_data;
  NOT_IMPLEMENTED(parser, "$INCLUDE directive not implemented yet");
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
zone_nonnull((1,2))
static inline void parse_dollar_origin(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t field =
    { { 4, "name" }, ZONE_DOLLAR_ORIGIN|ZONE_NAME, 0, { 0 } };
  static const zone_type_info_t type =
    { { 7, "$ORIGIN" }, 0, 0, { 1, &field } };

  (void)user_data;

  if (!lex(parser, token))
    SYNTAX_ERROR(parser, "Missing name in $ORIGIN");
  
  scan_name(parser, &type, &field, token,
            parser->file->origin.octets, &parser->file->origin.length);
  if (parser->file->origin.octets[parser->file->origin.length - 1] != 0)
    SYNTAX_ERROR(parser, "Invalid name in $ORIGIN, not fully qualified");
  if (lex(parser, token))
    SYNTAX_ERROR(parser, "$ORIGIN takes just a single argument");
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
zone_nonnull((1,2))
static inline void parse_dollar_ttl(
  zone_parser_t *parser, zone_token_t *token, void *user_data)
{
  static const zone_field_info_t field =
    { { 3, "ttl" }, ZONE_DOLLAR_TTL|ZONE_INT32, 0, { 0 } };
  static const zone_type_info_t type =
    { { 4, "$TTL" }, 0, 0, { 1, &field } };

  (void)user_data;

  if (!lex(parser, token))
    SYNTAX_ERROR(parser, "$TTL directive takes a ttl argument");

  scan_ttl(parser, &type, &field, token, &parser->file->default_ttl);

  if (lex(parser, token))
    SYNTAX_ERROR(parser, "$TTL directive takes only a ttl argument");

  parser->file->last_ttl = parser->file->default_ttl;
}

static inline zone_return_t parse(zone_parser_t *parser, void *user_data)
{
  static const zone_string_t ttl = { 4, "$TTL" };
  static const zone_string_t origin = { 7, "$ORIGIN" };
  static const zone_string_t include = { 8, "$INCLUDE" };

  zone_token_t token;

  for (;;) {
    switch (lex(parser, &token)) {
      case ZONE_CONTIGUOUS: // contiguous
        if (!parser->file->start_of_line || token.data[0] != '$')
          parse_rr(parser, &token, user_data);
        else if (zone_compare(&token, &ttl) == 0)
          parse_dollar_ttl(parser, &token, user_data);
        else if (zone_compare(&token, &origin) == 0)
          parse_dollar_origin(parser, &token, user_data);
        else if (zone_compare(&token, &include) == 0)
          parse_dollar_include(parser, &token, user_data);
        else
          parse_rr(parser, &token, user_data);
        break;
      case ZONE_QUOTED: // quoted (never a directive)
        parse_rr(parser, &token, user_data);
        break;
      case ZONE_DELIMITER:
        if (!token.data[0])
          return 0;
        break;
      default:
        break;
    }
  }

  return 0;
}

#endif // PARSER_H
