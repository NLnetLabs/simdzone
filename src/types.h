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
    check_generic_rr, parse_unknown_rdata }

// class descriptor exists to parse classes and types in a uniform way
typedef struct class_descriptor class_descriptor_t;
struct class_descriptor {
  zone_symbol_t name;
};

typedef struct type_descriptor type_descriptor_t;
struct type_descriptor {
  zone_type_info_t info;
  int32_t (*check)(zone_parser_t *, const zone_type_info_t *);
  int32_t (*parse)(zone_parser_t *, const zone_type_info_t *, token_t *);
};

#if _WIN32
typedef SSIZE_T ssize_t;
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#else
#include <strings.h>
#endif

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_bytes(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length,
  const size_t size)
{
  (void)data;
  if (length < size)
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), TNAME(type));
  return (ssize_t)size;
}

#define check_int8(...) check_bytes(__VA_ARGS__, sizeof(uint8_t))

#define check_int16(...) check_bytes(__VA_ARGS__, sizeof(uint16_t))

#define check_int32(...) check_bytes(__VA_ARGS__, sizeof(uint32_t))

#define check_ip4(...) check_bytes(__VA_ARGS__, 4)

#define check_ip6(...) check_bytes(__VA_ARGS__, 16)

#define check_ilnp64(...) check_bytes(__VA_ARGS__, sizeof(uint64_t))

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  uint32_t number;

  if (length < sizeof(number))
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), TNAME(type));

  memcpy(&number, data, sizeof(number));
  number = ntohl(number);

  if (number > INT32_MAX)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return 4;
}

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  uint16_t number;

  if (length < sizeof(number))
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), TNAME(type));

  memcpy(&number, data, sizeof(number));

  if (!number)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return 2;
}

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  size_t label = 0, count = 0;
  while (count < length) {
    label = data[count];
    count += 1 + label;
    if (!label)
      break;
  }

  if (!count || count > length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return (ssize_t)count;
}

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  size_t count;

  if (!length || (count = 1 + (size_t)data[0]) > length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return (ssize_t)count;
}

zone_nonnull((1,2,3,4))
static zone_really_inline ssize_t check_nsec(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  size_t count = 0;
  size_t last_window = 0;

  while ((count + 2) < length) {
    const size_t window = (size_t)data[0];
    const size_t blocks = 1 + (size_t)data[1];
    if (window < last_window || !window != !last_window)
      SYNTAX_ERROR(parser, "Invalid %s in %s, windows are out-of-order",
                   NAME(field), TNAME(type));
    if (blocks > 32)
      SYNTAX_ERROR(parser, "Invalid %s in %s, blocks are out-of-bounds",
                   NAME(field), TNAME(type));
    count += 2 + blocks;
    last_window = window;
  }

  if (count != length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return (ssize_t)count;
}

zone_nonnull((1))
static zone_really_inline int32_t check(size_t *length, ssize_t count)
{
  if (count < 0)
    return (int32_t)count;
  *length += (size_t)count;
  return 0;
}

zone_nonnull_all
static zone_really_inline int32_t accept_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t result;

  assert(parser->owner->length <= UINT8_MAX);
  assert(parser->rdata->length <= UINT16_MAX);
  result = parser->options.accept.add(
    parser,
    type,
    &(zone_name_t){ (uint8_t)parser->owner->length, parser->owner->octets },
    parser->file->last_type,
    parser->file->last_class,
    parser->file->last_ttl,
    (uint16_t)parser->rdata->length,
    parser->rdata->octets,
    parser->user_data);

  assert((size_t)result < parser->buffers.size);
  if (result < 0)
    return result;
  parser->rdata = &parser->buffers.rdata.blocks[result];
  return 0;
}

zone_nonnull_all
static int32_t check_a_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_ip4(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_ns_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_name(parser, type, &f[0], o, n))) < 0)
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_soa_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_name(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_name(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int32(parser, type, &f[2], o+c, n-c))) ||
      (r = check(&c, check_ttl(parser, type, &f[3], o+c, n-c))) ||
      (r = check(&c, check_ttl(parser, type, &f[4], o+c, n-c))) ||
      (r = check(&c, check_ttl(parser, type, &f[5], o+c, n-c))) ||
      (r = check(&c, check_ttl(parser, type, &f[6], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_wks_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_ip4(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[0], o+c, n-c))))
    return r;

  // any bit may, or may not, be set. confirm the bitmap does not exceed the
  // maximum number of ports
  if (n > 8192 + 5)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_wks_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t code;
  if ((code = parse_ip4(parser, type, &type->rdata.fields[0], token) < 0))
    return code;

  lex(parser, token);
  int32_t protocol = scan_protocol(token->data, token->length);
  if (protocol == -1)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&type->rdata.fields[1]), TNAME(type));

  parser->rdata->octets[parser->rdata->length++] = (uint8_t)protocol;
  uint8_t *bitmap = parser->rdata->octets + parser->rdata->length;
  int32_t highest_port = -1;

  lex(parser, token);
  while (token->code == CONTIGUOUS) {
    int32_t port = scan_service(token->data, token->length, protocol);
    if (port == -1)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&type->rdata.fields[2]), TNAME(type));

    if (port > highest_port) {
      // ensure newly used octets are zeroed out before use
      size_t offset = highest_port < 0 ? 0 : (size_t)highest_port / 8 + 1;
      size_t length = (size_t)port / 8 + 1;
      memset(bitmap + offset, 0, length - offset);
      highest_port = port;
    }

    // bits are counted from left to right, so bit 0 is the left most bit
    bitmap[port / 8] |= (1 << (7 - port % 8));
    lex(parser, token);
  }

  parser->rdata->length += (size_t)highest_port / 8 + 1;

  if ((code = have_delimiter(parser, type, token)) < 0)
    return code;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_hinfo_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_string(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_string(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_minfo_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_name(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_name(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_mx_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_name(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_txt_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_string(parser, type, &f[0], o, n))))
    return r;

  while (c < n)
    if ((r = check(&c, check_string(parser, type, &f[0], o+c, n-c))))
      return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_x25_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_string(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_isdn_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_string(parser, type, &f[0], o, n))))
    return r;
  // subaddress is optional
  if (c < n && (r = check(&c, check_string(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_rt_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_name(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nsap_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  if (parser->rdata->length == 0)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_nsap_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_nsap(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nsap_ptr_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  {
    int32_t r;
    size_t c = 0;
    const size_t n = parser->rdata->length;
    const uint8_t *o = parser->rdata->octets;
    const zone_field_info_t *f = type->rdata.fields;

    if ((r = check(&c, check_name(parser, type, &f[0], o, n))))
      return r;

    if (c != parser->rdata->length)
      SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  }

  {
    // RFC1706 section 6
    // A domain name is generated from an NSAP by reversing the hex nibbles of
    // the NSAP, treating each nibble as a separate subdomain, and appending
    // the top-level subdomain name "NSAP.INT" to it. For example, the domain
    // name used in the reverse lookup for the NSAP
    //
    //    47.0005.80.005a00.0000.0001.e133.ffffff000162.00
    //
    // would appear as
    //
    //    0.0.2.6.1.0.0.0.f.f.f.f.f.f.3.3.1.e.1.0.0.0.0.0.0.0.0.0.a.5.0.0.
    //                        0.8.5.0.0.0.7.4.NSAP.INT.
    size_t i = 0;
    const size_t n = parser->file->owner.length;
    const uint8_t *o = parser->file->owner.octets;
    for (; i < n; i += 2)
      if (o[i] != 1 || (b16rmap[o[i+1]] & 0x80))
        break;

    const uint8_t nsap_int[] = { 4, 'n', 's', 'a', 'p', 3, 'i', 'n', 't', 0 };
    if (strncasecmp((const char *)o + i, (const char *)nsap_int, 9) != 0 || !i || i + 10 != n)
      SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  }

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_nsap_ptr_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_name(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  // RFC1706 section 6 states each nibble is treated as a separate subdomain
  return check_nsap_ptr_rr(parser, type);
}

zone_nonnull_all
static int32_t check_key_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
#if 0
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  //
  // FIXME: implement (RFC2065)
  //
  // FIXME: verify the flag, algorithm and protocol combination is valid
  // FIXME: verify the key is valid for type(3)+algorithm(1)
  //
  // The combination is of course subject to secondary checks!
  //
#endif
  (void)type;
  return accept_rr(parser, type);
}

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

  return check_key_rr(parser, type);
}

zone_nonnull_all
static int32_t check_px_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_name(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_name(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s record", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_px_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_name(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_gpos_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_string(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_string(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_string(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s record", TNAME(type));
  return accept_rr(parser, type);
}

static int32_t parse_gpos_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_latitude(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_longitude(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_altitude(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_aaaa_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_ip6(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s record", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_loc_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  if (parser->rdata->length != 16)
    SYNTAX_ERROR(parser, "Invalid %s record", TNAME(type));
  return accept_rr(parser, type);

  // FIXME: check validity of latitude, longitude and latitude?
}

zone_nonnull_all
static int32_t parse_loc_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t result;
  uint32_t degrees, minutes, seconds;
  uint32_t latitude, longitude, altitude;
  const zone_field_info_t *fields = type->rdata.fields;
  static const uint32_t defaults = 0x13161200;

  // RFC1876 section 3:
  // If omitted, minutes and seconds default to zero, size defaults to 1m,
  // horizontal precision defaults to 10000m, and vertical precision defaults
  // to 10m.
  memcpy(parser->rdata->octets, &defaults, sizeof(defaults));
  parser->rdata->length = 16;

  // latitude
  if ((result = have_contiguous(parser, type, &fields[4], token)) < 0)
    return result;
  if (scan_degrees(token->data, token->length, &degrees) == -1)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[4]), TNAME(type));
  lex(parser, token);
  if (scan_minutes(token->data, token->length, &minutes) == -1)
    goto north_south; // minutes default to zero
  degrees += minutes;
  lex(parser, token);
  if (scan_seconds(token->data, token->length, &seconds) == -1)
    goto north_south; // seconds default to zero
  degrees += seconds;

  lex(parser, token);
  if ((result = have_contiguous(parser, type, &fields[4], token)) < 0)
    return result;
north_south:
  if (token->data[0] == 'N')
    latitude = htonl((1u<<31) + degrees);
  else if (token->data[1] == 'S')
    latitude = htonl((1u<<31) - degrees);
  else
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[4]), TNAME(type));

  memcpy(&parser->rdata->octets[4], &latitude, sizeof(latitude));

  // longitude
  lex(parser, token);
  if ((result = have_contiguous(parser, type, &fields[5], token)) < 0)
    return result;
  if (scan_degrees(token->data, token->length, &degrees) == -1)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[5]), TNAME(type));
  lex(parser, token);
  if (scan_minutes(token->data, token->length, &minutes) == -1)
    goto east_west; // minutes default to zero
  degrees += minutes;
  lex(parser, token);
  if (scan_seconds(token->data, token->length, &seconds) == -1)
    goto east_west; // seconds default to zero
  degrees += seconds;

  lex(parser, token);
  if ((result = have_contiguous(parser, type, &fields[5], token)) < 0)
    return result;
east_west:
  if (token->data[0] == 'E')
    longitude = htonl((1u<<31) + degrees);
  else if (token->data[0] == 'W')
    longitude = htonl((1u<<31) - degrees);
  else
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[5]), TNAME(type));

  memcpy(&parser->rdata->octets[8], &longitude, sizeof(longitude));

  // altitude
  lex(parser, token);
  if ((result = have_contiguous(parser, type, &fields[6], token)) < 0)
    return result;
  if (scan_altitude(token->data, token->length, &altitude) == -1)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[6]), TNAME(type));

  altitude = htonl(altitude);
  memcpy(&parser->rdata->octets[12], &altitude, sizeof(altitude));

  // size
  lex(parser, token);
  if (token->code != CONTIGUOUS)
    goto skip_optional;
  if (scan_precision(token->data, token->length, &parser->rdata->octets[1]))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), TNAME(type));

  // horizontal precision
  lex(parser, token);
  if (token->code != CONTIGUOUS)
    goto skip_optional;
  if (scan_precision(token->data, token->length, &parser->rdata->octets[2]))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[2]), TNAME(type));

  // vertical precision
  lex(parser, token);
  if (token->code != CONTIGUOUS)
    goto skip_optional;
  if (scan_precision(token->data, token->length, &parser->rdata->octets[3]))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[3]), TNAME(type));

  lex(parser, token);
skip_optional:
  if ((result = have_delimiter(parser, type, token)) < 0)
    return result;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_srv_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int16(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = check(&c, check_name(parser, type, &f[3], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_naptr_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  // FIXME: implement actual checks
  (void)type;
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_cert_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  // FIXME: implement actual checks
  (void)type;

  if (parser->rdata->length < 6)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_cert_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_symbol16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int16(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base64(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_ds_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  // FIXME: can implement checking for digest length based on algorithm here.
  //        e.g. SHA-1 digest is 20 bytes, see RFC3658 section 2.4

  if (c >= n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_int16(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base16(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_sshfp_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o, n))))
    return r;

  // https://www.iana.org/assignments/dns-sshfp-rr-parameters

  if (c >= n)
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME((&f[0])), TNAME(type));
  else if (o[1] == 1 && (n - c) != 20)
    SEMANTIC_ERROR(parser, "Wrong fingerprint size for type %s in %s",
                           "SHA1", TNAME(type));
  else if (o[1] == 2 && (n - c) != 32)
    SEMANTIC_ERROR(parser, "Wrong fingerprint size for type %s in %s",
                           "SHA256", TNAME(type));

  return accept_rr(parser, type);
}

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

  return check_sshfp_rr(parser, type);
}

zone_nonnull_all
static int32_t check_ipseckey_rr(
  zone_parser_t *parser, const zone_type_info_t *type);

zone_nonnull_all
static int32_t parse_ipseckey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token);

diagnostic_push()
gcc_diagnostic_ignored(missing-field-initializers)
clang_diagnostic_ignored(missing-field-initializers)

static const zone_field_info_t ipseckey_ipv4_rdata_fields[] = {
  FIELD("precedence", ZONE_INT8, 0),
  FIELD("gateway type", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("gateway", ZONE_IP4, 0),
  FIELD("public key", ZONE_BLOB, ZONE_BASE64)
};

static const type_descriptor_t ipseckey_ipv4[] = {
  TYPE("IPSECKEY", ZONE_IPSECKEY, ZONE_IN, FIELDS(ipseckey_ipv4_rdata_fields),
                   check_ipseckey_rr, parse_ipseckey_rdata),
};

static const zone_field_info_t ipseckey_ipv6_rdata_fields[] = {
  FIELD("precedence", ZONE_INT8, 0),
  FIELD("gateway type", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("gateway", ZONE_IP6, 0),
  FIELD("public key", ZONE_BLOB, ZONE_BASE64)
};

static const type_descriptor_t ipseckey_ipv6[] = {
  TYPE("IPSECKEY", ZONE_IPSECKEY, ZONE_IN, FIELDS(ipseckey_ipv6_rdata_fields),
                   check_ipseckey_rr, parse_ipseckey_rdata),
};


diagnostic_pop()

zone_nonnull_all
static int32_t check_ipseckey_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_type_info_t *t = type;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  switch (parser->rdata->octets[1]) {
    case 1: /* IPv4 address */
      t = (const zone_type_info_t *)ipseckey_ipv4;
      f = ipseckey_ipv4_rdata_fields;
      if ((r = check(&c, check_ip4(parser, t, &f[3], o+c, n-c))) < 0)
        return r;
      break;
    case 2: /* IPv6 address */
      t = (const zone_type_info_t *)ipseckey_ipv6;
      f = ipseckey_ipv6_rdata_fields;
      if ((r = check(&c, check_ip6(parser, t, &f[3], o+c, n-c))) < 0)
        return r;
      break;
    case 0: /* no gateway */
    case 3: /* domain name */
      if ((r = check(&c, check_name(parser, t, &f[3], o+c, n-c))) < 0)
        return r;
      break;
    default:
      SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  }

  switch (parser->rdata->octets[2]) {
    case 0:
      if (c < n)
        SYNTAX_ERROR(parser, "Trailing data in %s", TNAME(t));
      break;
    default:
      if (c >= n)
        SYNTAX_ERROR(parser, "Missing %s in %s", NAME(&f[4]), TNAME(t));
      break;
  }

  return accept_rr(parser, t);
}

zone_nonnull_all
static int32_t parse_ipseckey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;
  const zone_type_info_t *t;

  if ((r = parse_int8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[1], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_int8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);

  switch (parser->rdata->octets[1]) {
    case 1: /* IPv4 address */
      t = (const zone_type_info_t *)ipseckey_ipv4;
      if ((r = parse_ip4(parser, t, &t->rdata.fields[3], token)) < 0)
        return r;
      break;
    case 2: /* IPv6 address */
      t = (const zone_type_info_t *)ipseckey_ipv6;
      if ((r = parse_ip6(parser, t, &t->rdata.fields[3], token)) < 0)
        return r;
      break;
    case 0: /* no gateway */
    case 3: /* domain name */
      t = type;
      if ((r = parse_name(parser, t, &t->rdata.fields[3], token)) < 0)
        return r;
      break;
    default:
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&type->rdata.fields[3]), TNAME(type));
  }

  lex(parser, token);
  switch (parser->rdata->octets[2]) {
    case 0:
      if ((r = have_delimiter(parser, t, token)) < 0)
        return r;
      break;
    default:
      if ((r = parse_base64(parser, t, &t->rdata.fields[4], token)) < 0)
        return r;
      break;
  }

  return accept_rr(parser, (const zone_type_info_t *)t);
}

zone_nonnull_all
static int32_t check_rrsig_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_type(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int8(parser, type, &f[2], o+c, n-c))) ||
      (r = check(&c, check_ttl(parser, type, &f[3], o+c, n-c))) ||
      (r = check(&c, check_int32(parser, type, &f[4], o+c, n-c))) ||
      (r = check(&c, check_int32(parser, type, &f[5], o+c, n-c))) ||
      (r = check(&c, check_int16(parser, type, &f[6], o+c, n-c))) ||
      (r = check(&c, check_name(parser, type, &f[7], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_type(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[1], token)) < 0)
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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nsec_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_name(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_nsec(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_dnskey_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c >= n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[2], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_base64(parser, type, &type->rdata.fields[3], token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_dhcid_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  // RFC4701 section 3.1:
  // 2-octet identifier type, 1-octet digest type, followed by one or more
  // octets representing the actual identifier
  if (parser->rdata->length < 4)
    SEMANTIC_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_dhcid_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_base64(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;

  return check_dhcid_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nsec3_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = check(&c, check_string(parser, type, &f[3], o+c, n-c))) ||
      (r = check(&c, check_string(parser, type, &f[4], o+c, n-c))) ||
      (r = check(&c, check_nsec(parser, type, &f[5], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_symbol8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[1], token)) < 0)
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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nsec3param_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = check(&c, check_string(parser, type, &f[3], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_symbol8(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;
  lex(parser, token);
  if ((r = parse_symbol8(parser, type, &type->rdata.fields[1], token)) < 0)
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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_tlsa_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = check(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c >= n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_openpgpkey_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  // FIXME: as the RDATA contains a digest, it is likely we can make this
  //        check stricter, at least, for known algorithms
  if (parser->rdata->length < 4)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_openpgpkey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, token_t *token)
{
  int32_t r;

  if ((r = parse_base64(parser, type, &type->rdata.fields[0], token)) < 0)
    return r;

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_zonemd_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  // FIXME: RDATA contains digests, do extra checks?
  if (parser->rdata->length < 6)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_nid_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_ilnp64(parser, type, &f[1], o+c, n-c))))
    return r;
  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t parse_nid_rdata(
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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_l32_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_ip4(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_l64_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_ilnp64(parser, type, &f[1], o+c, n-c))))
    return r;
  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_eui48_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  if (parser->rdata->length != 6)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_eui64_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  if (parser->rdata->length != 8)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_uri_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int16(parser, type, &f[1], o+c, n-c))))
    return r;
  if (c >= n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_caa_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = check(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = check(&c, check_int8(parser, type, &f[1], o+c, n-c))))
    return r;
  if (c >= n)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return accept_rr(parser, type);
}

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

  return accept_rr(parser, type);
}

zone_nonnull_all
static int32_t check_generic_rr(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  (void)type;

  return accept_rr(parser, type);
}

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

diagnostic_push()
gcc_diagnostic_ignored(missing-field-initializers)
clang_diagnostic_ignored(missing-field-initializers)

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
  FIELD("bitmap", ZONE_SERVICE_BITMAP, 0)
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

static const zone_field_info_t nsap_rdata_fields[] = {
  FIELD("address", ZONE_BLOB, ZONE_NSAP)
};

static const zone_field_info_t nsap_ptr_rdata_fields[] = {
  FIELD("hostname", ZONE_NAME, 0)
};

static const zone_field_info_t key_rdata_fields[] = {
  FIELD("flags", ZONE_INT16, 0),
  FIELD("protocol", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("publickey", ZONE_BLOB, ZONE_BASE64)
};

static const zone_field_info_t px_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("map822", ZONE_NAME, 0),
  FIELD("mapx400", ZONE_NAME, 0)
};

static const zone_field_info_t gpos_rdata_fields[] = {
  FIELD("latitude", ZONE_STRING, 0),
  FIELD("longitude", ZONE_STRING, 0),
  FIELD("altitude", ZONE_STRING, 0)
};

static const zone_field_info_t aaaa_rdata_fields[] = {
  FIELD("address", ZONE_IP6, 0)
};

static const zone_field_info_t loc_rdata_fields[] = {
  FIELD("version", ZONE_INT8, 0),
  FIELD("size", ZONE_INT8, 0),
  FIELD("horizontal precision", ZONE_INT8, 0),
  FIELD("vertical precision", ZONE_INT8, 0),
  FIELD("latitude", ZONE_INT32, 0),
  FIELD("longitude", ZONE_INT32, 0),
  FIELD("altitude", ZONE_INT32, 0)
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

// https://www.iana.org/assignments/cert-rr-types/cert-rr-types.xhtml
static const zone_symbol_t cert_type_symbols[] = {
  SYMBOL("ACPKIX", 7),
  SYMBOL("IACPKIX", 8),
  SYMBOL("IPGP", 6),
  SYMBOL("IPKIX", 4),
  SYMBOL("ISPKI", 5),
  SYMBOL("OID", 254),
  SYMBOL("PGP", 3),
  SYMBOL("PKIX", 1),
  SYMBOL("SPKI", 2),
  SYMBOL("URI", 253),
};

// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
static const zone_symbol_t dnssec_algorithm_symbols[] = {
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

static const zone_field_info_t cert_rdata_fields[] = {
  FIELD("type", ZONE_INT16, 0, SYMBOLS(cert_type_symbols)),
  FIELD("key tag", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("certificate", ZONE_BLOB, ZONE_BASE64)
};

static const zone_field_info_t dname_rdata_fields[] = {
  FIELD("source", ZONE_NAME, 0)
};

static const zone_symbol_t ds_digest_type_symbols[] = {
  SYMBOL("GOST", 3),
  SYMBOL("SHA-1", 1),
  SYMBOL("SHA-256", 2),
  SYMBOL("SHA-384", 4)
};

static const zone_field_info_t ds_rdata_fields[] = {
  FIELD("keytag", ZONE_INT16, 0),
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
  FIELD("digtype", ZONE_INT8, 0, SYMBOLS(ds_digest_type_symbols)),
  FIELD("digest", ZONE_BLOB, ZONE_BASE16)
};

static const zone_field_info_t sshfp_rdata_fields[] = {
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("ftype", ZONE_INT8, 0),
  FIELD("fingerprint", ZONE_BLOB, ZONE_BASE16)
};

// FIXME: IPSECKEY is a little different because the rdata depends on the algorithm!
static const zone_field_info_t ipseckey_rdata_fields[] = {
  FIELD("precedence", ZONE_INT8, 0),
  FIELD("gateway type", ZONE_INT8, 0),
  FIELD("algorithm", ZONE_INT8, 0),
  FIELD("gateway", ZONE_NAME, 0),
  FIELD("public key", ZONE_BLOB, ZONE_BASE64)
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
  FIELD("algorithm", ZONE_INT8, 0, SYMBOLS(dnssec_algorithm_symbols)),
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

static const zone_field_info_t nid_rdata_fields[] = {
  FIELD("preference", ZONE_INT16, 0),
  FIELD("nodeid", ZONE_ILNP64, 0)
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
            check_a_rr, parse_a_rdata),
  TYPE("NS", ZONE_NS, ZONE_ANY, FIELDS(ns_rdata_fields),
             check_ns_rr, parse_ns_rdata),
  TYPE("MD", ZONE_MD, ZONE_ANY | ZONE_OBSOLETE, FIELDS(md_rdata_fields),
             check_ns_rr, parse_ns_rdata),
  TYPE("MF", ZONE_MF, ZONE_ANY | ZONE_OBSOLETE, FIELDS(mf_rdata_fields),
             check_ns_rr, parse_ns_rdata),
  TYPE("CNAME", ZONE_CNAME, ZONE_ANY, FIELDS(cname_rdata_fields),
                check_ns_rr, parse_ns_rdata),
  TYPE("SOA", ZONE_SOA, ZONE_ANY, FIELDS(soa_rdata_fields),
              check_soa_rr, parse_soa_rdata),
  TYPE("MB", ZONE_MB, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mb_rdata_fields),
             check_ns_rr, parse_ns_rdata),
  TYPE("MG", ZONE_MG, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mg_rdata_fields),
             check_ns_rr, parse_ns_rdata),
  TYPE("MR", ZONE_MR, ZONE_ANY | ZONE_EXPERIMENTAL, FIELDS(mr_rdata_fields),
             check_ns_rr, parse_ns_rdata),

  UNKNOWN_TYPE(10),

  TYPE("WKS", ZONE_WKS, ZONE_IN, FIELDS(wks_rdata_fields),
              check_wks_rr, parse_wks_rdata),
  TYPE("PTR", ZONE_PTR, ZONE_ANY, FIELDS(ptr_rdata_fields),
              check_ns_rr, parse_ns_rdata),
  TYPE("HINFO", ZONE_HINFO, ZONE_ANY, FIELDS(hinfo_rdata_fields),
                check_hinfo_rr, parse_hinfo_rdata),
  TYPE("MINFO", ZONE_MINFO, ZONE_ANY, FIELDS(minfo_rdata_fields),
                check_minfo_rr, parse_minfo_rdata),
  TYPE("MX", ZONE_MX, ZONE_ANY, FIELDS(mx_rdata_fields),
             check_mx_rr, parse_mx_rdata),
  TYPE("TXT", ZONE_TXT, ZONE_ANY, FIELDS(txt_rdata_fields),
              check_txt_rr, parse_txt_rdata),
  TYPE("RP", ZONE_RP, ZONE_ANY, FIELDS(rp_rdata_fields),
             check_minfo_rr, parse_minfo_rdata),
  TYPE("AFSDB", ZONE_AFSDB, ZONE_ANY, FIELDS(afsdb_rdata_fields),
                check_mx_rr, parse_mx_rdata),
  TYPE("X25", ZONE_X25, ZONE_ANY, FIELDS(x25_rdata_fields),
              check_x25_rr, parse_x25_rdata),
  TYPE("ISDN", ZONE_ISDN, ZONE_ANY, FIELDS(isdn_rdata_fields),
               check_isdn_rr, parse_isdn_rdata),
  TYPE("RT", ZONE_RT, ZONE_ANY, FIELDS(rt_rdata_fields),
             check_rt_rr, parse_rt_rdata),
  TYPE("NSAP", ZONE_NSAP, ZONE_IN, FIELDS(nsap_rdata_fields),
               check_nsap_rr, parse_nsap_rdata),
  TYPE("NSAP-PTR", ZONE_NSAP_PTR, ZONE_IN, FIELDS(nsap_ptr_rdata_fields),
                   check_nsap_ptr_rr, parse_nsap_ptr_rdata),

  UNKNOWN_TYPE(24),

  TYPE("KEY", ZONE_KEY, ZONE_ANY, FIELDS(key_rdata_fields),
              check_key_rr, parse_key_rdata),
  TYPE("PX", ZONE_PX, ZONE_IN, FIELDS(px_rdata_fields),
             check_px_rr, parse_px_rdata),
  TYPE("GPOS", ZONE_GPOS, ZONE_ANY, FIELDS(gpos_rdata_fields),
               check_gpos_rr, parse_gpos_rdata),
  TYPE("AAAA", ZONE_AAAA, ZONE_IN, FIELDS(aaaa_rdata_fields),
               check_aaaa_rr, parse_aaaa_rdata),
  TYPE("LOC", ZONE_LOC, ZONE_ANY, FIELDS(loc_rdata_fields),
              check_loc_rr, parse_loc_rdata),

  UNKNOWN_TYPE(30),
  UNKNOWN_TYPE(31),
  UNKNOWN_TYPE(32),

  TYPE("SRV", ZONE_SRV, ZONE_IN, FIELDS(srv_rdata_fields),
              check_srv_rr, parse_srv_rdata),

  UNKNOWN_TYPE(34),

  TYPE("NAPTR", ZONE_NAPTR, ZONE_IN, FIELDS(naptr_rdata_fields),
                check_naptr_rr, parse_naptr_rdata),
  TYPE("KX", ZONE_KX, ZONE_IN, FIELDS(kx_rdata_fields),
             check_mx_rr, parse_mx_rdata),
  TYPE("CERT", ZONE_CERT, ZONE_ANY, FIELDS(cert_rdata_fields),
               check_cert_rr, parse_cert_rdata),

  UNKNOWN_TYPE(38),

  TYPE("DNAME", ZONE_DNAME, ZONE_ANY, FIELDS(dname_rdata_fields),
                check_ns_rr, parse_ns_rdata),

  UNKNOWN_TYPE(40),
  UNKNOWN_TYPE(41),
  UNKNOWN_TYPE(42),

  TYPE("DS", ZONE_DS, ZONE_ANY, FIELDS(ds_rdata_fields),
             check_ds_rr, parse_ds_rdata),
  TYPE("SSHFP", ZONE_SSHFP, ZONE_ANY, FIELDS(sshfp_rdata_fields),
                check_sshfp_rr, parse_sshfp_rdata),
  TYPE("IPSECKEY", ZONE_IPSECKEY, ZONE_IN, FIELDS(ipseckey_rdata_fields),
                   check_ipseckey_rr, parse_ipseckey_rdata),
  TYPE("RRSIG", ZONE_RRSIG, ZONE_ANY, FIELDS(rrsig_rdata_fields),
                check_rrsig_rr, parse_rrsig_rdata),
  TYPE("NSEC", ZONE_NSEC, ZONE_ANY, FIELDS(nsec_rdata_fields),
               check_nsec_rr, parse_nsec_rdata),
  TYPE("DNSKEY", ZONE_DNSKEY, ZONE_ANY, FIELDS(dnskey_rdata_fields),
                 check_dnskey_rr, parse_dnskey_rdata),
  TYPE("DHCID", ZONE_DHCID, ZONE_IN, FIELDS(dhcid_rdata_fields),
                check_dhcid_rr, parse_dhcid_rdata),
  TYPE("NSEC3", ZONE_NSEC3, ZONE_ANY, FIELDS(nsec3_rdata_fields),
                check_nsec3_rr, parse_nsec3_rdata),
  TYPE("NSEC3PARAM", ZONE_NSEC3PARAM, ZONE_ANY, FIELDS(nsec3param_rdata_fields),
                     check_nsec3param_rr, parse_nsec3param_rdata),
  TYPE("TLSA", ZONE_TLSA, ZONE_ANY, FIELDS(tlsa_rdata_fields),
               check_tlsa_rr, parse_tlsa_rdata),
  TYPE("SMIMEA", ZONE_SMIMEA, ZONE_ANY, FIELDS(smimea_rdata_fields),
                 check_tlsa_rr, parse_tlsa_rdata),

  UNKNOWN_TYPE(54),
  UNKNOWN_TYPE(55), // HIP
  UNKNOWN_TYPE(56),
  UNKNOWN_TYPE(57),
  UNKNOWN_TYPE(58),

  TYPE("CDS", ZONE_CDS, ZONE_ANY, FIELDS(cds_rdata_fields),
              check_ds_rr, parse_ds_rdata),
  TYPE("CDNSKEY", ZONE_CDNSKEY, ZONE_ANY, FIELDS(cdnskey_rdata_fields),
                  check_dnskey_rr, parse_dnskey_rdata),
  TYPE("OPENPGPKEY", ZONE_OPENPGPKEY, ZONE_ANY, FIELDS(openpgpkey_rdata_fields),
                     check_openpgpkey_rr, parse_openpgpkey_rdata),

  UNKNOWN_TYPE(62),

  TYPE("ZONEMD", ZONE_ZONEMD, ZONE_ANY, FIELDS(zonemd_rdata_fields),
                 check_zonemd_rr, parse_zonemd_rdata),

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
              check_txt_rr, parse_txt_rdata),

  UNKNOWN_TYPE(100),
  UNKNOWN_TYPE(101),
  UNKNOWN_TYPE(102),
  UNKNOWN_TYPE(103),

  TYPE("NID", ZONE_NID, ZONE_ANY, FIELDS(nid_rdata_fields),
              check_nid_rr, parse_nid_rdata),
  TYPE("L32", ZONE_L32, ZONE_ANY, FIELDS(l32_rdata_fields),
              check_l32_rr, parse_l32_rdata),
  TYPE("L64", ZONE_L64, ZONE_ANY, FIELDS(l64_rdata_fields),
              check_l64_rr, parse_l64_rdata),
  TYPE("LP", ZONE_LP, ZONE_ANY, FIELDS(lp_rdata_fields),
             check_mx_rr, parse_mx_rdata),
  TYPE("EUI48", ZONE_EUI48, ZONE_ANY, FIELDS(eui48_rdata_fields),
                check_eui48_rr, parse_eui48_rdata),
  TYPE("EUI64", ZONE_EUI64, ZONE_ANY, FIELDS(eui64_rdata_fields),
                check_eui64_rr, parse_eui64_rdata),

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
              check_uri_rr, parse_uri_rdata),
  TYPE("CAA", ZONE_CAA, ZONE_ANY, FIELDS(caa_rdata_fields),
              check_caa_rr, parse_caa_rdata),
  TYPE("AVC", ZONE_AVC, ZONE_ANY, FIELDS(avc_rdata_fields),
              check_txt_rr, parse_txt_rdata),
  TYPE("DLV", ZONE_DLV, ZONE_ANY | ZONE_OBSOLETE, FIELDS(dlv_rdata_fields),
              check_ds_rr, parse_ds_rdata)
};

#undef UNKNOWN_CLASS
#undef CLASS
#undef UNKNOWN_TYPE
#undef TYPE

diagnostic_pop()

#endif // TYPES_H
