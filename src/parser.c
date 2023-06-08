/*
 * parser.c -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <string.h>
#if _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#else
#include <netinet/in.h>
#endif

#include "zone.h"
#include "diagnostic.h"
#include "log.h"
#include "visit.h"

#if _WIN32
typedef SSIZE_T ssize_t;
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
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), NAME(type));
  return (ssize_t)size;
}

#define check_int8(...) check_bytes(__VA_ARGS__, sizeof(uint8_t))

#define check_int16(...) check_bytes(__VA_ARGS__, sizeof(uint16_t))

#define check_int32(...) check_bytes(__VA_ARGS__, sizeof(uint32_t))

#define check_ip4(...) check_bytes(__VA_ARGS__, sizeof(struct in_addr))

#define check_ip6(...) check_bytes(__VA_ARGS__, sizeof(struct in6_addr))


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
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), NAME(type));

  memcpy(&number, data, sizeof(number));
  number = ntohl(number);

  if (number > INT32_MAX)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

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
    SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), NAME(type));

  memcpy(&number, data, sizeof(number));

  if (!number)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

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
  }

  if (!count || count > length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

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
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

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
                   NAME(field), NAME(type));
    if (blocks > 32)
      SYNTAX_ERROR(parser, "Invalid %s in %s, blocks are out-of-bounds",
                   NAME(field), NAME(type));
    count += 2 + blocks;
    last_window = window;
  }

  if (count != length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  return (ssize_t)count;
}

zone_nonnull((1))
static int32_t add(size_t *length, ssize_t count)
{
  if (count < 0)
    return (int32_t)count;
  *length = (size_t)count;
  return 0;
}

diagnostic_push()
clang_diagnostic_ignored(implicit-function-declaration)
clang_diagnostic_ignored(missing-prototypes)

zone_nonnull((1,2))
int32_t zone_check_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_ip4(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_name(parser, type, &f[0], o, n))) < 0)
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_cname_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_name(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_name(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_name(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int32(parser, type, &f[2], o+c, n-c))) ||
      (r = add(&c, check_ttl(parser, type, &f[3], o+c, n-c))) ||
      (r = add(&c, check_ttl(parser, type, &f[4], o+c, n-c))) ||
      (r = add(&c, check_ttl(parser, type, &f[5], o+c, n-c))) ||
      (r = add(&c, check_ttl(parser, type, &f[6], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_name(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_string(parser, type, &f[0], o, n))))
    return r;

  while (c < n)
    if ((r = add(&c, check_string(parser, type, &f[0], o+c, n-c))))
      return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_ip6(parser, type, &f[0], o, n))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s record", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int16(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = add(&c, check_name(parser, type, &f[3], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_type(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int8(parser, type, &f[2], o+c, n-c))) ||
      (r = add(&c, check_ttl(parser, type, &f[3], o+c, n-c))) ||
      (r = add(&c, check_int32(parser, type, &f[4], o+c, n-c))) ||
      (r = add(&c, check_int32(parser, type, &f[5], o+c, n-c))) ||
      (r = add(&c, check_int16(parser, type, &f[6], o+c, n-c))) ||
      (r = add(&c, check_name(parser, type, &f[7], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_name(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_nsec(parser, type, &f[1], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int16(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int8(parser, type, &f[2], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = add(&c, check_string(parser, type, &f[3], o+c, n-c))) ||
      (r = add(&c, check_string(parser, type, &f[4], o+c, n-c))) ||
      (r = add(&c, check_nsec(parser, type, &f[5], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  int32_t r;
  size_t c = 0;
  const size_t n = parser->rdata->length;
  const uint8_t *o = parser->rdata->octets;
  const zone_field_info_t *f = type->rdata.fields;

  if ((r = add(&c, check_int8(parser, type, &f[0], o, n))) ||
      (r = add(&c, check_int8(parser, type, &f[1], o+c, n-c))) ||
      (r = add(&c, check_int16(parser, type, &f[2], o+c, n-c))) ||
      (r = add(&c, check_string(parser, type, &f[3], o+c, n-c))))
    return r;

  if (c != n)
    SYNTAX_ERROR(parser, "Invalid %s", NAME(type));
  return accept_rr(parser);
}

zone_nonnull((1,2))
int32_t zone_check_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *type)
{
  (void)parser;
  (void)type;

  // FIXME: implement

  return 0;
}

diagnostic_pop()
