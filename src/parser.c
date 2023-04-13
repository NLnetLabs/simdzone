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
#include <arpa/inet.h>
#endif

#include "zone.h"
#include "diagnostic.h"
#include "log.h"
#include "visit.h"

zone_nonnull((1,2,3,4))
zone_always_inline()
static inline size_t check_bytes(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length,
  const size_t size)
{
  (void)data;
  if (length < size)
    SEMANTIC_ERROR(parser, "Missing %s in %s record",
                   field->name.data, type->name.data);
  return size;
}

#define check_int8(...) check_bytes(__VA_ARGS__, sizeof(uint8_t))

#define check_int16(...) check_bytes(__VA_ARGS__, sizeof(uint16_t))

#define check_int32(...) check_bytes(__VA_ARGS__, sizeof(uint32_t))

#define check_ip4(...) check_bytes(__VA_ARGS__, sizeof(struct in_addr))

#define check_ip6(...) check_bytes(__VA_ARGS__, sizeof(struct in6_addr))

zone_always_inline()
zone_nonnull((1,2,3,4))
static inline size_t check_ttl(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  uint32_t number;

  if (length < sizeof(number))
    SEMANTIC_ERROR(parser, "Missing %s in %s record",
                   field->name.data, type->name.data);

  memcpy(&number, data, sizeof(number));
  number = ntohl(number);

  if (number > INT32_MAX)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);

  return 4;
}

zone_always_inline()
zone_nonnull((1,2,3,4))
static inline size_t check_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  uint16_t number;

  if (length < sizeof(number))
    SEMANTIC_ERROR(parser, "Missing %s in %s record",
                   field->name.data, type->name.data);

  memcpy(&number, data, sizeof(number));

  if (!number)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);
  return 2;
}

zone_always_inline()
zone_nonnull((1,2,3,4))
static inline size_t check_name(
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
    SEMANTIC_ERROR(parser, "Invalid %s in  %s record",
                   field->name.data, type->name.data);
  return count;
}

zone_always_inline()
zone_nonnull((1,2,3,4))
static inline size_t check_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t *data,
  const size_t length)
{
  size_t count;

  if (!length || (count = 1 + (size_t)data[0]) > length)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);
  return count;
}

zone_always_inline()
zone_nonnull((1,2,3,4))
static inline size_t check_nsec(
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
      SEMANTIC_ERROR(parser, "Invalid %s in %s, windows are out-of-order",
                     field->name.data, type->name.data);
    if (blocks > 32)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, blocks are out-of-bounds",
                     field->name.data, type->name.data);
    count += 2 + blocks;
    last_window = window;
  }

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  return count;
}

diagnostic_push()
clang_diagnostic_ignored(implicit-function-declaration)
clang_diagnostic_ignored(missing-prototypes)

zone_nonnull((1,2))
void zone_check_a_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_ip4(parser, type, &fields[0], data, length);
  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);

  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_ns_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_name(parser, type, &fields[0], data, length);
  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);

  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_cname_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_name(parser, type, &fields[0], data, length);
  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_soa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_name(parser, type, &fields[0], data, length);
  count += check_name(parser, type, &fields[1], data + count, length - count);
  count += check_int32(parser, type, &fields[2], data + count, length - count);
  count += check_ttl(parser, type, &fields[3], data + count, length - count);
  count += check_ttl(parser, type, &fields[4], data + count, length - count);
  count += check_ttl(parser, type, &fields[5], data + count, length - count);
  count += check_ttl(parser, type, &fields[6], data + count, length - count);

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_mx_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int16(parser, type, &fields[0], data, length);
  count += check_name(parser, type, &fields[1], data + count, length - count);

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_txt_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_string(parser, type, &fields[0], data, length);
  while (count < length)
    count += check_string(parser, type, &fields[0], data+count, length-count);

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_aaaa_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_ip6(parser, type, &fields[0], data, length);

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_srv_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int16(parser, type, &fields[0], data, length);
  count += check_int16(parser, type, &fields[1], data+count, length-count);
  count += check_int16(parser, type, &fields[2], data+count, length-count);
  count += check_name(parser, type, &fields[3], data+count, length-count);

  if (count != length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_ds_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int16(parser, type, &fields[0], data, length);
  count += check_int8(parser, type, &fields[1], data+count, length-count);
  count += check_int8(parser, type, &fields[2], data+count, length-count);

  if (count <= length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_rrsig_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_type(parser, type, &fields[0], data, length);
  count += check_int8(parser, type, &fields[1], data, length);
  count += check_int8(parser, type, &fields[2], data, length);
  count += check_ttl(parser, type, &fields[3], data, length);
  count += check_int32(parser, type, &fields[4], data, length);
  count += check_int32(parser, type, &fields[5], data, length);
  count += check_int16(parser, type, &fields[6], data, length);
  count += check_name(parser, type, &fields[7], data, length);

  if (count <= length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_nsec_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_name(parser, type, &fields[0], data, length);
  count += check_nsec(parser, type, &fields[1], data, length);

  if (count <= length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);
  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_dnskey_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int16(parser, type, &fields[0], data, length);
  count += check_int8(parser, type, &fields[1], data+count, length-count);
  count += check_int8(parser, type, &fields[2], data+count, length-count);

  if (count <= length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);

  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_nsec3_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int8(parser, type, &fields[0], data, length);
  count += check_int8(parser, type, &fields[1], data+count, length-count);
  count += check_int16(parser, type, &fields[2], data+count, length-count);
  count += check_string(parser, type, &fields[3], data+count, length-count);
  count += check_string(parser, type, &fields[4], data+count, length-count);
  count += check_nsec(parser, type, &fields[5], data+count, length-count);

  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_nsec3param_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  size_t count = 0;
  const size_t length = parser->rdata->length;
  const uint8_t *data = parser->rdata->octets;
  const zone_field_info_t *fields = type->rdata.fields;

  count += check_int8(parser, type, &fields[0], data, length);
  count += check_int8(parser, type, &fields[1], data+count, length-count);
  count += check_int16(parser, type, &fields[2], data+count, length-count);
  count += check_string(parser, type, &fields[3], data+count, length-count);

  if (count <= length)
    SEMANTIC_ERROR(parser, "Invalid %s record", type->name.data);

  accept_rr(parser, user_data);
}

zone_nonnull((1,2))
void zone_check_unknown_rdata(
  zone_parser_t *parser, const zone_type_info_t *type, void *user_data)
{
  (void)parser;
  (void)type;
  (void)user_data;

  // implement
}

diagnostic_pop()
