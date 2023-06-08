/*
 * number.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NUMBER_H
#define NUMBER_H

#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

zone_nonnull_all
static zone_really_inline int32_t parse_symbol(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint64_t n = 0;
  const char *p = token->data;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (is_contiguous((uint8_t)*p)) {
    const zone_symbol_t *s;
    if (!(s = lookup_symbol(&field->symbols, token)))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
    n = (uint8_t)s->value;
  } else {
    if (n > UINT8_MAX || p - token->data > 3)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  }

  parser->rdata->octets[parser->rdata->length] = (uint8_t)n;
  parser->rdata->length += sizeof(uint8_t);
  return ZONE_INT8;
}

zone_nonnull_all
static zone_really_inline int32_t parse_int8(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint64_t n = 0;
  const char *p = token->data;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (n > UINT8_MAX || p - token->data > 3 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  parser->rdata->octets[parser->rdata->length] = (uint8_t)n;
  parser->rdata->length += sizeof(uint8_t);
  return ZONE_INT8;
}

zone_nonnull_all
static zone_really_inline int32_t parse_int16(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint64_t n = 0;
  const char *p = token->data;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (n > UINT16_MAX || p - token->data > 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint16_t n16 = htons((uint16_t)n);
  memcpy(&parser->rdata->octets[parser->rdata->length], &n16, sizeof(n16));
  parser->rdata->length += sizeof(n16);
  return ZONE_INT16;
}

zone_nonnull_all
static zone_really_inline zone_return_t parse_int32(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint64_t n = 0;
  const char *p = token->data;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (n > UINT32_MAX || p - token->data > 10 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  const uint32_t n32 = htonl((uint32_t)n);
  memcpy(&parser->rdata->octets[parser->rdata->length], &n32, sizeof(n32));
  parser->rdata->length += sizeof(n32);
  return ZONE_INT32;
}

#endif // NUMBER_H
