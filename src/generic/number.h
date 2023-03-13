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
#include <arpa/inet.h>
#endif

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t parse_int8(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint64_t v = 0;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = (unsigned char)token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT8_MAX)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, value exceeds maximum",
                     field->name.data, type->name.data);
  }

  parser->rdata[parser->rdlength] = (uint8_t)v;
  parser->rdlength += sizeof(uint8_t);
  return ZONE_RDATA;
parse_symbol:
  if (!(symbol = zone_lookup(&field->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid %s in %s, not a number",
                 field->name.data, type->name.data);
  assert(symbol->value <= UINT8_MAX);
  parser->rdata[parser->rdlength] = (uint8_t)symbol->value;
  parser->rdlength += sizeof(uint8_t);
  return ZONE_RDATA;
}

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t parse_int16(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint64_t v = 0;
  uint16_t v16;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = (unsigned char)token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT16_MAX)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, value exceeds maximum",
                     field->name.data, type->name.data);
  }

  v16 = htons((uint16_t)v);
  memcpy(&parser->rdata[parser->rdlength], &v16, sizeof(v16));
  parser->rdlength += sizeof(uint16_t);
  return ZONE_RDATA;
parse_symbol:
  if (!(symbol = zone_lookup(&field->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid %s in %s, not a number",
                 field->name.data, type->name.data);
  assert(symbol->value <= UINT16_MAX);
  v16 = htons((uint16_t)symbol->value);
  memcpy(&parser->rdata[parser->rdlength], &v16, sizeof(v16));
  parser->rdlength += sizeof(uint16_t);
  return ZONE_RDATA;
}

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t parse_int32(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint64_t v = 0;
  uint32_t v32;
  zone_symbol_t *symbol;

  for (size_t i=0; i < token->length; i++) {
    const uint64_t n = (unsigned char)token->data[i] - '0';
    if (n > 9)
      goto parse_symbol;
    v = (v * 10) + n;
    if (v > UINT32_MAX)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, value exceeds maximum",
                     field->name.data, type->name.data);
  }

  v32 = htonl((uint32_t)v);
  memcpy(&parser->rdata[parser->rdlength], &v32, sizeof(v32));
  parser->rdlength += sizeof(uint32_t);
  return ZONE_RDATA;
parse_symbol:
  if (!(symbol = zone_lookup(&field->symbols, token)))
    SYNTAX_ERROR(parser, "Invalid %s in %s, not a number",
                 field->name.data, type->name.data);
  assert(symbol->value <= UINT16_MAX);
  v32 = htonl(symbol->value);
  memcpy(&parser->rdata[parser->rdlength], &v32, sizeof(v32));
  parser->rdlength += sizeof(uint32_t);
  return ZONE_RDATA;
}

#endif // NUMBER_H
