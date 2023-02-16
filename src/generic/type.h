/*
 * type.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TYPE_H
#define TYPE_H

#include <string.h>
#include <strings.h>

#include "zone.h"

extern const zone_table_t *zone_identifiers;
extern const zone_fast_table_t *zone_fast_identifiers;

zone_always_inline()
static inline uint8_t subs(uint8_t x, uint8_t y)
{
  uint8_t res = x - y;
  res &= -(res <= x);
  return res;
}

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->data[n] & 0xdf);
  h *= 0x07;
  h += (uint8_t)token->length;

  const zone_fast_table_t *table = &zone_fast_identifiers[k];

  simd_8x16_t keys;
  simd_loadu_8x16(&keys, table->keys);
  const uint64_t bits = simd_find_8x16(&keys, h) | (1u << 15);
  const uint64_t index = trailing_zeroes(bits);
  const zone_symbol_t *symbol = table->symbols[index];

  if (symbol &&
      token->length == symbol->key.length &&
      strncasecmp(token->data, symbol->key.data, symbol->key.length) == 0)
  {
    *code = symbol->value & 0xffffu;
    return symbol->value >> 16;
  }

  if (token->length > 4 &&
      strncasecmp(token->data, "TYPE", 4) == 0)
  {
    uint64_t v = 0;
    for (size_t i=4; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_type;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_type;
    }

    *code = (uint16_t)v;
    return ZONE_TYPE;
bad_type:
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  }

  if (token->length > 5 &&
      strncasecmp(token->data, "CLASS", 5) == 0)
  {
    uint64_t v = 0;
    for (size_t i=5; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_class;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_class;
    }

    *code = (uint16_t)v;
    return ZONE_CLASS;
bad_class:
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  }

  SEMANTIC_ERROR(parser, "Invalid %s in %s",
                 field->name.data, type->name.data);
}

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->data[n] & 0xdf);
  h *= 0x07;
  h += (uint8_t)token->length;

  const zone_fast_table_t *table = &zone_fast_identifiers[k];

  simd_8x16_t keys;
  simd_loadu_8x16(&keys, table->keys);
  const uint64_t bits = simd_find_8x16(&keys, h) | (1u << 15);
  const uint64_t index = trailing_zeroes(bits);
  const zone_symbol_t *symbol = table->symbols[index];

  if (symbol &&
      token->length == symbol->key.length &&
      strncasecmp(token->data, symbol->key.data, symbol->key.length) == 0)
  {
    *code = symbol->value & 0xffff;
    //return symbol->value >> 16;
    return ZONE_TYPE;
  }

  if (token->length > 4 &&
      strncasecmp(token->data, "TYPE", 4) == 0)
  {
    uint64_t v = 0;
    for (size_t i=4; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_type;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_type;
    }

    *code = (uint16_t)v;
    return ZONE_TYPE;
  }

bad_type:
  SEMANTIC_ERROR(parser, "Invalid %s in %s",
                 field->name.data, type->name.data);
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint16_t code;

  scan_type(parser, type, field, token, &code);
  code = htons(code);
  memcpy(&parser->rdata[parser->rdlength], &code, sizeof(code));
  parser->rdlength += sizeof(uint16_t);
}

#endif // TYPE_H
