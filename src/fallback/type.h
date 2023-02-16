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

#include <strings.h>

#include "zone.h"

extern const zone_table_t *zone_identifiers;

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const zone_token_t *token,
  uint16_t *code)
{
  const zone_symbol_t *symbol = NULL;

  if ((symbol = zone_lookup(zone_identifiers, token))) {
    *code = symbol->value & 0xffff;
    return symbol->value >> 16;
  } else if (token->length > 4 && strncasecmp(token->data, "TYPE", 4) == 0) {
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
    SEMANTIC_ERROR(parser, "Invalid type in %s", field->name.data);
  } else if (token->length > 5 && strncasecmp(token->data, "CLASS", 5) == 0) {
    uint64_t v = 0;
    for (size_t i=5; i < token->length; i++) {
      const uint64_t n = (uint8_t)token->data[i] - '0';
      if (n > 9)
        goto bad_class;
      v = v * 10 + n;
      if (v > UINT16_MAX)
        goto bad_type;
    }

    *code = (uint16_t)v;
    return ZONE_CLASS;
bad_class:
    SEMANTIC_ERROR(parser, "Invalid class in %s", field->name.data);
  }

  SEMANTIC_ERROR(parser, "Invalid type or class in %s", field->name.data);
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
  const zone_symbol_t *symbol = NULL;

  if ((symbol = zone_lookup(zone_identifiers, token))) {
    if (symbol->value >> 16 != ZONE_TYPE)
      goto bad_type;
    *code = symbol->value & 0xffff;
    return ZONE_TYPE;
  } else if (token->length > 4 && strncasecmp(token->data, "TYPE", 4) == 0) {
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
  SEMANTIC_ERROR(parser, "Invalid type in %s", field->name.data);
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
