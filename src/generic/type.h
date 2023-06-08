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
#if !defined _WIN32
#include <strings.h>
#endif

extern const zone_table_t *zone_identifiers;
extern const zone_fast_table_t *zone_fast_identifiers;

zone_nonnull_all
static zone_really_inline const zone_symbol_t *lookup_type_or_class(
  zone_parser_t *parser, const token_t *token)
{
  delimited_t delimited;

  (void)parser;
  // FIXME: Not explicitly specified, but RRTYPE names (so far) consist of
  //        [0-9a-zA-Z-]. A simple range check (as described on #66) may
  //        outperform scanning for delimiters.
  scan_delimited(&delimited, non_contiguous, blank, token->data);

  const size_t length = trailing_zeroes(delimited.delimiter | (1llu << 63));
  uint8_t key = ((uint8_t)(token->data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t hash = token->data[length - 1] & 0xdf;
  hash *= 0x07; // better distribution (A + 1 != B)
  hash += (uint8_t)length;

  const zone_fast_table_t *table = &zone_fast_identifiers[key];

  simd_8x16_t keys;
  simd_loadu_8x16(&keys, table->keys);
  const uint64_t bits = simd_find_8x16(&keys, (char)hash);
  const uint64_t index = trailing_zeroes(bits | (1llu << 15));

  const zone_symbol_t *symbol = table->symbols[index];

  if (!symbol || strncasecmp(token->data, symbol->key.data, symbol->key.length))
    return NULL;
  if (contiguous[ (uint8_t)token->data[symbol->key.length] ] == CONTIGUOUS)
    return NULL;

  return symbol;
}

zone_nonnull_all
static zone_really_inline int32_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code)
{
  int32_t r;
  const zone_symbol_t *s;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  if ((s = lookup_type_or_class(parser, token)))
    return (void)(*code = s->value & 0xffffu), s->value >> 16;

  if (strncasecmp(token->data, "TYPE", 4) == 0)
    r = ZONE_TYPE;
  else if (strncasecmp(token->data, "CLASS", 5) == 0)
    r = ZONE_CLASS;
  else
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint64_t n = 0;
  const char *p = token->data + 4 + (r == ZONE_CLASS);
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > UINT16_MAX || p - token->data >= 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  *code = (uint16_t)n;
  return r;
}

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code)
{
  int32_t r;
  const zone_symbol_t *s;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  if ((s = lookup_type_or_class(parser, token)))
    return (void)(*code = s->value & 0xffffu), s->value >> 16;

  if (strncasecmp(token->data, "TYPE", 4) == 0)
    r = ZONE_TYPE;
  else
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint64_t n = 0;
  const char *p = token->data + 4;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > UINT16_MAX || p - token->data > 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  *code = (uint16_t)n;
  return r;
}

zone_nonnull_all
static zone_really_inline int32_t parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  uint16_t c;

  if ((r = scan_type(parser, type, field, token, &c)) < 0)
    return r;
  c = htons(c);
  memcpy(&parser->rdata->octets[parser->rdata->length], &c, sizeof(c));
  parser->rdata->length += sizeof(c);
  return ZONE_TYPE;
}

#endif // TYPE_H
