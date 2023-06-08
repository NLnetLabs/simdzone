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
#if _WIN32
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#else
#include <strings.h>
#endif

#include "zone.h"

extern const zone_table_t *zone_identifiers;

zone_nonnull_all
static zone_really_inline int32_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code)
{
  int32_t r;
  const zone_symbol_t *s = NULL;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;
  if ((s = lookup_symbol(zone_identifiers, token)))
    return (void)(*code = s->value & 0xffff), s->value >> 16;

  if (strncasecmp(token->data, "TYPE", 4) == 0)
    r = ZONE_TYPE;
  else if (strncasecmp(token->data, "CLASS", 5) == 0)
    r = ZONE_CLASS;
  else
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint64_t n = 0;
  const char *p, *q;
  p = q = token->data + 4 + (r == ZONE_CLASS);
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > UINT16_MAX || p - q >= 5 || is_contiguous((uint8_t)*p))
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
  if ((s = lookup_symbol(zone_identifiers, token)))
    return (void)(*code = s->value & 0xffff), s->value >> 16;

  if (strncasecmp(token->data, "TYPE", 4) != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint64_t n = 0;
  const char *p, *q;
  p = q = token->data + 4;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  return ZONE_NAME;
}

zone_nonnull_all
static zone_really_inline int32_t parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;
  uint16_t c = 0;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  scan_type(parser, type, field, token, &c);
  c = htons(c);
  memcpy(&parser->rdata->octets[parser->rdata->length], &c, sizeof(c));
  parser->rdata->length += sizeof(c);
  return ZONE_NAME;
}

#endif // TYPE_H
