/*
 * text.h -- fallback parser for strings
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TEXT_H
#define TEXT_H

zone_nonnull_all
static zone_really_inline uint32_t unescape(const char *text, uint8_t *wire)
{
  uint8_t d[3];

  if ((d[0] = (uint8_t)text[1] - '0') > 9) {
    *wire = (uint8_t)text[1];
    return 2u;
  } else {
    d[1] = (uint8_t)text[2] - '0';
    d[2] = (uint8_t)text[3] - '0';
    uint32_t o = d[0] * 100 + d[1] * 10 + d[2];
    *wire = (uint8_t)o;
    return (o > 255 || d[1] > 9 || d[2] > 9) ? 0 : 4u;
  }
}

zone_nonnull_all
static zone_really_inline int32_t parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w - 1, *we = w + 255;
  const char *t = token->data, *te = t + token->length;

  while ((t < te) & (w < we)) {
    *w = (uint8_t)*t;
    if (zone_unlikely(*t == '\\')) {
      uint32_t o;
      if (!(o = unescape(t, w)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      w += 1; t += o;
    } else {
      w += 1; t += 1;
    }
  }

  if (t != te || w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  parser->rdata->octets[parser->rdata->length] = (uint8_t)((w - ws) - 1);
  parser->rdata->length += (size_t)(w - ws);
  return ZONE_STRING;
}

zone_nonnull_all
static zone_really_inline int32_t parse_text_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_SIZE];
  const char *t = token->data, *te = t + token->length;

  while ((t < te) & (w < we)) {
    *w = (uint8_t)*t;
    if (zone_unlikely(*t == '\\')) {
      uint32_t o;
      if (!(o = unescape(t, w)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      w += 1; t += o;
    } else {
      w += 1; t += 1;
    }
  }

  if (t != te || w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  parser->rdata->length += (size_t)(w - ws);
  return ZONE_BLOB;
}

zone_nonnull_all
static zone_really_inline int32_t parse_quoted_text(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code & QUOTED))
    return parse_text_internal(parser, type, field, token);
  return have_quoted(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_text(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code & (CONTIGUOUS|QUOTED)))
    return parse_text_internal(parser, type, field, token);
  return have_string(parser, type, field, token);
}

#endif // TEXT_H
