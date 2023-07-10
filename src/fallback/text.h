/*
 * text.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TEXT_H
#define TEXT_H

zone_nonnull_all
static zone_really_inline int32_t parse_string_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  const uint8_t *d = token->code == CONTIGUOUS ? contiguous : quoted;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w - 1, *we = w + 255;
  const char *t = token->data;

  while (w < we) {
    const uint8_t c = (uint8_t)*t;
    if (c == '\\') {
      uint8_t x[3];
      x[0] = (uint8_t)t[1] - '0';

      if (x[0] > 2) {
        w[0] = (uint8_t)t[1];
        w += 1; t += 2;
      } else {
        x[1] = (uint8_t)t[2] - '0';
        x[2] = (uint8_t)t[3] - '0';
        const uint32_t o = x[0] * 100 + x[1] * 10 + x[2];
        if (o > 255 || x[1] > 9 || x[2] > 9)
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
        w[0] = (uint8_t)o;
        w += 1; t += 4;
      }
    } else if (d[c] == token->code) {
      w[0] = c;
      w += 1; t += 1;
    } else {
      break;
    }
  }

  if (w == we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  assert(d[(uint8_t)*t] != token->code);
  parser->rdata->octets[parser->rdata->length] = (uint8_t)((w - ws) - 1);
  parser->rdata->length += (size_t)(w - ws);
  return ZONE_STRING;
}

zone_nonnull_all
static zone_really_inline int32_t parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code & (CONTIGUOUS|QUOTED)))
    return parse_string_internal(parser, type, field, token);
  return have_string(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_text_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  const uint8_t *d = token->code == CONTIGUOUS ? contiguous : quoted;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_LIMIT];
  const char *t = token->data;

  while (w < we) {
    const uint8_t c = (uint8_t)*t;
    if (c == '\\') {
      uint8_t x[3];
      x[0] = (uint8_t)t[1] - '0';
      if (x[0] > 9) {
        w[0] = (uint8_t)t[1];
        w += 1; t += 2;
      } else {
        x[1] = (uint8_t)t[2] - '0';
        x[2] = (uint8_t)t[3] - '0';
        const uint32_t o = x[0] * 100 + x[1] * 10 + x[0];
        if (o > 255 || x[1] > 9 || x[2] > 9)
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
        w[0] = (uint8_t)o;
        w += 1; t += 4;
      }
    } else if (d[c] == token->code) {
      w[0] = c;
      w += 1; t += 1;
    } else {
      break;
    }
  }

  if (w == we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  assert(d[(uint8_t)*t] != token->code);
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
  if (zone_likely(token->code == QUOTED))
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
