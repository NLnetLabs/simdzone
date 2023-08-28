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
static zone_really_inline uint32_t unescape(const char *text, uint8_t *wire)
{
  uint8_t d[3];
  uint32_t o;

  if ((d[0] = (uint8_t)text[1] - '0') > 9) {
    o = (uint8_t)text[1];
    *wire = (uint8_t)o;
    return 2u;
  } else {
    d[1] = (uint8_t)text[2] - '0';
    d[2] = (uint8_t)text[3] - '0';
    o = d[0] * 100 + d[1] * 10 + d[2];
    *wire = (uint8_t)o;
    return (o > 255 || d[1] > 9 || d[2] > 9) ? 0 : 4u;
  }
}

typedef struct string_block string_block_t;
struct string_block {
  uint64_t backslashes;
};

zone_nonnull_all
static zone_really_inline void copy_string_block(
  string_block_t *block, const char *text, uint8_t *wire)
{
  simd_8x32_t input;
  simd_loadu_8x32(&input, text);
  simd_storeu_8x32(wire, &input);
  block->backslashes = simd_find_8x32(&input, '\\');
}

zone_nonnull_all
static zone_really_inline int32_t parse_string_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w - 1, *we = w + 255;
  const char *t = token->data, *te = t + token->length;
  uint64_t left = token->length;

  while ((t < te) & (w < we)) {
    copy_string_block(&b, t, w);
    uint64_t n = 32;
    if (left < 32)
      n = left;
    uint64_t mask = (1llu << n) - 1;

    if (b.backslashes & mask) {
      n = trailing_zeroes(b.backslashes);
      w += n; t += n;
      if (!(n = unescape(t, w)))
        SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      w += 1; t += n;
    } else {
      w += n; t += n;
    }
  }

  if (w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
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
  int32_t r;

  if ((r = have_string(parser, type, field, token)) < 0)
    return r;
  return parse_string_internal(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_text_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_SIZE];
  const char *t = token->data, *te = t + token->length;
  uint64_t left = token->length;

  while ((t < te) & (w < we)) {
    copy_string_block(&b, t, w);
    uint64_t n = 32;
    if (left < 32)
      n = left;
    uint64_t mask = (1llu << n) - 1;

    if (zone_unlikely(b.backslashes & mask)) {
      n = trailing_zeroes(b.backslashes);
      w += n; t += n;
      if (!(n = unescape(t, w)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      w += 1; t += n;
    } else {
      w += n; t += n;
    }
  }

  if (w >= we)
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
  int32_t r;

  if ((r = have_quoted(parser, type, field, token)) < 0)
    return r;
  return parse_text_internal(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_text(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;

  if ((r = have_string(parser, type, field, token)) < 0)
    return r;
  return parse_text_internal(parser, type, field, token);
}

#endif // TEXT_H
