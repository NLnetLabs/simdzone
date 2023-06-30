/*
 * text.h -- some useful commment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TEXT_H
#define TEXT_H

zone_nonnull_all
static zone_really_inline size_t unescape(const char *text, uint8_t *wire)
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
    return (o > 255 || d[1] > 9 || d[2]) ? 0 : 4u;
  }
}

zone_nonnull_all
static zone_really_inline int32_t parse_contiguous_string_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w - 1, *we = w + 255;
  const char *t = token->data;

  while (w < we) {
    copy_contiguous_string_block(t, w, &b);

    if (b.backslash & (b.delimiter - 1)) {
      const size_t n = trailing_zeroes(b.backslash);
      const size_t o = unescape(t, w);
      if (!o)
        SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      w += n + 1; t += n + o;
    } else {
      const size_t n = trailing_zeroes(b.delimiter | (1llu << 32));
      w += n; t += n;
      if (b.delimiter)
        break;
    }
  }

  if (w >= we)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  parser->rdata->octets[parser->rdata->length] = (uint8_t)((w - ws) - 1);
  parser->rdata->length += (size_t)(w - ws);
  return ZONE_STRING;
}

zone_nonnull_all
static zone_really_inline int32_t parse_quoted_string_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w - 1, *we = w + 255;
  const char *t = token->data;

  while (w < we) {
    copy_quoted_string_block(t, w, &b);

    if (b.backslash & (b.delimiter - 1)) {
      const size_t n = trailing_zeroes(b.backslash);
      const size_t o = unescape(t, w);
      if (!o)
        SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      w += n + 1; t += n + o;
    } else {
      const size_t n = trailing_zeroes(b.delimiter | (1llu << 32));
      w += n; t += n;
      if (b.delimiter)
        break;
    }
  }

  if (w >= we)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
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
  if (zone_likely(token->code == QUOTED)) // strings are usually quoted
    return parse_quoted_string_internal(parser, type, field, token);
  else if (token->code == CONTIGUOUS)
    return parse_contiguous_string_internal(parser, type, field, token);
  else
    return have_string(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_contiguous_text_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_LIMIT];
  const char *t = token->data;

  while (w < we) {
    copy_contiguous_string_block(t, w, &b);

    if (zone_unlikely(b.backslash & (b.delimiter - 1))) {
      const size_t n = trailing_zeroes(b.backslash);
      const size_t o = unescape(t+n, w+n);
      if (!o)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      w += n + 1; t += n + o;
    } else {
      const size_t n = trailing_zeroes(b.delimiter | (1llu << 32));
      w += n; t += n;
      if (b.delimiter)
        break;
    }
  }

  if (w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  parser->rdata->length += (size_t)(w - ws);
  return ZONE_BLOB;
}

zone_nonnull_all
static zone_really_inline int32_t parse_quoted_text_internal(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  string_block_t b;
  uint8_t *w = &parser->rdata->octets[parser->rdata->length];
  const uint8_t *ws = w, *we = &parser->rdata->octets[ZONE_RDATA_LIMIT];
  const char *t = token->data;

  while (w < we) {
    copy_quoted_string_block(t, w, &b);

    if (zone_unlikely(b.backslash & (b.delimiter - 1))) {
      const size_t n = trailing_zeroes(b.backslash);
      const size_t o = unescape(t+n, w+n);
      if (!o)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      w += n + 1; t += n + o;
    } else {
      const size_t n = trailing_zeroes(b.delimiter | (1llu << 32));
      w += n; t += n;
      if (b.delimiter)
        break;
    }
  }

  if (w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

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
    return parse_quoted_text_internal(parser, type, field, token);
  return have_quoted(parser, type, field, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_text(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code == QUOTED)) // strings are usually quoted
    return parse_quoted_text_internal(parser, type, field, token);
  else if (token->code == CONTIGUOUS)
    return parse_contiguous_text_internal(parser, type, field, token);
  return have_string(parser, type, field, token);
}

#endif // TEXT_H
