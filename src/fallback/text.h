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
  const uint8_t delimiters[256],
  const token_t *token)
{
  uint8_t *b = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *bs = b + 255;
  const char *s = token->data;

  while (b < bs) {
    const uint8_t c = (uint8_t)*s;
    if (c == '\\') {
      uint8_t d[3];
      d[0] = (uint8_t)s[1] - '0';

      if (d[0] > 2) {
        b[0] = (uint8_t)s[1];
        b += 1; s += 2;
      } else {
        uint8_t m = d[0] < 2 ? 9 : 5;
        d[1] = (uint8_t)s[2] - '0';
        d[2] = (uint8_t)s[3] - '0';
        if (d[1] > m || d[2] > m)
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(type), NAME(field));
        b[0] = d[0] * 100 + d[1] * 10 + d[0];
        b += 1; s += 4;
      }
    } else if (delimiters[c] != token->code) {
      break;
    } else {
      b[0] = c;
      b += 1; s += 1;
    }
  }

  if (delimiters[(uint8_t)*s] == token->code)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  parser->rdata->octets[parser->rdata->length] = (uint8_t)((b - parser->rdata->octets) - 1);
  parser->rdata->length += (size_t)(b - parser->rdata->octets);
  return ZONE_STRING;
}

zone_nonnull_all
static zone_really_inline int32_t parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (token->code == QUOTED)
    return parse_string_internal(parser, type, field, quoted, token);
  else if (token->code == CONTIGUOUS)
    return parse_string_internal(parser, type, field, contiguous, token);
  else
    return have_string(parser, type, field, token);
}

#endif // TEXT_H
