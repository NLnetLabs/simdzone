/*
 * name.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NAME_H
#define NAME_H

zone_nonnull_all
static zone_really_inline int32_t scan_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const uint8_t delimiters[256],
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  uint8_t *l = octets, *b = octets + 1;
  const uint8_t *bs = octets + 255;
  const char *s = token->data;

  l[0] = 0;

  if (s[0] == '.') {
    if (delimiters[(uint8_t)s[1]] == token->code)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    *length = 1;
    return 0;
  }

  while (b < bs) {
    const uint8_t c = (uint8_t)s[0];
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
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
        b[0] = d[0] * 100 + d[1] * 10 + d[0];
        b += 1; s += 4;
      }
    } else if (c == '.') {
      if ((b - 1) - l > 63 || (b - 1) - l == 0)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      l[0] = (uint8_t)((b - 1) - l);
      l = b;
      l[0] = 0;
      b += 1; s += 1;
    } else if (delimiters[c] != token->code) {
      if ((b - 1) - l > 63)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      l[0] = (uint8_t)((b - 1) - l);
      break;
    } else {
      b[0] = c;
      b += 1; s += 1;
    }
  }

  if (delimiters[(uint8_t)*s] == token->code)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *length = (size_t)(b - octets);
  return l[0] == 0 ? 0 : ZONE_NAME;
}

zone_nonnull_all
static zone_really_inline int32_t scan_contiguous_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  return scan_name(parser, type, field, contiguous, token, octets, length);
}

zone_nonnull_all
static zone_really_inline int32_t scan_quoted_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  return scan_name(parser, type, field, quoted, token, octets, length);
}

zone_nonnull_all
static zone_really_inline int32_t parse_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  size_t n = 0;
  uint8_t *o = &parser->rdata->octets[parser->rdata->length];

  if (zone_likely(token->code == CONTIGUOUS)) {
    // a freestanding "@" denotes the current origin
    if (token->data[0] == '@' && !is_contiguous((uint8_t)token->data[1]))
      goto relative;
    r = scan_contiguous_name(parser, type, field, token, o, &n);
    if (r == 0)
      goto absolute;
    if (r < 0)
      return r;
  } else if (token->code == QUOTED) {
    r = scan_quoted_name(parser, type, field, token, o, &n);
    if (r == 0)
      goto absolute;
    if (r < 0)
      return r;
  } else {
    return have_string(parser, type, field, token);
  }

relative:
  if (n > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  memcpy(o+n, parser->file->origin.octets, parser->file->origin.length);
  parser->rdata->length += n + parser->file->origin.length;
  return ZONE_NAME;
absolute:
  parser->rdata->length += n;
  return ZONE_NAME;
}

#endif // NAME_H
