/*
 * base16.h -- some useful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef BASE16_H
#define BASE16_H

extern const uint8_t *zone_b16rmap;

static const uint8_t b16rmap_special = 0xf0;
static const uint8_t b16rmap_end = 0xfd;
static const uint8_t b16rmap_space = 0xfe;

zone_nonnull_all
static zone_really_inline int32_t parse_base16(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;
  uint32_t state = 0;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  do {
    const char *p = token->data;
    for (;; p++) {
      const uint8_t ofs = zone_b16rmap[(uint8_t)*p];

      if (ofs >= b16rmap_special)
        break;

      if (state == 0)
        parser->rdata->octets[parser->rdata->length] = (uint8_t)(ofs << 4);
      else
        parser->rdata->octets[parser->rdata->length++] |= ofs;

      state = !state;
    }

    if (is_contiguous((uint8_t)*p))
      SYNTAX_ERROR(parser, "Invalid %s in %s record", NAME(field), TNAME(type));
    lex(parser, token);
  } while (token->code == CONTIGUOUS);

  if (state != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;

  return ZONE_BLOB;
}

zone_nonnull_all
static zone_really_inline int32_t parse_salt(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;
  uint32_t state = 0;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  const char *p = token->data;

  if (*p == '-' && contiguous[ (uint8_t)*(p+1) ] != CONTIGUOUS) {
    parser->rdata->octets[parser->rdata->length++] = 0;
    return ZONE_STRING;
  }

  size_t rdlength = parser->rdata->length++;

  for (;; p++) {
    const uint8_t ofs = zone_b16rmap[(uint8_t)*p];

    if (ofs >= b16rmap_special)
      break;

    if (state == 0)
      parser->rdata->octets[parser->rdata->length] = (uint8_t)(ofs << 4);
    else
      parser->rdata->octets[parser->rdata->length++] |= ofs;

    state = !state;
  }

  if (p == token->data || contiguous[ (uint8_t)*p ] == CONTIGUOUS)
    SYNTAX_ERROR(parser, "Invalid %s in %s record", NAME(field), TNAME(type));
  if (state != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s record", NAME(field), TNAME(type));

  parser->rdata->octets[rdlength] = (uint8_t)(parser->rdata->length - rdlength);
  return ZONE_STRING;
}

#endif // BASE16_H
