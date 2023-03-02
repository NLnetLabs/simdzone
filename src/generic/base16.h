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

zone_always_inline()
zone_nonnull_all()
static inline void parse_base16(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint32_t state = 0;

  do {
    for (size_t i=0; i < token->length; i++) {
      const uint8_t ofs = zone_b16rmap[(uint8_t)token->data[i]];

      if (ofs >= b16rmap_special) {
        // ignore whitespace
        if (ofs == b16rmap_space)
          continue;
        // end of base16 characters
        if (ofs == b16rmap_end)
          break;
        SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                       field->name.data, type->name.data);
      }

      if (state == 0) {
        parser->rdata[parser->rdlength] = (uint8_t)(ofs << 4);
        state = 1;
      } else {
        parser->rdata[parser->rdlength++] |= ofs;
        state = 0;
      }
    }
  } while (lex(parser, token));

  if (state != 0)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_salt(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint32_t state = 0;

  if (token->length == 1 && token->data[0] == '-') {
    parser->rdata[parser->rdlength++] = 0;
    return;
  }

  if (token->length > 2 * 255)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);

  size_t rdlength = parser->rdlength++;

  for (size_t i=0; i < token->length; i++) {
    const uint8_t ofs = zone_b16rmap[(uint8_t)token->data[i]];

    if (ofs >= b16rmap_special) {
      // ignore whitespace
      if (ofs == b16rmap_space)
        continue;
      // end of base16 characters
      if (ofs == b16rmap_end)
        break;
      SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                     field->name.data, type->name.data);
    }

    if (state == 0) {
      parser->rdata[parser->rdlength] = (uint8_t)(ofs << 4);
      state = 1;
    } else {
      parser->rdata[parser->rdlength++] |= ofs;
      state = 0;
    }
  }

  if (state != 0)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);

  parser->rdata[rdlength] = (uint8_t)(parser->rdlength - rdlength);
}

#endif // BASE16_H
