/*
 * base64.h -- parser for base64 rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef BASE64_H
#define BASE64_H

extern const uint8_t *zone_b64rmap;

static const char Pad64 = '=';

static const uint8_t b64rmap_special = 0xf0;
static const uint8_t b64rmap_end = 0xfd;
static const uint8_t b64rmap_space = 0xfe;

zone_always_inline()
zone_nonnull_all()
static inline void parse_base64(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint32_t state = 0;

  do {
    size_t i=0;

    for (; i < token->length; i++) {
      const uint8_t ofs = zone_b64rmap[(uint8_t)token->data[i]];

      if (ofs >= b64rmap_special) {
        // ignore whitespaces
        if (ofs == b64rmap_space)
          continue;
        // end of base64 characters
        if (ofs == b64rmap_end)
          break;
        // non-base64 character
        goto bad_char;
      }

      switch (state) {
        case 0:
          parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 2);
          state = 1;
          break;
        case 1:
          parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 4);
          parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)((ofs & 0x0f) << 4);
          state = 2;
          break;
        case 2:
          parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 2);
          parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)((ofs & 0x03) << 6);
          state = 3;
          break;
        case 3:
          parser->rdata->octets[parser->rdata->length++] |= ofs;
          parser->rdata->octets[parser->rdata->length  ]  = 0;
          state = 0;
          break;
        default:
          goto bad_char;
      }
    }

    assert(i == token->length || token->data[i] == Pad64);
    if (i < token->length) {
      switch (state) {
        case 0: // invalid, pad character in first position
        case 1: // invalid, pad character in second position
          goto bad_char;

        case 2: // valid, one byte of info
          state = 4;
          // fall through
        case 4:
          for (++i; i < token->length; i++) {
            const uint8_t ofs = zone_b64rmap[(uint8_t)token->data[i]];
            if (ofs == b64rmap_space)
              continue;
            if (ofs == b64rmap_end)
              break;
            goto bad_char;
          }

          if (i == token->length)
            break;
          // fall through

        case 3: // valid, two bytes of info
          state = 5;
          // fall through
        case 5:
          for (++i; i < token->length; i++) {
            const uint8_t ofs = zone_b64rmap[(uint8_t)token->data[i]];
            if (ofs == b64rmap_space)
              continue;
            goto bad_char;
          }
          break;
      }
    }
  } while (lex(parser, token));

  if (state != 0 && state != 5)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);

  return;

bad_char:
  SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                 field->name.data, type->name.data);
}

#endif // BASE64_H
