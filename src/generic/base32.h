/*
 * base32.h -- some useful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef BASE32_H
#define BASE32_H

extern const uint8_t *zone_b32rmap;

static const uint8_t b32rmap_special = 0xf0;
static const uint8_t b32rmap_end = 0xfd;
static const uint8_t b32rmap_space = 0xfe;

zone_always_inline()
zone_nonnull_all()
static inline void parse_base32(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint32_t state = 0;

    size_t i = 0;

    for (; i < token->length; i++) {
      const uint8_t ofs = zone_b32rmap[(uint8_t)token->data[i]];

      if (ofs >= b32rmap_special) {
        // ignore whitespace
        if (ofs == b32rmap_space)
          continue;
        // end of base32 characters
        if (ofs == b32rmap_end)
          break;
        goto bad_char;
      }

      switch (state) {
        case 0:
          parser->rdata[parser->rdlength  ]  = ofs << 3;
          state = 1;
          break;
        case 1:
          parser->rdata[parser->rdlength++] |= ofs >> 2;
          parser->rdata[parser->rdlength  ]  = ofs << 6;
          state = 2;
          break;
        case 2:
          parser->rdata[parser->rdlength  ] |= ofs << 1;
          state = 3;
          break;
        case 3:
          parser->rdata[parser->rdlength++] |= ofs >> 4;
          parser->rdata[parser->rdlength  ]  = ofs << 4;
          state = 4;
          break;
        case 4:
          parser->rdata[parser->rdlength++] |= ofs >> 1;
          parser->rdata[parser->rdlength  ]  = ofs << 7;
          state = 5;
          break;
        case 5:
          parser->rdata[parser->rdlength  ] |= ofs << 2;
          state = 6;
          break;
        case 6:
          parser->rdata[parser->rdlength++] |= ofs >> 3;
          parser->rdata[parser->rdlength  ]  = ofs << 5;
          state = 7;
          break;
        case 7:
          parser->rdata[parser->rdlength++] |= ofs;
          state = 0;
          break;
      }
    }

    if (i < token->length) {
      assert(token->data[i] == '=');
      for (; i < token->length ; i++) {
        if (zone_b32rmap[(uint8_t)token->data[i]] == b32rmap_space)
          continue;
        if (token->data[i] != '=')
          goto bad_char;

        switch (state) {
          case 0: // invalid
          case 1:
          case 3:
          case 6:
            goto bad_char;
          case 2: // require six pad characters
            state = 13;
            continue;
          case 4: // require four pad characters
            state = 11;
            continue;
          case 5: // require three pad characters
            state = 10;
            break;
          case 7: // require one pad character
            state = 8;
            break;
          default:
            if (state == 8)
              goto bad_char;
            assert(state > 8);
            state--;
            break;
        }
      }
    }

  if (state != 0 && state != 8)
    SEMANTIC_ERROR(parser, "Invalid %s in %s record",
                   field->name.data, type->name.data);

  return;
bad_char:
  SEMANTIC_ERROR(parser, "Invalid base32 sequence");
}

#endif // BASE32_H
