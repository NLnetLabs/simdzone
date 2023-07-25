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

zone_nonnull_all
static zone_really_inline int32_t parse_base32(
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
  for (;; p++) {
    const uint8_t ofs = zone_b32rmap[(uint8_t)*p];

    if (ofs >= b32rmap_special)
      break;

    switch (state) {
      case 0:
        parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 3);
        state = 1;
        break;
      case 1:
        parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 2);
        parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 6);
        state = 2;
        break;
      case 2:
        parser->rdata->octets[parser->rdata->length  ] |= (uint8_t)(ofs << 1);
        state = 3;
        break;
      case 3:
        parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 4);
        parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 4);
        state = 4;
        break;
      case 4:
        parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 1);
        parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 7);
        state = 5;
        break;
      case 5:
        parser->rdata->octets[parser->rdata->length  ] |= (uint8_t)(ofs << 2);
        state = 6;
        break;
      case 6:
        parser->rdata->octets[parser->rdata->length++] |= (uint8_t)(ofs >> 3);
        parser->rdata->octets[parser->rdata->length  ]  = (uint8_t)(ofs << 5);
        state = 7;
        break;
      case 7:
        parser->rdata->octets[parser->rdata->length++] |= ofs;
        state = 0;
        break;
    }
  }

  for (; *p == '-'; p++) {
    switch (state) {
      case 0: // invalid
      case 1:
      case 3:
      case 6:
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
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
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
        assert(state > 8);
        state--;
        break;
    }
  }

  if (contiguous[ (uint8_t)*p ] == CONTIGUOUS)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  if (state != 0 && state != 8)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return ZONE_STRING;
}

#endif // BASE32_H
