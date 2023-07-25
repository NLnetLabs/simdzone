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

static const uint8_t b64rmap_special = 0xf0;
static const uint8_t b64rmap_end = 0xfd;
static const uint8_t b64rmap_space = 0xfe;

zone_nonnull_all
static zone_really_inline int32_t parse_base64(
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
      const uint8_t ofs = zone_b64rmap[(uint8_t)*p];

      if (ofs >= b64rmap_special)
        break;

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
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      }
    }

    if (*p == '=') {
      switch (state) {
        case 0: // invalid, pad character in first position
        case 1: // invalid, pad character in second position
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
        case 2: // valid, one byte of info
          state = 4;
          if (*p++ != '=')
            break;
          // fall through
        case 3: // valid, two bytes of info
        case 4:
          state = 5;
          p++;
          break;
        default:
          break;
      }
    }

    if (is_contiguous((uint8_t)*p))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    lex(parser, token);
  } while (token->code == CONTIGUOUS);

  if ((r = have_delimiter(parser, type, token)) < 0)
    return r;
  if (state != 0 && state != 5)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  return ZONE_BLOB;
}

#endif // BASE64_H
