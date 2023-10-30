/*
 * base64.h -- naive base64 parser
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef BASE64_H
#define BASE64_H

static uint8_t b64rmap[256] = {
  0xfd, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*   0 -   7 */
  0xff, 0xfe, 0xfe, 0xfe,  0xfe, 0xfe, 0xff, 0xff,  /*   8 -  15 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  16 -  23 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  24 -  31 */
  0xfe, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  32 -  39 */
  0xff, 0xff, 0xff, 0x3e,  0xff, 0xff, 0xff, 0x3f,  /*  40 -  47 */
  0x34, 0x35, 0x36, 0x37,  0x38, 0x39, 0x3a, 0x3b,  /*  48 -  55 */
  0x3c, 0x3d, 0xff, 0xff,  0xff, 0xfd, 0xff, 0xff,  /*  56 -  63 */
  0xff, 0x00, 0x01, 0x02,  0x03, 0x04, 0x05, 0x06,  /*  64 -  71 */
  0x07, 0x08, 0x09, 0x0a,  0x0b, 0x0c, 0x0d, 0x0e,  /*  72 -  79 */
  0x0f, 0x10, 0x11, 0x12,  0x13, 0x14, 0x15, 0x16,  /*  80 -  87 */
  0x17, 0x18, 0x19, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  88 -  95 */
  0xff, 0x1a, 0x1b, 0x1c,  0x1d, 0x1e, 0x1f, 0x20,  /*  96 - 103 */
  0x21, 0x22, 0x23, 0x24,  0x25, 0x26, 0x27, 0x28,  /* 104 - 111 */
  0x29, 0x2a, 0x2b, 0x2c,  0x2d, 0x2e, 0x2f, 0x30,  /* 112 - 119 */
  0x31, 0x32, 0x33, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 120 - 127 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 128 - 135 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 136 - 143 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 144 - 151 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 152 - 159 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 160 - 167 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 168 - 175 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 176 - 183 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 184 - 191 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 192 - 199 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 200 - 207 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 208 - 215 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 216 - 223 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 224 - 231 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 232 - 239 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 240 - 247 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 248 - 255 */
};

static const uint8_t b64rmap_special = 0xf0;

zone_nonnull_all
static zone_really_inline int32_t parse_base64_sequence(
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
      const uint8_t ofs = b64rmap[(uint8_t)*p];

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

zone_nonnull_all
static zone_really_inline int32_t parse_base64(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  uint32_t state = 0;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  const char *p = token->data;
  for (;; p++) {
    const uint8_t ofs = b64rmap[(uint8_t)*p];

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

	return 0;
}

#endif // BASE64_H
