/*
 * base32.h -- some useful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_BASE32_H
#define ZONE_BASE32_H

#include "scanner.h"

static const uint8_t b32rmap[256] = {
  0xfd, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*   0 -   7 */
  0xff, 0xfe, 0xfe, 0xfe,  0xfe, 0xfe, 0xff, 0xff,  /*   8 -  15 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  16 -  23 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  24 -  31 */
  0xfe, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  32 -  39 */
  0xff, 0xff, 0xff, 0x3e,  0xff, 0xff, 0xff, 0x3f,  /*  40 -  47 */
  0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,  /*  48 -  55 */
  0x08, 0x09, 0xff, 0xff,  0xff, 0xfd, 0xff, 0xff,  /*  56 -  63 */
  0xff, 0x0a, 0x0b, 0x0c,  0x0d, 0x0e, 0x0f, 0x10,  /*  64 -  71 */
  0x11, 0x12, 0x13, 0x14,  0x15, 0x16, 0x17, 0x18,  /*  72 -  79 */
  0x19, 0x1a, 0x1b, 0x1c,  0x1d, 0x1e, 0x1f, 0xff,  /*  80 -  87 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /*  88 -  95 */
  0xff, 0x0a, 0x0b, 0x0c,  0x0d, 0x0e, 0x0f, 0x10,  /*  96 - 103 */
  0x11, 0x12, 0x13, 0x14,  0x15, 0x16, 0x17, 0x18,  /* 104 - 111 */
  0x19, 0x1a, 0x1b, 0x1c,  0x1d, 0x1e, 0x1f, 0xff,  /* 112 - 119 */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  /* 120 - 127 */
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

static const uint8_t b32rmap_special = 0xf0;
static const uint8_t b32rmap_end = 0xfd;
static const uint8_t b32rmap_space = 0xfe;

static inline zone_return_t parse_base32(
  zone_parser_t *parser, const zone_field_info_t *info, zone_token_t *token)
{
  size_t i = 0;

  for (; i < token->string.length; i++) {
    const uint_fast8_t ofs = b32rmap[token->string.data[i]];

    if (ofs >= b32rmap_special) {
      // ignore whitespace
      if (ofs == b32rmap_space)
        continue;
      // end of base32 characters
      if (ofs == b32rmap_end)
        break;
      goto bad_char;
    }

    switch (parser->state.base32) {
      case 0:
        parser->rdata[parser->rdlength  ]  = ofs << 3;
        parser->state.base32 = 1;
        break;
      case 1:
        parser->rdata[parser->rdlength++] |= ofs >> 2;
        parser->rdata[parser->rdlength  ]  = ofs << 6;
        parser->state.base32 = 2;
        break;
      case 2:
        parser->rdata[parser->rdlength  ] |= ofs << 1;
        parser->state.base32 = 3;
        break;
      case 3:
        parser->rdata[parser->rdlength++] |= ofs >> 4;
        parser->rdata[parser->rdlength  ]  = ofs << 4;
        parser->state.base32 = 4;
        break;
      case 4:
        parser->rdata[parser->rdlength++] |= ofs >> 1;
        parser->rdata[parser->rdlength  ]  = ofs << 7;
        parser->state.base32 = 5;
        break;
      case 5:
        parser->rdata[parser->rdlength  ] |= ofs << 2;
        parser->state.base32 = 6;
        break;
      case 6:
        parser->rdata[parser->rdlength++] |= ofs >> 3;
        parser->rdata[parser->rdlength  ]  = ofs << 5;
        parser->state.base32 = 7;
        break;
      case 7:
        parser->rdata[parser->rdlength++] |= ofs;
        parser->state.base32 = 0;
        break;
    }
  }

  if (i < token->string.length) {
    assert(token->string.data[i] == '=');
    for (; i < token->string.length ; i++) {
      if (b32rmap[token->string.data[i]] == b32rmap_space)
        continue;
      if (b32rmap[token->string.data[i]] != '=')
        goto bad_char;

      switch (parser->state.base32) {
        case 0: // invalid
        case 1:
        case 3:
        case 6:
          goto bad_char;
        case 2: // require six pad characters
          parser->state.base32 = 13;
          continue;
        case 4: // require four pad characters
          parser->state.base32 = 11;
          continue;
        case 5: // require three pad characters
          parser->state.base32 = 10;
          break;
        case 7: // require one pad character
          parser->state.base32 = 8;
          break;
        default:
          if (parser->state.base32 == 8)
            goto bad_char;
          assert(parser->state.base32 > 8);
          parser->state.base32--;
          break;
      }
    }
  }

  return 0;
bad_char:
  SEMANTIC_ERROR(parser, "Invalid base32 sequence");
}

static inline zone_return_t accept_base32(
  zone_parser_t *parser, void *user_data)
{
  if (parser->state.base32 != 0 && parser->state.base32 != 8)
    SEMANTIC_ERROR(par, "Invalid base32 sequence");
  parser->state.base32 = 0;
  return 0;
}

#endif // ZONE_BASE32_H
