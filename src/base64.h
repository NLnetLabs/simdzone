/*
 * base64.h -- parser for base64 rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_BASE64_H
#define ZONE_BASE64_H

static const char Pad64 = '=';

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
static const uint8_t b64rmap_end = 0xfd;
static const uint8_t b64rmap_space = 0xfe;

static inline zone_return_t parse_base64(
  zone_parser_t *__restrict par, zone_token_t *__restrict tok)
{
  int32_t ch;
  uint8_t ofs;

  for (;;) {
    ch = zone_get(par, tok);
    ofs = b64rmap[(uint8_t)ch & 0xff];

    if (ofs >= b64rmap_special) {
      // ignore whitespaces
      if (ofs == b64rmap_space)
        continue;
      // end of base64 characters
      if (ofs == b64rmap_end)
        break;
      // propagate error
      if (ch < 0)
        return ch;
      // non-base64 character
      goto bad_char;
    }

    switch (par->state.base64) {
      case 0:
        par->rdata.base64[par->rdata.length  ]  =  ofs << 2;
        par->state.base64 = 1;
        break;
      case 1:
        par->rdata.base64[par->rdata.length++] |=  ofs >> 4;
        par->rdata.base64[par->rdata.length  ]  = (ofs & 0x0f) << 4;
        par->state.base64 = 2;
        break;
      case 2:
        par->rdata.base64[par->rdata.length++] |=  ofs >> 2;
        par->rdata.base64[par->rdata.length  ]  = (ofs & 0x03) << 6;
        par->state.base64 = 3;
        break;
      case 3:
        par->rdata.base64[par->rdata.length++] |=  ofs;
        par->rdata.base64[par->rdata.length  ]  = 0;
        par->state.base64 = 0;
        break;
      default:
        goto bad_char;
    }
  }

  assert(ch == '\0' || (ch & 0xff) == Pad64);
  if ((ch & 0xff) == Pad64) { // got a pad character
    switch (par->state.base64) {
      case 0: // invalid, pad character in first position
      case 1: // invalid, pad character in second position
        goto bad_char;

      case 2: // valid, one byte of info
        par->state.base64 = 4;
        // fall through
      case 4:
        for (;;) {
          ch = zone_get(par, tok);
          ofs = b64rmap[ch & 0xff];
          if (ofs == b64rmap_space)
            continue;
          if (ofs == b64rmap_end)
            break;
          goto bad_char;
        }

        if (ch == '\0')
          break;
        // fall through

      case 3: // valid, two bytes of info
        par->state.base64 = 5;
        // fall through
      case 5:
        for (;;) {
          ch = zone_get(par, tok);
          ofs = b64rmap[ch & 0xff];
          if (ofs == b64rmap_space)
            continue;
          if (ch == '\0')
            break;
          goto bad_char;
        }
        break;

    }
  }

  return ZONE_DEFER_ACCEPT;
bad_char:
  if (ch < 0)
    return ch;
  SEMANTIC_ERROR(par, "Invalid base64 sequence");
}

static inline zone_return_t accept_base64(
  zone_parser_t *__restrict par, zone_field_t *__restrict fld, void *ptr)
{
  const int32_t state = par->state.base64;

  par->state.base64 = 0;
  if (state != 0 && state != 5)
    SEMANTIC_ERROR(par, "Invalid base64 sequence");

  return par->options.accept.rdata(par, fld, ptr);
}

#endif // ZONE_BASE64_H
