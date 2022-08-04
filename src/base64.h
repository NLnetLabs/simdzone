/*
 * base64.c -- parser for base64 rdata in (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_BASE64_H
#define ZONE_BASE64_H
/* Adaptation of an existing implementation found in NSD. */

/*
 * Portions Copyright (c) 1996, 1998 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

// !!INCLUDES!!
static const char Pad64 = '=';

/* (From RFC1521 and draft-ietf-dnssec-secext-03.txt)
   The following encoding technique is taken from RFC 1521 by Borenstein
   and Freed.  It is reproduced here in a slightly edited form for
   convenience.

   A 65-character subset of US-ASCII is used, enabling 6 bits to be
   represented per printable character. (The extra 65th character, "=",
   is used to signify a special processing function.)

   The encoding process represents 24-bit groups of input bits as output
   strings of 4 encoded characters. Proceeding from left to right, a
   24-bit input group is formed by concatenating 3 8-bit input groups.
   These 24 bits are then treated as 4 concatenated 6-bit groups, each
   of which is translated into a single digit in the base64 alphabet.

   Each 6-bit group is used as an index into an array of 64 printable
   characters. The character referenced by the index is placed in the
   output string.

                         Table 1: The Base64 Alphabet

      Value Encoding  Value Encoding  Value Encoding  Value Encoding
          0 A            17 R            34 i            51 z
          1 B            18 S            35 j            52 0
          2 C            19 T            36 k            53 1
          3 D            20 U            37 l            54 2
          4 E            21 V            38 m            55 3
          5 F            22 W            39 n            56 4
          6 G            23 X            40 o            57 5
          7 H            24 Y            41 p            58 6
          8 I            25 Z            42 q            59 7
          9 J            26 a            43 r            60 8
         10 K            27 b            44 s            61 9
         11 L            28 c            45 t            62 +
         12 M            29 d            46 u            63 /
         13 N            30 e            47 v
         14 O            31 f            48 w         (pad) =
         15 P            32 g            49 x
         16 Q            33 h            50 y

   Special processing is performed if fewer than 24 bits are available
   at the end of the data being encoded.  A full encoding quantum is
   always completed at the end of a quantity.  When fewer than 24 input
   bits are available in an input group, zero bits are added (on the
   right) to form an integral number of 6-bit groups.  Padding at the
   end of the data is performed using the '=' character.

   Since all base64 input is an integral number of octets, only the
         -------------------------------------------------
   following cases can arise:

       (1) the final quantum of encoding input is an integral
           multiple of 24 bits; here, the final unit of encoded
     output will be an integral multiple of 4 characters
     with no "=" padding,
       (2) the final quantum of encoding input is exactly 8 bits;
           here, the final unit of encoded output will be two
     characters followed by two "=" padding characters, or
       (3) the final quantum of encoding input is exactly 16 bits;
           here, the final unit of encoded output will be three
     characters followed by one "=" padding character.
   */

/* skips all whitespace anywhere.
   converts characters, four at a time, starting at (or after)
   src from base - 64 numbers into three 8 bit bytes in the target area.
   it returns the number of data bytes stored at the target, or -1 on error.
 */

zone_return_t accept_base64(
  zone_parser_t *par, zone_field_t *fld, void *ptr)
{
  size_t len = 0;
  uint8_t *octs;

  switch (par->parser.base64.state) {
    case 0:
      break;
    case 1:
      SEMANTIC_ERROR(par, "Invalid base64 sequence");
    case 2:
    case 4:
      if (par->parser.base64.pad != 2)
        SEMANTIC_ERROR(par, "Missing padding characters!");
      len = 1;
      break;
    case 3:
    case 5:
      if (par->parser.base64.pad != 1)
        SEMANTIC_ERROR(par, "Missing padding characters!");
      len = 2;
      break;
  }

  if (par->parser.base64.length > sizeof(par->parser.base64.octets) - len)
    SEMANTIC_ERROR(par, "Base64 data is too much!");

  memmove(&par->parser.base64.octets[par->parser.base64.length],
          &par->parser.base64.decoded[0], len);
  par->parser.base64.length += len;


  if (!(octs = zone_malloc(par, par->parser.base64.length)))
    return ZONE_OUT_OF_MEMORY;
  memcpy(octs, par->parser.base64.octets, par->parser.base64.length);
  fld->b64.length = par->parser.base64.length;
  fld->b64.octets = octs;

  zone_return_t ret;
  if ((ret = par->options.accept.rdata(par, fld, ptr)) < 0)
    zone_free(par, octs);

  par->parser.base64.pad = 0;
  par->parser.base64.state = 0;
  par->parser.base64.length = 0;
  return 0;
}

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

zone_return_t parse_base64(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t cur = 0;
  uint8_t ofs;
  zone_char_t ch;

  (void)fld;
  (void)ptr;

  for (;;) {
    if ((ch = zone_string_next(&tok->string, &cur, 0)) < 0)
      goto bad_escape;
    ofs = b64rmap[(uint8_t)ch & 0xff];

    if (ofs >= b64rmap_special) {
      // Ignore whitespaces
      if (ofs == b64rmap_space)
        continue;
      // End of base64 characters
      if (ofs == b64rmap_end)
        break;
      // A non-base64 character.
      goto bad_char;
    }

    if (par->parser.base64.state == 0) {
      par->parser.base64.decoded[0]  = ofs << 2;
      par->parser.base64.state = 1;
    } else if (par->parser.base64.state == 1) {
      par->parser.base64.decoded[0] |=  ofs >> 4;
      par->parser.base64.decoded[1]  = (ofs & 0x0f) << 4;
      par->parser.base64.state = 2;
    } else if (par->parser.base64.state == 2) {
      par->parser.base64.decoded[1] |=  ofs >> 2;
      par->parser.base64.decoded[2]  = (ofs & 0x03) << 6;
      par->parser.base64.state = 3;
    } else if (par->parser.base64.state == 3) {
      par->parser.base64.decoded[2] |=  ofs;
      par->parser.base64.state = 0;
      if (par->parser.base64.length > sizeof(par->parser.base64.octets) - 3)
        goto too_big;
      memmove(
        &par->parser.base64.octets[par->parser.base64.length],
        &par->parser.base64.decoded[0], 3);
      par->parser.base64.length += 3;
    } else {
      break;
    }
  }

  //
  // We are done decoding Base-64 chars.  Let's see if we ended
  // on a byte boundary, and/or with erroneous trailing characters.
  //

  assert(ch == '\0' || ch == Pad64);
  if ((ch & 0xff) == Pad64) { // We got a pad char.
    switch (par->parser.base64.state) {
      case 0: // Invalid = in first position
      case 1: // Invalid = in second position
        goto bad_char;

      case 2: // Valid, means one byte of info
        par->parser.base64.state = 4;
        // FALLTHROUGH
      case 4:
        // Skip any number of spaces, count any pad characters.
        do {
          if (b64rmap[(uint8_t)ch & 0xff] == b64rmap_space)
            continue;
          if ((ch & 0xff) != Pad64 || ++par->parser.base64.pad > 2)
            goto bad_char;
        } while ((ch = zone_string_next(&tok->string, &cur, 0)) != '\0');

        break;

      case 3: // Valid, means two bytes of info
        par->parser.base64.state = 5;
        // FALLTHROUGH
      case 5:
        //
        // We know this char is an =.  Is there anything but
        // whitespace after it?
        //
        do {
          if (b64rmap[(uint8_t)ch & 0xff] == b64rmap_space)
            continue;
          if ((ch & 0xff) != Pad64 || ++par->parser.base64.pad > 1)
            goto bad_char;
        } while ((ch = zone_string_next(&tok->string, &cur, 0)) != '\0');

        break;
    }
  }

  return ZONE_DEFER_ACCEPT;
bad_char:
  SEMANTIC_ERROR(par, "Invalid sequence");
bad_escape:
  SEMANTIC_ERROR(par, "Bad escape sequence");
too_big:
  SEMANTIC_ERROR(par, "Base64 data is too big");
}
#endif // ZONE_BASE64_H
