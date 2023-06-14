/*
 * ip4.h -- SSE 4.1 parser for IPv4 addresses
 *          https://lemire.me/blog/2023/06/08/parsing-ip-addresses-crazily-fast/
 *
 * Copyright (c) 2023. Daniel Lemire
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef IP4_H
#define IP4_H

static const uint8_t patterns_id[256] = {
    38,  65,  255, 56,  73,  255, 255, 255, 255, 255, 255, 3,   255, 255, 6,
    255, 255, 9,   255, 27,  255, 12,  30,  255, 255, 255, 255, 15,  255, 33,
    255, 255, 255, 255, 18,  36,  255, 255, 255, 54,  21,  255, 39,  255, 255,
    57,  255, 255, 255, 255, 255, 255, 255, 255, 24,  42,  255, 255, 255, 60,
    255, 255, 255, 255, 255, 255, 255, 255, 45,  255, 255, 63,  255, 255, 255,
    255, 255, 255, 255, 255, 255, 48,  53,  255, 255, 66,  71,  255, 255, 16,
    255, 34,  255, 255, 255, 255, 255, 255, 255, 52,  255, 255, 22,  70,  40,
    255, 255, 58,  51,  255, 255, 69,  255, 255, 255, 255, 255, 255, 255, 255,
    255, 5,   255, 255, 255, 255, 255, 255, 11,  29,  46,  255, 255, 64,  255,
    255, 72,  0,   77,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 76,  255, 255, 255, 255, 255, 255, 255, 75,  255,
    80,  255, 255, 255, 26,  255, 44,  255, 7,   62,  255, 255, 25,  255, 43,
    13,  31,  61,  255, 255, 255, 255, 255, 255, 255, 255, 255, 2,   19,  37,
    255, 255, 50,  55,  79,  68,  255, 255, 255, 255, 49,  255, 255, 67,  255,
    255, 255, 255, 17,  255, 35,  78,  255, 4,   255, 255, 255, 255, 255, 255,
    10,  23,  28,  41,  255, 255, 59,  255, 255, 255, 8,   255, 255, 255, 255,
    255, 1,   14,  32,  255, 255, 255, 255, 255, 255, 255, 255, 74,  255, 47,
    20,
};

static const uint8_t patterns[81][16] = {
  {0, 128, 2, 128, 4, 128, 6, 128, 128, 128, 128, 128, 128, 128, 128, 128},
  {0, 128, 2, 128, 4, 128, 7, 6, 128, 128, 128, 128, 128, 128, 128, 6},
  {0, 128, 2, 128, 4, 128, 8, 7, 128, 128, 128, 128, 128, 128, 6, 6},
  {0, 128, 2, 128, 5, 4, 7, 128, 128, 128, 128, 128, 128, 4, 128, 128},
  {0, 128, 2, 128, 5, 4, 8, 7, 128, 128, 128, 128, 128, 4, 128, 7},
  {0, 128, 2, 128, 5, 4, 9, 8, 128, 128, 128, 128, 128, 4, 7, 7},
  {0, 128, 2, 128, 6, 5, 8, 128, 128, 128, 128, 128, 4, 4, 128, 128},
  {0, 128, 2, 128, 6, 5, 9, 8, 128, 128, 128, 128, 4, 4, 128, 8},
  {0, 128, 2, 128, 6, 5, 10, 9, 128, 128, 128, 128, 4, 4, 8, 8},
  {0, 128, 3, 2, 5, 128, 7, 128, 128, 128, 128, 2, 128, 128, 128, 128},
  {0, 128, 3, 2, 5, 128, 8, 7, 128, 128, 128, 2, 128, 128, 128, 7},
  {0, 128, 3, 2, 5, 128, 9, 8, 128, 128, 128, 2, 128, 128, 7, 7},
  {0, 128, 3, 2, 6, 5, 8, 128, 128, 128, 128, 2, 128, 5, 128, 128},
  {0, 128, 3, 2, 6, 5, 9, 8, 128, 128, 128, 2, 128, 5, 128, 8},
  {0, 128, 3, 2, 6, 5, 10, 9, 128, 128, 128, 2, 128, 5, 8, 8},
  {0, 128, 3, 2, 7, 6, 9, 128, 128, 128, 128, 2, 5, 5, 128, 128},
  {0, 128, 3, 2, 7, 6, 10, 9, 128, 128, 128, 2, 5, 5, 128, 9},
  {0, 128, 3, 2, 7, 6, 11, 10, 128, 128, 128, 2, 5, 5, 9, 9},
  {0, 128, 4, 3, 6, 128, 8, 128, 128, 128, 2, 2, 128, 128, 128, 128},
  {0, 128, 4, 3, 6, 128, 9, 8, 128, 128, 2, 2, 128, 128, 128, 8},
  {0, 128, 4, 3, 6, 128, 10, 9, 128, 128, 2, 2, 128, 128, 8, 8},
  {0, 128, 4, 3, 7, 6, 9, 128, 128, 128, 2, 2, 128, 6, 128, 128},
  {0, 128, 4, 3, 7, 6, 10, 9, 128, 128, 2, 2, 128, 6, 128, 9},
  {0, 128, 4, 3, 7, 6, 11, 10, 128, 128, 2, 2, 128, 6, 9, 9},
  {0, 128, 4, 3, 8, 7, 10, 128, 128, 128, 2, 2, 6, 6, 128, 128},
  {0, 128, 4, 3, 8, 7, 11, 10, 128, 128, 2, 2, 6, 6, 128, 10},
  {0, 128, 4, 3, 8, 7, 12, 11, 128, 128, 2, 2, 6, 6, 10, 10},
  {1, 0, 3, 128, 5, 128, 7, 128, 128, 0, 128, 128, 128, 128, 128, 128},
  {1, 0, 3, 128, 5, 128, 8, 7, 128, 0, 128, 128, 128, 128, 128, 7},
  {1, 0, 3, 128, 5, 128, 9, 8, 128, 0, 128, 128, 128, 128, 7, 7},
  {1, 0, 3, 128, 6, 5, 8, 128, 128, 0, 128, 128, 128, 5, 128, 128},
  {1, 0, 3, 128, 6, 5, 9, 8, 128, 0, 128, 128, 128, 5, 128, 8},
  {1, 0, 3, 128, 6, 5, 10, 9, 128, 0, 128, 128, 128, 5, 8, 8},
  {1, 0, 3, 128, 7, 6, 9, 128, 128, 0, 128, 128, 5, 5, 128, 128},
  {1, 0, 3, 128, 7, 6, 10, 9, 128, 0, 128, 128, 5, 5, 128, 9},
  {1, 0, 3, 128, 7, 6, 11, 10, 128, 0, 128, 128, 5, 5, 9, 9},
  {1, 0, 4, 3, 6, 128, 8, 128, 128, 0, 128, 3, 128, 128, 128, 128},
  {1, 0, 4, 3, 6, 128, 9, 8, 128, 0, 128, 3, 128, 128, 128, 8},
  {1, 0, 4, 3, 6, 128, 10, 9, 128, 0, 128, 3, 128, 128, 8, 8},
  {1, 0, 4, 3, 7, 6, 9, 128, 128, 0, 128, 3, 128, 6, 128, 128},
  {1, 0, 4, 3, 7, 6, 10, 9, 128, 0, 128, 3, 128, 6, 128, 9},
  {1, 0, 4, 3, 7, 6, 11, 10, 128, 0, 128, 3, 128, 6, 9, 9},
  {1, 0, 4, 3, 8, 7, 10, 128, 128, 0, 128, 3, 6, 6, 128, 128},
  {1, 0, 4, 3, 8, 7, 11, 10, 128, 0, 128, 3, 6, 6, 128, 10},
  {1, 0, 4, 3, 8, 7, 12, 11, 128, 0, 128, 3, 6, 6, 10, 10},
  {1, 0, 5, 4, 7, 128, 9, 128, 128, 0, 3, 3, 128, 128, 128, 128},
  {1, 0, 5, 4, 7, 128, 10, 9, 128, 0, 3, 3, 128, 128, 128, 9},
  {1, 0, 5, 4, 7, 128, 11, 10, 128, 0, 3, 3, 128, 128, 9, 9},
  {1, 0, 5, 4, 8, 7, 10, 128, 128, 0, 3, 3, 128, 7, 128, 128},
  {1, 0, 5, 4, 8, 7, 11, 10, 128, 0, 3, 3, 128, 7, 128, 10},
  {1, 0, 5, 4, 8, 7, 12, 11, 128, 0, 3, 3, 128, 7, 10, 10},
  {1, 0, 5, 4, 9, 8, 11, 128, 128, 0, 3, 3, 7, 7, 128, 128},
  {1, 0, 5, 4, 9, 8, 12, 11, 128, 0, 3, 3, 7, 7, 128, 11},
  {1, 0, 5, 4, 9, 8, 13, 12, 128, 0, 3, 3, 7, 7, 11, 11},
  {2, 1, 4, 128, 6, 128, 8, 128, 0, 0, 128, 128, 128, 128, 128, 128},
  {2, 1, 4, 128, 6, 128, 9, 8, 0, 0, 128, 128, 128, 128, 128, 8},
  {2, 1, 4, 128, 6, 128, 10, 9, 0, 0, 128, 128, 128, 128, 8, 8},
  {2, 1, 4, 128, 7, 6, 9, 128, 0, 0, 128, 128, 128, 6, 128, 128},
  {2, 1, 4, 128, 7, 6, 10, 9, 0, 0, 128, 128, 128, 6, 128, 9},
  {2, 1, 4, 128, 7, 6, 11, 10, 0, 0, 128, 128, 128, 6, 9, 9},
  {2, 1, 4, 128, 8, 7, 10, 128, 0, 0, 128, 128, 6, 6, 128, 128},
  {2, 1, 4, 128, 8, 7, 11, 10, 0, 0, 128, 128, 6, 6, 128, 10},
  {2, 1, 4, 128, 8, 7, 12, 11, 0, 0, 128, 128, 6, 6, 10, 10},
  {2, 1, 5, 4, 7, 128, 9, 128, 0, 0, 128, 4, 128, 128, 128, 128},
  {2, 1, 5, 4, 7, 128, 10, 9, 0, 0, 128, 4, 128, 128, 128, 9},
  {2, 1, 5, 4, 7, 128, 11, 10, 0, 0, 128, 4, 128, 128, 9, 9},
  {2, 1, 5, 4, 8, 7, 10, 128, 0, 0, 128, 4, 128, 7, 128, 128},
  {2, 1, 5, 4, 8, 7, 11, 10, 0, 0, 128, 4, 128, 7, 128, 10},
  {2, 1, 5, 4, 8, 7, 12, 11, 0, 0, 128, 4, 128, 7, 10, 10},
  {2, 1, 5, 4, 9, 8, 11, 128, 0, 0, 128, 4, 7, 7, 128, 128},
  {2, 1, 5, 4, 9, 8, 12, 11, 0, 0, 128, 4, 7, 7, 128, 11},
  {2, 1, 5, 4, 9, 8, 13, 12, 0, 0, 128, 4, 7, 7, 11, 11},
  {2, 1, 6, 5, 8, 128, 10, 128, 0, 0, 4, 4, 128, 128, 128, 128},
  {2, 1, 6, 5, 8, 128, 11, 10, 0, 0, 4, 4, 128, 128, 128, 10},
  {2, 1, 6, 5, 8, 128, 12, 11, 0, 0, 4, 4, 128, 128, 10, 10},
  {2, 1, 6, 5, 9, 8, 11, 128, 0, 0, 4, 4, 128, 8, 128, 128},
  {2, 1, 6, 5, 9, 8, 12, 11, 0, 0, 4, 4, 128, 8, 128, 11},
  {2, 1, 6, 5, 9, 8, 13, 12, 0, 0, 4, 4, 128, 8, 11, 11},
  {2, 1, 6, 5, 10, 9, 12, 128, 0, 0, 4, 4, 8, 8, 128, 128},
  {2, 1, 6, 5, 10, 9, 13, 12, 0, 0, 4, 4, 8, 8, 128, 12},
  {2, 1, 6, 5, 10, 9, 14, 13, 0, 0, 4, 4, 8, 8, 12, 12},
};


// convert IPv4 from text to binary form.
//
// ipv4_string points to a character string containing an IPv4 network address in dotted-decimal format
// "ddd.ddd.ddd.ddd" of length ipv4_string_length (the string does not have to be null terminated),
// where ddd is a decimal number of up to three digits in the range 0 to 255. 
// The address is converted to a 32-bit integer (destination) (in  network byte order).
//
// Important: the function will systematically read 16 bytes at the provided address (ipv4_string). However,
// only the first ipv4_string_length bytes are processed.
//
// returns 1 on success (network address was successfully converted).
//
// This function assumes that the processor supports SSE 4.1 instructions or better. That's true of most
// processors in operation today (June 2023).
//
// See also sse_inet_aton_16 for a version that does not take a string length.
static inline int sse_inet_aton(const char* ipv4_string, const size_t ipv4_string_length, uint8_t * destination) {
  // This function always reads 16 bytes. With AVX-512 we can do a mask
  // load, but it is not generally available with SSE 4.1.
  const __m128i input = _mm_loadu_si128((const __m128i *)ipv4_string);
  if (ipv4_string_length > 15) {
    return 0;
  }
  // locate dots
  uint16_t dotmask;
  {
    const __m128i dot = _mm_set1_epi8('.');
    const __m128i t0 = _mm_cmpeq_epi8(input, dot);
    dotmask = (uint16_t)_mm_movemask_epi8(t0);
    uint16_t mask = (uint16_t)(1 << ipv4_string_length);
    dotmask &= mask - 1;
    dotmask |= mask;
  }

  // build a hashcode
  const uint8_t hashcode = ((6639 * dotmask) >> 13);

  // grab the index of the shuffle mask
  const uint8_t id = patterns_id[hashcode];
  if (id >= 81) {
    return 0;
  }
  const uint8_t *pat = &patterns[id][0];
  const __m128i pattern = _mm_loadu_si128((const __m128i *)pat);
  // The value of the shuffle mask at a specific index points at the last digit,
  // we check that it matches the length of the input.
  const __m128i ascii0 = _mm_set1_epi8('0');
  const __m128i t0 = input;
  __m128i t1 = _mm_shuffle_epi8(t0, pattern);
  // check that leading digits of 2- 3- numbers are not zeros.
  {
    const __m128i eq0 = _mm_cmpeq_epi8(t1, ascii0);
    if (!_mm_testz_si128(eq0, _mm_set_epi8(-1, 0, -1, 0, -1, 0, -1, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0))) {
      return 0;
    }
  }
  // replace null values with '0'
  __m128i t1b = _mm_blendv_epi8(t1, ascii0, pattern);

  // subtract '0'
  const __m128i t2 = _mm_sub_epi8(t1b, ascii0);
  // check that everything was in the range '0' to '9'
  {
    const __m128i c9 = _mm_set1_epi8('9' - '0');
    const __m128i t2m = _mm_max_epu8(t2, c9);
    const __m128i t2me = _mm_cmpeq_epi8(t2m, c9);
    if (!_mm_test_all_ones(t2me)) {
      return 0;
    }
  }
  // We do the computation, the Mula way.
  const __m128i weights =
      _mm_setr_epi8(1, 10, 1, 10, 1, 10, 1, 10, 100, 0, 100, 0, 100, 0, 100, 0);
  const __m128i t3 = _mm_maddubs_epi16(t2, weights);
  const __m128i t4 = _mm_alignr_epi8(t3, t3, 8);
  const __m128i t5 = _mm_add_epi16(t4, t3);
  // Test that we don't overflow (over 255)
  if (!_mm_testz_si128(t5, _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1,
                                        0, -1, 0, -1, 0))) {
    return 0;
  }
  // pack and we are done!
  const __m128i t6 = _mm_packus_epi16(t5, t5);
  uint32_t address =  (uint32_t)_mm_cvtsi128_si32(t6);
  memcpy(destination, &address, 4);
  return (int)(ipv4_string_length - (size_t)pat[6]);
}

// convert IPv4 from text to binary form.
//
// ipv4_string points to a character string containing an IPv4 network address in dotted-decimal format
// "ddd.ddd.ddd.ddd" of length ipv4_string_length (the string does not have to be null terminated),
// where ddd is a decimal number of up to three digits in the range 0 to 255. 
// The address is converted to a 32-bit integer (destination) (in  network byte order).
//
// Important: the function will systematically read 16 bytes at the provided address (ipv4_string). We infer
// the network address size in bytes by looking for a sequence of dots and decimal digits.
//
// returns 1 on success (network address was successfully converted).
//
// This function assumes that the processor supports SSE 4.1 instructions or better. That's true of most
// processors in operation today (June 2023).
//
// See also sse_inet_aton for a version that takes a string length
static inline int sse_inet_aton_16(const char* ipv4_string, uint8_t * destination) {
  const __m128i input = _mm_loadu_si128((const __m128i *)ipv4_string);
  const __m128i dot = _mm_set1_epi8('.');
  // locate dots
  uint16_t dotmask;
  int ipv4_string_length;
  {
    const __m128i ascii0_9 = _mm_setr_epi8(
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0, 0, 0, 0, 0, 0);
    const __m128i digits = _mm_cmpeq_epi8(input, _mm_shuffle_epi8(ascii0_9, input));
    
    const __m128i t0 = _mm_cmpeq_epi8(input, dot);
    dotmask = (uint16_t)_mm_movemask_epi8(t0);
    const uint16_t digit_mask = (uint16_t)_mm_movemask_epi8(digits);
    uint16_t m = digit_mask | dotmask;
    // credit @aqrit
    m ^= (m + 1); // mask of lowest clear bit and below
    dotmask = ~digit_mask & m;
    ipv4_string_length = __builtin_popcount(m) - 1;
  }
  // build a hashcode
  const uint8_t hashcode = (uint8_t)((6639 * dotmask) >> 13);
  // grab the index of the shuffle mask
  const uint8_t id = patterns_id[hashcode];
  if (id >= 81) {
    return 0;
  }
  const uint8_t *pat = &patterns[id][0];

  const __m128i pattern = _mm_loadu_si128((const __m128i *)pat);
  // The value of the shuffle mask at a specific index points at the last digit,
  // we check that it matches the length of the input.
  const __m128i ascii0 = _mm_set1_epi8('0');
  const __m128i t0 = input;

  __m128i t1 = _mm_shuffle_epi8(t0, pattern);
  // check that leading digits of 2- 3- numbers are not zeros.
  {
    const __m128i eq0 = _mm_cmpeq_epi8(t1, ascii0);
    if (!_mm_testz_si128(eq0, _mm_set_epi8(-1, 0, -1, 0, -1, 0, -1, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0))) {
      return 0;
    }
  }

  // subtract '0'
  const __m128i t2 = _mm_subs_epu8(t1, ascii0);
  // check that there is no dot
  {
    const __m128i t2me = _mm_cmpeq_epi8(t1, dot);
    if (!_mm_test_all_zeros(t2me, t2me)) {
      return 0;
    }
  }
  // We do the computation, the Mula way.
  const __m128i weights =
      _mm_setr_epi8(1, 10, 1, 10, 1, 10, 1, 10, 100, 0, 100, 0, 100, 0, 100, 0);
  const __m128i t3 = _mm_maddubs_epi16(t2, weights);
  // In t3, we have 8 16-bit values, the first four combine the two first digits, and
  // the 4 next 16-bit valued are made of the third digits.
  const __m128i t4 = _mm_alignr_epi8(t3, t3, 8);
  const __m128i t5 = _mm_add_epi16(t4, t3);
  // Test that we don't overflow (over 255)
  if (!_mm_testz_si128(t5, _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1,
                                        0, -1, 0, -1, 0))) {
    return 0;
  }
  // pack and we are done!
  const __m128i t6 = _mm_packus_epi16(t5, t5);
  uint32_t address =  (uint32_t)_mm_cvtsi128_si32(t6);
  memcpy(destination, &address, 4);
  return (ipv4_string_length - (int)pat[6]);
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_ip4(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  if (token->length > INET_ADDRSTRLEN)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  // Note that this assumes that reading up to token->data + 16 is safe (i.e., we do not cross a page).
  if (sse_inet_aton_16(token->data, &parser->rdata->octets[parser->rdata->length]) != 1)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  parser->rdata->length += sizeof(struct in_addr);
}

#endif // IP4_H
