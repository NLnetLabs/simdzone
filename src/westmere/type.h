/*
 * type.h -- SSE4.1 RRTYPE parser
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TYPE_H
#define TYPE_H

#define T(code) { &(types[code].info.name), ZONE_TYPE }
#define C(code) { &(classes[code].name), ZONE_CLASS }

// map hash to type or class descriptor (generated using hash.c)
static const struct {
  const zone_symbol_t *symbol;
  int32_t type;
} types_and_classes[256] = {
    T(0),   T(0),   T(0),   T(0),   T(0),  T(44),   T(0),   T(3),
    T(0),   T(0),   T(0),   T(0),  T(11),   T(0),  T(42),   T(0),
    T(0),   T(0),   T(0),   T(0),   T(0),  T(62),   T(0),   T(0),
    T(0),  T(99),  T(25),   T(0),  T(53),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0),  T(50),   T(0),   T(0),   T(0),
    T(0),  T(39),   T(0),  T(21),   T(0),   T(5),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(1),   T(0),   T(0),
    C(1),   T(0), T(105),  T(49),   T(0),  T(59),   T(0),   T(29),
    T(0),  T(20),   T(0),   T(6),   T(0),   T(0),   T(0),   C(3),
    T(0),  T(63),   T(0),   T(0),   T(0),   C(2),  T(43),  T(37),
    T(0),   C(4),   T(0),   T(0),  T(45), T(104),   T(2),   T(0),
   T(23),  T(55),   T(0),  T(24),   T(0),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(7),   T(0),   T(0),   T(0),  T(12),
    T(0),   T(0),  T(60),   T(0),   T(0),  T(36),  T(10),  T(15),
    T(0),  T(26),   T(0),   T(0),  T(19),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),  T(65),   T(0),   T(8),   T(0), T(108),
    T(0),  T(38),   T(0),   T(9),   T(0),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0),  T(46),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(0),  T(27),  T(48),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),
    T(0),   T(0),  T(28),   T(4),  T(51),   T(0),   T(0),  T(30),
    T(0), T(106),   T(0),   T(0),  T(16),  T(64),   T(0),   T(0),
    T(0),   T(0), T(257),   T(0),   T(0),   T(0),   T(0),   T(0),
  T(256),   T(0),   T(0),   T(0),   T(0),  T(22),   T(0),   T(0),
    T(0),  T(33),   T(0),  T(61),   T(0),  T(52),   T(0),   T(0),
  T(259),   T(0),   T(0),   T(0),  T(14),   T(0),   T(0),   T(0),
   T(13),   T(0),   T(0),   T(0),   T(0),   T(0), T(107),   T(0),
    T(0),  T(18),   T(0),  T(17),   T(0),   T(0),  T(35),   T(0),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),   T(0),
    T(0),   T(0),   T(0),   T(0), T(258),   T(0),   T(0), T(109),
    T(0),   T(0),   T(0),   T(0),   T(0),   T(0),  T(47),   T(0)
};

#undef T
#undef C

static int8_t zero_masks[32] = {
   0,   0,   0,   0,   0,   0,   0,   0,
   0,   0,   0,   0,   0,   0,   0,   0,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

static zone_really_inline uint8_t hash(uint64_t prefix)
{
  uint32_t value = (uint32_t)((prefix >> 32) ^ prefix);
  // magic value is generated using hash.c, rerun when adding types
  return (uint8_t)((value * 3523264710ull) >> 32);
}

zone_nonnull_all
static zone_really_inline int32_t find_type_or_class(
  zone_parser_t *parser,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  (void)parser;

  __m128i input = _mm_loadu_si128((const __m128i *)token->data);

  // RRTYPEs consist of [0-9a-zA-Z-] (unofficially, no other values are in use)
  // 0x2d        : hyphen : 0b0010_1101
  // 0x30 - 0x39 :  0 - 9 : 0b0011_0000 - 0b0011_1001
  // 0x41 - 0x4f :  A - O : 0b0100_0001 - 0b0100_1111
  // 0x50 - 0x5a :  P - Z : 0b0101_0000 - 0b0101_1010
  // 0x61 - 0x6f :  a - o : 0b0110_0001 - 0b0110_1111
  // 0x70 - 0x7a :  p - z : 0b0111_0000 - 0b0111_1010
  //
  // delimiters for strings consisting of a contiguous set of characters
  // 0x00        :       end-of-file : 0b0000_0000
  // 0x20        :             space : 0b0010_0000
  // 0x22        :             quote : 0b0010_0010
  // 0x28        :  left parenthesis : 0b0010_1000
  // 0x29        : right parenthesis : 0b0010_1001
  // 0x09        :               tab : 0b0000_1001
  // 0x0a        :         line feed : 0b0000_1010
  // 0x3b        :         semicolon : 0b0011_1011
  // 0x0d        :   carriage return : 0b0000_1101
  //
  // deltas do not catch ('.' (0x2e) or '/' (0x2f)), but neither is a delimiter
  //const __m128i deltas = _mm_setr_epi8(
  //  -16, -32, -45, 70, -65, 37, -97, 5, 0, 0, 0, 0, 0, 0, 0, 0);
  const __m128i nibbles = _mm_and_si128(_mm_srli_epi32(input, 4), _mm_set1_epi8(0x0f));
  //const __m128i check = _mm_add_epi8(_mm_shuffle_epi8(deltas, nibbles), input);

  //int mask = (uint16_t)_mm_movemask_epi8(check);
  //uint16_t length = (uint16_t)__builtin_ctz((unsigned int)mask);

  const __m128i upper = _mm_setr_epi8(
    -1, -1, -1, -1, -1, -1, -33, -33, -1, -1, -1, -1, -1, -1, -1, -1);

  __m128i zero_mask;
  //if (token->length > 16)
  //  zero_mask = _mm_loadu_si128((const __m128i *)zero_masks);
  //else
    zero_mask = _mm_loadu_si128((const __m128i *)(zero_masks + 16 - token->length));
  input = _mm_and_si128(input, _mm_shuffle_epi8(upper, nibbles));
  input = _mm_andnot_si128(zero_mask, input);

  // input is now sanitized and upper case

  const uint8_t index = hash((uint64_t)_mm_cvtsi128_si64(input));
  *symbol = types_and_classes[index].symbol;

  const __m128i compar = _mm_loadu_si128((const __m128i *)(*symbol)->key.data);
  const __m128i xorthem = _mm_xor_si128(compar, input);

  *code = (uint16_t)(*symbol)->value;

  //const uint8_t delimiter = (uint8_t)token->data[token->length];
  if (_mm_test_all_zeros(xorthem, xorthem))// & (contiguous[delimiter] != CONTIGUOUS))
    return types_and_classes[index].type;
  return 0;
}

zone_nonnull_all
static zone_really_inline int32_t scan_generic_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  const char *ps = token->data + 4, *p = ps;
  uint64_t n = 0;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > 65535 || p - ps > 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *code = (uint16_t)n;
  if (*code <= 258)
    *symbol = &types[*code].info.name;
  else if (*code == ZONE_DLV)
    *symbol = &types[259].info.name;
  else
    *symbol = &types[0].info.name;
  return ZONE_TYPE;
}

zone_nonnull_all
static zone_really_inline int32_t scan_generic_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  const char *ps = token->data + 5, *p = ps;
  uint64_t n = 0;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > 65535 || p - ps >= 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *code = (uint16_t)n;
  if (*code <= 4)
    *symbol = &classes[*code].name;
  else
    *symbol = &classes[0].name;
  return ZONE_CLASS;
}

#define TYPE (0x45505954llu)
#define CLASS (0x5353414c43llu)

zone_nonnull_all
static zone_really_inline int32_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;
  if ((r = find_type_or_class(parser, token, code, symbol)))
    return r;

  uint64_t k;
  memcpy(&k, token->data, 8);
  if ((k & 0xdfdfdfdfllu) == TYPE)
    return scan_generic_type(parser, type, field, token, code, symbol);
  else if ((k & 0xdfdfdfdfdfllu) == CLASS)
    return scan_generic_class(parser, type, field, token, code, symbol);

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
}

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;
  if ((r = find_type_or_class(parser, token, code, symbol)) == ZONE_TYPE)
    return r;

  uint64_t k;
  memcpy(&k, token->data, 8);
  if ((k & 0xdfdfdfdfllu) == TYPE)
    return scan_generic_type(parser, type, field, token, code, symbol);

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
}

#undef TYPE
#undef CLASS

zone_nonnull_all
static zone_really_inline int32_t parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  uint16_t c;
  const zone_symbol_t *s;

  if ((r = scan_type(parser, type, field, token, &c, &s)) != ZONE_TYPE)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  c = htons(c);
  memcpy(&parser->rdata->octets[parser->rdata->length], &c, sizeof(c));
  parser->rdata->length += sizeof(c);
  return ZONE_TYPE;
}

#endif // TYPE_H
