/*
 * types.h -- some useful description
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdint.h>
#include <string.h>

//
// we want to recognize the record type really fast because it's guarantueed
// to be required for every entry!!!
//   >> the number of record types isn't very long, but going over a list
//      just isn't that fast. instead we apply sort-of a radix tree lookup
//      we first look at the starting character and then apply a "hashing"
//      algorithm so we can do a simd lookup. using a generic hashing
//      function is problematic because the chance of collisions is relatively
//      high with only 8-bits. because the list is so small though, we can
//      hand code figuring out the unique key per letter.
//      for some the length is unique enough, others require some more logic...
//      >> we don't care about being as unique as possible, only unique enough
//         to distinguish between record types. a string compare is always
//         required!
//

//
// instead of the type code, we should include the descriptor when
// parsing the ttl+class+type thingy!
//   >> yes, because we need to do the string compare too!
//

extern const zone_type_info_t *zone_types;
extern const size_t zone_type_count;

extern const zone_class_info_t *zone_classes;
extern const size_t zone_class_count;

extern const zone_hash_map_t *zone_type_class_map;

// FIXME: scan_type and scan_class_or_type require generic implementations

zone_always_inline()
static inline uint8_t subs(uint8_t x, uint8_t y)
{
  uint8_t res = x - y;
  res &= -(res <= x);
  return res;
}

zone_always_inline()
static inline zone_return_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->string.length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->string.data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->string.data[n] & 0xdf);
  h *= 0x07;
  h += n;

  const zone_hash_map_t *map = &zone_type_class_map[k];

  vector8x16_t keys;
  load_8x16(&keys, map->keys);
  const uint64_t bits = find_8x16(&keys, h) | (1u << 15);
  assert(bits);
  const uint64_t slot = trailing_zeroes(bits);
  assert(slot <= 15);
  const zone_string_t *name = map->objects[slot];

  if (token->string.length == name->length &&
      strncasecmp(token->string.data, name->data, name->length) == 0)
  {
    uintptr_t start, end;

    start = (uintptr_t)zone_types;
    end = (uintptr_t)(zone_types + zone_type_count);
    if ((uintptr_t)name > start && (uintptr_t)name < end) {
      *code = ((const zone_type_info_t *)name)->code;
      return ZONE_TYPE;
    }

    start = (uintptr_t)zone_classes;
    end = (uintptr_t)(zone_classes + zone_class_count);
    if ((uintptr_t)name > start && (uintptr_t)name < end) {
      *code = ((const zone_class_info_t *)name)->code;
      return ZONE_CLASS;
    }
  }

  size_t i = 0;
  zone_return_t item;
  if (token->string.length > 4 && strncasecmp(token->string.data, "TYPE", 4) == 0) {
    item = ZONE_TYPE;
    i = 4;
  } else if (token->string.length > 5 && strncasecmp(token->string.data, "CLASS", 5) == 0) {
    item = ZONE_CLASS;
    i = 5;
  } else {
    SEMANTIC_ERROR(parser, "Invalid type or class in %s", info->name.data);
  }

  uint64_t v = 0;
  for (; i < token->string.length; i++) {
    const uint64_t n = (uint8_t)token->string.data[0] - '0' > 9;
    if (n > 9)
      SEMANTIC_ERROR(parser, "Invalid type or class in %s", info->name.data);
    v = v * 10 + n;
    if (v > UINT16_MAX)
      SEMANTIC_ERROR(parser, "Invalid type or class in %s", info->name.data);
  }

  *code = (uint16_t)v;
  return item;
}

zone_always_inline()
static inline zone_return_t scan_type(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  const zone_token_t *token,
  uint16_t *code)
{
  const uint8_t n = subs(token->string.length & 0xdf, 0x01);
  uint8_t k = ((uint8_t)(token->string.data[0] & 0xdf) - 0x41) & 0x1f;
  uint8_t h = (token->string.data[n] & 0xdf);
  h *= 0x07;
  h += n;

  const zone_hash_map_t *map = &zone_type_class_map[k];

  vector8x16_t keys;
  load_8x16(&keys, map->keys);
  const uint64_t bits = find_8x16(&keys, h) | (1u << 15);
  assert(bits);
  const uint64_t slot = trailing_zeroes(bits);
  assert(slot <= 15);
  const zone_string_t *name = map->objects[slot];

  if (token->string.length == name->length &&
      strncasecmp(token->string.data, name->data, name->length) == 0)
  {
    uintptr_t start, end;

    start = (uintptr_t)zone_types;
    end = (uintptr_t)(zone_types + zone_type_count);
    if ((uintptr_t)name > start && (uintptr_t)name < end) {
      *code = ((const zone_type_info_t *)name)->code;
      return ZONE_TYPE;
    }
  }

  zone_return_t item;
  if (token->string.length > 4 && strncasecmp(token->string.data, "TYPE", 4) == 0)
    item = ZONE_TYPE;
  else
    SEMANTIC_ERROR(parser, "Invalid type in %s", info->name.data);

  uint64_t v = 0;
  for (size_t i=4; i < token->string.length; i++) {
    const uint64_t n = (uint8_t)token->string.data[0] - '0' > 9;
    if (n > 9)
      SEMANTIC_ERROR(parser, "Invalid type in %s", info->name.data);
    v = v * 10 + n;
    if (v > UINT16_MAX)
      SEMANTIC_ERROR(parser, "Invalid type in %s", info->name.data);
  }

  *code = (uint16_t)v;
  return item;
}
