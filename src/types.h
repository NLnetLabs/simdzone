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
static inline size_t min(size_t x, size_t y)
{
  return y ^ ((x ^ y) & -(x < y));
}

zone_always_inline()
static inline uint64_t load_64(const char *ptr)
{
  uint64_t x;
  memcpy(&x, ptr, sizeof(x));
#ifdef __BIG_ENDIAN__
  x = __builtin_bswap32(x);
#endif
  return x;
}

zone_always_inline()
static inline zone_return_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_field_info_t *info,
  const zone_token_t *token,
  uint16_t *code)
{
  static const uint64_t mask[6] = {
    0u, 0xdfu, 0xdfdfu, 0xdfdfdfu, 0xdfdfdfdfu, 0xdfdfdfdfdfu };

  const size_t length = min(token->string.length, 8u);
  uint64_t prefix = load_64(token->string.data); // assume buffer is padded
  prefix &= mask[length]; // convert to upper case and zero out padding

  const zone_hash_map_t *map = &zone_type_class_map[((prefix & 0xff) - 'A') & 0x1fu];

  uint8_t key = (uint8_t)token->string.length;
  key += ((prefix >> map->shift[0]) & 0xff) +
         ((prefix >> map->shift[1]) & 0xff);

  vector8x16_t keys;
  load_8x16(&keys, map->keys);
  const uint64_t bits = find_8x16(&keys, key) | (1u << 15);
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
  if (prefix >> 32 == 0x69808984 && token->string.length > 4) {
    item = ZONE_TYPE;
    i = 4;
  } else if (prefix >> 24 == 0x8383647667 && token->string.length > 5) {
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
  static const uint64_t mask[6] = {
    0u, 0xdfu, 0xdfdfu, 0xdfdfdfu, 0xdfdfdfdfu, 0xdfdfdfdfdfu };

  const size_t length = min(token->string.length, 5u);
  uint64_t prefix = load_64(token->string.data); // assume buffer is padded
  prefix &= mask[length]; // convert to upper case and zero out padding

  const zone_hash_map_t *map = &zone_type_class_map[((prefix & 0xff) - 'A') & 0x1fu];

  uint8_t key = (uint8_t)token->string.length;
  key += ((prefix >> map->shift[0]) & 0xff) +
         ((prefix >> map->shift[1]) & 0xff);

  vector8x16_t keys;
  load_8x16(&keys, map->keys);
  const uint64_t bits = find_8x16(&keys, key) | (1u << 15);
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
  if (prefix >> 32 == 0x69808984 && token->string.length > 4)
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
