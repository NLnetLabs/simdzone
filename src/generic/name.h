/*
 * name.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NAME_H
#define NAME_H

typedef struct name_block name_block_t;
struct name_block {
  uint64_t backslashes;
  uint64_t dots;
};

zone_nonnull_all
static zone_really_inline void copy_name_block(
  name_block_t *block, const char *text, uint8_t *wire)
{
  simd_8x32_t input;
  simd_loadu_8x32(&input, text);
  simd_storeu_8x32(wire, &input);
  block->backslashes = simd_find_8x32(&input, '\\');
  block->dots = simd_find_8x32(&input, '.');
}

#define likely(...) zone_likely(__VA_ARGS__)
#define unlikely(...) zone_unlikely(__VA_ARGS__)

zone_nonnull_all
static zone_really_inline int32_t scan_name(
  zone_parser_t *parser,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *lengthp)
{
  uint64_t label = 0;
  const char *text = token->data;
  uint8_t *wire = octets + 1;
  name_block_t block;

  (void)parser;

  octets[0] = 0;

  // real world domain names quickly exceed 16 octets (www.example.com is
  // encoded as 3www7example3com0, or 18 octets), but rarely exceed 32
  // octets. encode in 32-byte blocks.
  copy_name_block(&block, text, wire);

  uint64_t count = 32, length = 0, base = 0, left = token->length;
  uint64_t carry = 0;
  if (token->length < 32)
    count = token->length;
  uint64_t mask = (1llu << count) - 1u;

  // check for escape sequences
  if (unlikely(block.backslashes & mask))
    goto escaped;

  // check for root, i.e. "."
  if (unlikely(block.dots & 1llu))
    return ((*lengthp = token->length) == 1 ? 0 : -1);

  length = count;
  block.dots &= mask;
  carry = (block.dots >> (length - 1));

  // check for null labels, i.e. ".."
  if (unlikely(block.dots & (block.dots >> 1)))
    return -1;

  if (likely(block.dots)) {
    count = trailing_zeroes(block.dots);
    block.dots = clear_lowest_bit(block.dots);
    octets[label] = (uint8_t)count;
    label = count + 1;
    while (block.dots) {
      count = trailing_zeroes(block.dots);
      block.dots = clear_lowest_bit(block.dots);
      octets[label] = (uint8_t)(count - label);
      label = count + 1;
    }
  }

  octets[label] = (uint8_t)(length - label);

  if (length < 32)
    return (void)(*lengthp = length + 1), carry == 0;

  text += length;
  wire += length;
  left -= length;

  do {
    copy_name_block(&block, text, wire);
    count = 32;
    if (left < 32)
      count = left;
    mask = (1llu << count) - 1u;
    base = length;

    // check for escape sequences
    if (unlikely(block.backslashes & mask)) {
escaped:
      block.backslashes &= -block.backslashes;
      mask = block.backslashes - 1;
      block.dots &= mask;
      count = count_ones(mask);
      const uint32_t octet = unescape(text+count, wire+count);
      if (!octet)
        return -1;
      text += count + octet;
      wire += count + 1;
      length += count + 1;
    } else {
      block.dots &= mask;
      text += count;
      wire += count;
      length += count;
    }

    left -= count;

    // check for null labels, i.e. ".."
    if (unlikely(block.dots & ((block.dots >> 1) | carry)))
      return -1;
    carry = block.dots >> (count - 1);

    if (likely(block.dots)) {
      count = trailing_zeroes(block.dots) + base;
      block.dots = clear_lowest_bit(block.dots);
      octets[label] = (uint8_t)(count - label);
      // check if label exceeds 63 octets
      if (unlikely(count - label > 63))
        return -1;
      label = count + 1;
      while (block.dots) {
        count = trailing_zeroes(block.dots) + base;
        block.dots = clear_lowest_bit(block.dots);
        octets[label] = (uint8_t)(count - label);
        label = count + 1;
      }
    } else {
      // check if label exceeds 63 octets
      if (length - label > 63)
        return -1;
    }

    octets[label] = (uint8_t)(length - label);
  } while (left);

  *lengthp = length + 1;
  return carry == 0;
}

#undef likely
#undef unlikely

zone_nonnull_all
static zone_really_inline int32_t parse_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  size_t n = 0;
  uint8_t *o = &parser->rdata->octets[parser->rdata->length];

  if (zone_likely(token->code == CONTIGUOUS)) {
    // a freestanding "@" denotes the current origin
    if (token->data[0] == '@' && token->length == 1)
      goto relative;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r > 0)
      goto relative;
  } else if (token->code == QUOTED) {
    if (token->length == 0)
      goto invalid;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r > 0)
      goto relative;
  } else {
    return have_string(parser, type, field, token);
  }

invalid:
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

relative:
  if (n > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  memcpy(o+n, parser->file->origin.octets, parser->file->origin.length);
  parser->rdata->length += n + parser->file->origin.length;
  return ZONE_NAME;
}

#endif // NAME_H
