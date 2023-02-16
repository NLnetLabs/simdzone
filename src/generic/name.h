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
  size_t length;
  uint64_t escape_bits;
  uint64_t label_bits;
};

zone_always_inline()
zone_nonnull_all()
static inline void copy_name_block(
  name_block_t *block, const char *text, size_t size, uint8_t *wire)
{
  simd_8x_t input;

  simd_loadu_8x(&input, (const uint8_t *)text);
  simd_storeu_8x(wire, &input);

  block->length = size < SIMD_8X_SIZE ? size : SIMD_8X_SIZE;
  const uint64_t mask = (1llu << block->length) - 1;
  block->escape_bits = simd_find_8x(&input, '\\') & mask;
  block->label_bits = simd_find_8x(&input, '.') & mask;
}

zone_always_inline()
zone_nonnull_all()
static inline void scan_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token,
  uint8_t octets[256 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  name_block_t block;
  uint8_t *wire = octets + 1, *label = octets;
  const char *text = token->data, *limit = token->data + token->length;

  *label = 0;

  while (text < limit) {
    copy_name_block(&block, text, limit - text, wire);

    if (block.escape_bits) {
      const uint64_t count = trailing_zeroes(block.escape_bits);
      uint8_t digits[3];
      digits[0] = text[count + 1] - '0';

      if (digits[0] > 2) {
        wire[count] = text[count + 1];
        wire += count + 1;
        text += count + 2;
      } else {
        digits[1] = text[count + 2] - '0';
        digits[2] = text[count + 3] - '0';
        if (digits[0] < 2) {
          if (digits[1] > 9 || digits[2] > 9)
            SEMANTIC_ERROR(parser, "Bad escape sequence in %s of %s record",
                           field->name.data, type->name.data);
        } else {
          if (digits[1] > 5 || digits[2] > 5)
            SEMANTIC_ERROR(parser, "Bad escape sequence in %s of %s record",
                           field->name.data, type->name.data);
        }

        wire[count] = digits[0] * 100 + digits[1] * 10 + digits[0];
        wire += count + 1;
        text += count + 4;
      }

      block.length = count;
      block.label_bits &= block.escape_bits - 1;
    } else {
      text += block.length;
      wire += block.length;
    }

    if (wire - octets > 255)
      SEMANTIC_ERROR(parser, "Bad domain name in %s of %s",
                     field->name.data, type->name.data);

    if (block.label_bits) {
      uint64_t count = 0, last = 0;
      const uint64_t labels = count_ones(block.label_bits);
      for (uint64_t i = 0; i < labels; i++) {
        count = trailing_zeroes(block.label_bits) - last;
        block.label_bits = clear_lowest_bit(block.label_bits);
        *label += count;
        if (!*label || *label > 63)
          SEMANTIC_ERROR(parser, "Bad domain name in %s of %s record",
                         field->name.data, type->name.data);
        label += *label + 1;
        *label = 0;
        last += count + 1;
        assert(label < wire);
      }
      *label += (wire - label) - 1;
    } else {
      *label += (uint8_t)block.length;
      if (*label > 63)
        SEMANTIC_ERROR(parser, "Bad domain name in %s of %s record",
                       field->name.data, type->name.data);
    }
  }

  if (!(wire - octets)) {
    SEMANTIC_ERROR(parser, "Invalid domain name in %s of %s",
                   field->name.data, type->name.data);
  }

  *length = wire - octets;
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  // a freestanding "@" denotes the current origin
  if (token->length == 1 && token->data[0] == '@') {
    memcpy(&parser->rdata[parser->rdlength],
            parser->file->origin.octets,
            parser->file->origin.length);
    parser->rdlength += parser->file->origin.length;
    return;
  }

  size_t length;
  uint8_t *data = &parser->rdata[parser->rdlength];

  scan_name(parser, type, field, token, data, &length);
  assert(length != 0);
  if (data[length - 1] == 0)
    return;

  if (length > 256 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid name in %s, exceeds 255 octets", field->name.data);

  parser->rdlength += length;
  memcpy(&parser->rdata[parser->rdlength],
          parser->file->origin.octets,
          parser->file->origin.length);
  parser->rdlength += parser->file->origin.length;
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_owner(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  // a freestanding "@" denotes the origin
  if (token->length == 1 && token->data[0] == '@') {
    memcpy(parser->file->owner.octets,
           parser->file->origin.octets,
           parser->file->origin.length);
    parser->file->owner.length = parser->file->origin.length;
    return;
  }

  scan_name(parser, type, field, token,
            parser->file->owner.octets,
           &parser->file->owner.length);

  if (parser->file->owner.octets[parser->file->owner.length - 1] == 0)
    return;
  if (parser->file->owner.length > 255 - parser->file->origin.length)
    SEMANTIC_ERROR(parser, "Invalid name in owner");

  memcpy(&parser->file->owner.octets[parser->file->owner.length],
          parser->file->origin.octets,
          parser->file->origin.length);
  parser->file->owner.length += parser->file->origin.length;
}

#endif // NAME_H
