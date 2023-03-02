/*
 * text.h -- some useful commment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TEXT_H
#define TEXT_H

typedef struct string_block string_block_t;
struct string_block {
  size_t length;
  uint64_t escape_bits;
};

zone_always_inline()
zone_nonnull_all()
static inline void copy_string_block(
  string_block_t *block, const char *text, size_t size, uint8_t *wire)
{
  simd_8x_t input;

  simd_loadu_8x(&input, (const uint8_t *)text);
  simd_storeu_8x(wire, &input);

  block->length = size < SIMD_8X_SIZE ? size : SIMD_8X_SIZE;
  const uint64_t mask = (1llu << block->length) - 1;
  block->escape_bits = simd_find_8x(&input, '\\') & mask;
}

zone_always_inline()
zone_nonnull_all()
static inline void parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  string_block_t block;
  uint8_t *wire = parser->rdata + 1;
  const char *text = token->data, *limit = token->data + token->length;

  while (text < limit) {
    copy_string_block(&block, text, (size_t)(limit - text), wire);

    if (block.escape_bits) {
      const uint64_t count = trailing_zeroes(block.escape_bits);
      uint8_t digits[3];
      digits[0] = (unsigned char)text[count + 1] - '0';

      if (digits[0] > 2) {
        wire[count] = (unsigned char)text[count + 1];
        wire += count + 1;
        text += count + 2;
      } else {
        digits[1] = (unsigned char)text[count + 2] - '0';
        digits[2] = (unsigned char)text[count + 3] - '0';
        if (digits[0] < 2) {
          if (digits[1] > 9 || digits[2] > 9)
            SEMANTIC_ERROR(parser, "Invalid %s in %s, bad escape sequence",
                           field->name.data, type->name.data);
        } else {
          if (digits[1] > 5 || digits[2] > 5)
            SEMANTIC_ERROR(parser, "Invalid %s in %s, bad escape sequence",
                           field->name.data, type->name.data);
        }

        wire[count] = digits[0] * 100 + digits[1] * 10 + digits[0];
        wire += count + 1;
        text += count + 4;
      }
    } else {
      text += block.length;
      wire += block.length;
    }

    if (wire - parser->rdata > 256)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, exceeds maximum length",
                     field->name.data, type->name.data);
  }

  parser->rdata[parser->rdlength] = (uint8_t)((wire - parser->rdata) - 1);
  parser->rdlength += (size_t)(wire - parser->rdata);
}

#endif // TEXT_H
