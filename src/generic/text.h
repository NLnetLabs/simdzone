/*
 * text.h -- some useful comment
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
  delimited_t delimited;
  uint64_t backslash;
};

zone_nonnull_all
static zone_really_inline void copy_string_block(
  string_block_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source,
  uint8_t *destination)
{
  copy_and_scan_delimited(&block->delimited, delimiter, space, source, destination);
  block->backslash = simd_find_8x(&block->delimited.input, '\\');
}

zone_nonnull_all
static zone_really_inline int32_t parse_string_in(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const simd_table_t delimiter,
  const simd_table_t space,
  const token_t *token)
{
  string_block_t block;
  uint8_t *wire = &parser->rdata->octets[parser->rdata->length + 1];
  const char *text = token->data;

  for (bool loop=true; loop; ) {
    copy_string_block(&block, delimiter, space, text, wire);

    if (block.backslash & (block.delimited.delimiter - 1)) {
      size_t count = trailing_zeroes(block.backslash);
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
      size_t count = trailing_zeroes(block.delimited.delimiter | (1llu << SIMD_8X_SIZE));
      loop = !block.delimited.delimiter;
      text += count;
      wire += count;
    }

    if (wire - parser->rdata->octets > 256)
      SEMANTIC_ERROR(parser, "Invalid %s in %s, exceeds maximum length",
                     field->name.data, type->name.data);
  }

  parser->rdata->octets[parser->rdata->length] = (uint8_t)((wire - parser->rdata->octets) - 1);
  parser->rdata->length += (size_t)(wire - parser->rdata->octets);
  return ZONE_STRING;
}

#define parse_contiguous_string(parser, type, field, token) \
  parse_string_in(parser, type, field, non_contiguous, blank, token)

#define parse_quoted_string(parser, type, field, token) \
  parse_string_in(parser, type, field, non_quoted, non_quoted, token)

zone_nonnull_all
static zone_really_inline int32_t parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code == QUOTED))
    return parse_quoted_string(parser, type, field, token);
  else if (token->code == CONTIGUOUS)
    return parse_contiguous_string(parser, type, field, token);
  else
    return have_string(parser, type, field, token);
}

#endif // TEXT_H
