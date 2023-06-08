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
  delimited_t delimited;
  uint64_t backslash;
  uint64_t label;
};

zone_nonnull_all
static zone_really_inline void copy_name_block(
  name_block_t *block,
  const simd_table_t delimiter,
  const simd_table_t space,
  const char *source,
  uint8_t *destination)
{
  copy_and_scan_delimited(
    &block->delimited, delimiter, space, source, destination);
  block->backslash = simd_find_8x(&block->delimited.input, '\\');
  block->label = simd_find_8x(&block->delimited.input, '.');
}

zone_nonnull_all
static zone_really_inline int32_t scan_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const simd_table_t delimiter,
  const simd_table_t space,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  name_block_t block;
  uint8_t *wire = octets + 1, *label = octets;
  const char *text = token->data;

  *label = 0;

  for (bool loop=true; loop; ) {
    copy_name_block(&block, delimiter, space, text, wire);

    uint64_t size;
    if (!(block.backslash & (block.delimited.delimiter - 1))) {
      block.label &= block.delimited.delimiter - 1;
      size = trailing_zeroes(block.delimited.delimiter | (1llu << SIMD_8X_SIZE));
      loop = !block.delimited.delimiter;
      text += size;
      wire += size;
    } else {
      size = trailing_zeroes(block.backslash);
      uint8_t digits[3];
      digits[0] = (unsigned char)text[size + 1] - '0';

      if (digits[0] > 2) {
        wire[size] = (unsigned char)text[size + 1];
        wire += size + 1;
        text += size + 2;
      } else {
        digits[1] = (unsigned char)text[size + 2] - '0';
        digits[2] = (unsigned char)text[size + 3] - '0';
        if (digits[0] < 2) {
          if (digits[1] > 9 || digits[2] > 9)
            SEMANTIC_ERROR(parser, "Bad escape sequence in %s of %s record",
                           field->name.data, type->name.data);
        } else {
          if (digits[1] > 5 || digits[2] > 5)
            SEMANTIC_ERROR(parser, "Bad escape sequence in %s of %s record",
                           field->name.data, type->name.data);
        }

        wire[size] = digits[0] * 100 + digits[1] * 10 + digits[0];
        wire += size + 1;
        text += size + 4;
      }

      block.label &= block.backslash - 1;
    }

    if (wire - octets > 255)
      SEMANTIC_ERROR(parser, "Bad domain name in %s of %s",
                     field->name.data, type->name.data);

    if (block.label) {
      uint64_t count = 0, last = 0;
      const uint64_t labels = count_ones(block.label);
      for (uint64_t i = 0; i < labels; i++) {
        count = trailing_zeroes(block.label) - last;
        block.label = clear_lowest_bit(block.label);
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
      *label += (uint8_t)size;
      if (*label > 63)
        SEMANTIC_ERROR(parser, "Bad domain name in %s of %s record",
                       field->name.data, type->name.data);
    }
  }

  if (!(wire - octets)) {
    SEMANTIC_ERROR(parser, "Invalid domain name in %s of %s",
                   field->name.data, type->name.data);
  }

  *length = (size_t)(wire - octets);
  if (!*label)
    return 0;
  return ZONE_NAME;
}

zone_nonnull_all
static zone_really_inline int32_t scan_contiguous_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  return scan_name(
    parser, type, field, non_contiguous, blank, token, octets, length);
}

zone_nonnull_all
static zone_really_inline int32_t scan_quoted_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *length)
{
  return scan_name(
    parser, type, field, non_quoted, non_quoted, token, octets, length);
}

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
    if (token->data[0] == '@' && !is_contiguous((uint8_t)token->data[1]))
      goto relative;
    r = scan_contiguous_name(parser, type, field, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r < 0)
      return r;
  } else if (token->code == QUOTED) {
    r = scan_quoted_name(parser, type, field, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r < 0)
      return r;
  } else {
    return have_string(parser, type, field, token);
  }

relative:
  if (n > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  memcpy(o+n, parser->file->origin.octets, parser->file->origin.length);
  parser->rdata->length += n + parser->file->origin.length;
  return ZONE_NAME;
}

#endif // NAME_H
