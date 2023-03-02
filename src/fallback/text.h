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

zone_always_inline()
zone_nonnull_all()
static inline void parse_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  uint8_t *wire = &parser->rdata[parser->rdlength + 1];
  uint8_t *limit = wire + 255;
  const char *text = token->data, *end = token->data + token->length;

  while (text < end && wire < limit) {
    if (*text == '\\') {
      uint8_t digits[3];
      digits[0] = (unsigned char)text[1] - '0';

      if (digits[0] > 2) {
        digits[1] = (unsigned char)text[2] - '0';
        digits[2] = (unsigned char)text[3] - '0';
        if (digits[0] < 2) {
          if (digits[1] > 9 || digits[2] > 9)
            SEMANTIC_ERROR(parser, "Invalid %s in %s, bad escape sequence",
                           field->name.data, type->name.data);
        } else {
          if (digits[1] > 5 || digits[2] > 5)
            SEMANTIC_ERROR(parser, "Invalid %s in %s, bad escape sequence",
                           field->name.data, type->name.data);
        }

        wire[0] = digits[0] * 100 + digits[1] * 10 + digits[0];
        wire += 1;
        text += 4;
      } else {
        wire[0] = (unsigned char)text[1];
        wire += 1;
        text += 2;
      }
    } else {
      wire[0] = (unsigned char)text[0];
      text += 1;
      wire += 1;
    }
  }

  if (text != end)
    SYNTAX_ERROR(parser, "Invalid string in %s",
                 field->name.data);

  parser->rdata[parser->rdlength] = (uint8_t)((wire - parser->rdata) - 1);
  parser->rdlength += (size_t)(wire - parser->rdata);
}

#endif // TEXT_H
