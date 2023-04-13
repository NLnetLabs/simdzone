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

#include <string.h>

static inline zone_return_t scan_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token,
  uint8_t octets[256],
  size_t *length)
{
  size_t label = 0, octet = 1;

  (void)type;

  for (size_t i=0; i < token->length; i++) {
    if (octet >= 255)
      SYNTAX_ERROR(parser, "Invalid name in %s, name exceeds maximum",
        field->name.data);

    // FIXME: implement support for escape sequences

    switch (token->data[i]) {
      case '.':
        if (octet - 1 == label)
          SYNTAX_ERROR(parser, "Invalid name in %s, empty label",
            field->name.data);
        // fall through
      case '\0':
        if ((octet - 1) - label > 63)
          SYNTAX_ERROR(parser, "Invalid name in %s, label exceeds maximum",
            field->name.data);
        octets[label] = (uint8_t)((octet - label) - 1);
        if (token->data[i] != '.')
          break;
        label = octet;
        octets[octet++] = 0;
        break;
      default:
        octets[octet++] = (unsigned char)token->data[i];
        break;
    }
  }

  *length = octet;
  return 0;
}

static inline void parse_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  // a freestanding "@" denotes the current origin
  if (token->length == 1 && token->data[0] == '@') {
    memcpy(&parser->rdata->octets[parser->rdata->length],
            parser->file->origin.octets,
            parser->file->origin.length);
    parser->rdata->length += parser->file->origin.length;
    return;
  }

  size_t length;
  uint8_t *data = &parser->rdata->octets[parser->rdata->length];

  scan_name(parser, type, field, token, data, &length);
  assert(length != 0);
  if (data[length - 1] == 0)
    return;

  if (length > 256 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid name in %s, exceeds 255 octets", field->name.data);

  parser->rdata->length += length;
  memcpy(&parser->rdata->octets[parser->rdata->length],
          parser->file->origin.octets,
          parser->file->origin.length);
  parser->rdata->length += parser->file->origin.length;
}

#endif // NAME_H
