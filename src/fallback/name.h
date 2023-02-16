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
        octets[label] = (octet - label) - 1;
        if (token->data[i] != '.')
          break;
        label = octet;
        octets[octet++] = 0;
        break;
      default:
        octets[octet++] = token->data[i];
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
