/*
 * ip4.h -- fallback parser for IPv4 addresses
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef IP4_H
#define IP4_H

#include <netinet/in.h>

zone_always_inline()
zone_nonnull_all()
static inline void parse_ip4(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  char buf[INET_ADDRSTRLEN + 1];

  if (token->length > INET_ADDRSTRLEN)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);

  memcpy(buf, token->data, token->length);
  buf[token->length] = '\0';
  if (inet_pton(AF_INET, buf, &parser->rdata[parser->rdlength]) != 1)
    SEMANTIC_ERROR(parser, "Invalid %s in %s",
                   field->name.data, type->name.data);
  parser->rdlength += sizeof(struct in_addr);
}

#endif // IP4_H
