/*
 * parse.h -- meaningful comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_PARSER_H
#define ZONE_PARSER_H

#include <stdlib.h>

#include "scanner.h"

zone_return_t
zone_parse_ttl(
  zone_parser_t *parser,
  const zone_token_t *token,
  uint32_t *ttl);

zone_return_t
zone_parse_name(
  zone_parser_t *parser,
  const zone_token_t *token,
  uint8_t str[255],
  size_t size,
  size_t *len);

#endif // ZONE_PARSER_H
