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
zone_parse_int(
  zone_parser_t *parser,
  const zone_rdata_descriptor_t *desc,
  const zone_token_t *token,
  uint64_t max,
  uint64_t *num);

zone_return_t
zone_parse_name(
  zone_parser_t *parser,
  const zone_rdata_descriptor_t *desc,
  const zone_token_t *token,
  uint8_t str[255],
  size_t *len);

inline void *zone_malloc(zone_parser_t *par, size_t size)
{
  if (!par->options.allocator.malloc)
    return malloc(size);
  return par->options.allocator.malloc(par->options.allocator.arena, size);
}

inline void *zone_realloc(zone_parser_t *par, void *ptr, size_t size)
{
  if (!par->options.allocator.realloc)
    return realloc(ptr, size);
  return par->options.allocator.realloc(par->options.allocator.arena, ptr, size);
}

inline void zone_free(zone_parser_t *par, void *ptr)
{
  if (!par->options.allocator.free)
    free(ptr);
  else
    par->options.allocator.free(par->options.allocator.arena, ptr);
}

#endif // ZONE_PARSER_H
