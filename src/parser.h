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

inline void *zone_malloc(void *vopts, size_t size)
{
  zone_options_t *opts = vopts;
  if (!opts->allocator.malloc)
    return malloc(size);
  return opts->allocator.malloc(opts->allocator.arena, size);
}

inline void *zone_realloc(void *vopts, void *ptr, size_t size)
{
  zone_options_t *opts = vopts;
  if (!opts->allocator.realloc)
    return realloc(ptr, size);
  return opts->allocator.realloc(opts->allocator.arena, ptr, size);
}

inline void zone_free(void *vopts, void *ptr)
{
  zone_options_t *opts = vopts;
  if (!opts->allocator.free)
    free(ptr);
  else
    opts->allocator.free(opts->allocator.arena, ptr);
}

inline char *zone_strdup(void *vopts, const char *str)
{
  zone_options_t *opts = vopts;
  size_t len = strlen(str);
  char *ptr;
  if (!opts->allocator.malloc)
    ptr = malloc(len + 1);
  else
    ptr = opts->allocator.malloc(opts->allocator.arena, len + 1);
  if (!ptr)
    return NULL;
  memcpy(ptr, str, len);
  ptr[len] = '\0';
  return ptr;
}

typedef zone_return_t(*rdata_parse_t)(
  zone_parser_t *, const zone_token_t *, zone_field_t *, void *);

typedef zone_return_t(*rdata_accept_t)(
  zone_parser_t *, zone_field_t *, void *);

struct rdata_descriptor {
  zone_rdata_descriptor_t public;
  rdata_parse_t typed;
  rdata_parse_t generic;
  rdata_accept_t accept;
};

struct type_descriptor {
  zone_type_descriptor_t public;
  const struct rdata_descriptor *rdata;
};

#endif // ZONE_PARSER_H
