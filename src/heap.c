/*
 * heap.c -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdlib.h>
#include <string.h>

#include "heap.h"

void *zone_malloc(zone_parser_t *parser, size_t size)
{
  if (!parser->options.allocator.malloc)
    return malloc(size);
  return parser->options.allocator.malloc(parser->options.allocator.arena, size);
}

void *zone_realloc(zone_parser_t *parser, void *ptr, size_t size)
{
  if (!parser->options.allocator.realloc)
    return realloc(ptr, size);
  return parser->options.allocator.realloc(parser->options.allocator.arena, ptr, size);
}

void zone_free(zone_parser_t *parser, void *ptr)
{
  if (!parser->options.allocator.free)
    free(ptr);
  else
    parser->options.allocator.free(parser->options.allocator.arena, ptr);
}

char *zone_strdup(zone_parser_t *parser, const char *str)
{
  size_t len = strlen(str);
  char *ptr;
  if (!(ptr = zone_malloc(parser, len + 1)))
    return NULL;
  memcpy(ptr, str, len);
  ptr[len] = '\0';
  return ptr;
}

char *zone_strndup(zone_parser_t *parser, const char *str, size_t n)
{
  char *ptr;
  size_t len = strlen(str);
  if (len > n)
    len = n;
  if (!(ptr = zone_malloc(parser, len + 1)))
    return NULL;
  memcpy(ptr, str, len);
  ptr[len] = '\0';
  return ptr;
}
