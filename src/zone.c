/*
 * zone.h -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "zone.h"

static const char string[] = "<string>";

int32_t zone_open_string(zone_parser_t *parser, const char *str, size_t len)
{
  zone_file_t *file;

  if (!(file = calloc(1, sizeof(*file))))
    return ZONE_NO_MEMORY;
  file->name = string;
  file->path = string;
  file->handle = NULL; // valid for fixed buffer
  file->buffer.used = len;
  file->buffer.size = len;
  file->buffer.data.read = str;
  file->position.line = 1;
  file->position.column = 1;
  memset(parser, 0, sizeof(*parser));
  parser->state = ZONE_INITIAL;
  parser->file = file;
  return 0;
}

void zone_close(zone_parser_t *parser)
{
  (void)parser;
  // FIXME: implement
  // x. close the whole thing.
  // x. cleanup buffers
  // x. etc, etc, etc
  return;
}
