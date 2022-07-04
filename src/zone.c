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

#include "scanner.h"

static const char string[] = "<string>";

extern inline zone_type_t zone_type(const zone_code_t code);
extern inline zone_item_t zone_item(const zone_code_t code);

zone_return_t zone_open_string(
  zone_parser_t *par, const zone_options_t *opts, const char *str, size_t len)
{
  zone_file_t *file;

  if (!str)
    return ZONE_BAD_PARAMETER;

  // custom allocator must be fully specified or not at all
  int alloc = (opts->allocator.malloc != 0) +
              (opts->allocator.realloc != 0) +
              (opts->allocator.free != 0) +
              (opts->allocator.arena != NULL);
  if (alloc != 0 && alloc != 4)
    return ZONE_BAD_PARAMETER;
  //
  if (!opts->accept.rr)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rdata)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.delimiter)
    return ZONE_BAD_PARAMETER;

  if (!(file = calloc(1, sizeof(*file))))
    return ZONE_OUT_OF_MEMORY;
  file->name = string;
  file->path = string;
  file->handle = NULL; // valid for fixed buffer
  file->buffer.used = len;
  file->buffer.size = len;
  file->buffer.data.read = str;
  file->position.line = 1;
  file->position.column = 1;
  memset(par, 0, sizeof(*par));
  par->scanner.state = ZONE_INITIAL;
  par->parser.state = ZONE_INITIAL;
  par->file = file;
  par->options = *opts;
  return 0;
}

void zone_close(zone_parser_t *par)
{
  if (par) {
    if (par->file) {
      if (par->file->handle)
        fclose(par->file->handle);
      free(par->file);
    }
  }
  // FIXME: implement
  // x. close the whole thing.
  // x. cleanup buffers
  // x. etc, etc, etc
  return;
}
