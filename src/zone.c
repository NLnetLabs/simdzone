/*
 * zone.h -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "parser.h"
#include "util.h"

static const char not_a_file[] = "<string>";

extern inline zone_type_t zone_type(const zone_code_t code);
extern inline zone_item_t zone_item(const zone_code_t code);

static zone_return_t check_options(const zone_options_t *opts)
{
  // custom allocator must be fully specified or not at all
  int alloc = (opts->allocator.malloc != 0) +
              (opts->allocator.realloc != 0) +
              (opts->allocator.free != 0) +
              (opts->allocator.arena != NULL);
  if (alloc != 0 && alloc != 4)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rr)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rdata)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.delimiter)
    return ZONE_BAD_PARAMETER;

  return 0;
}

zone_return_t zone_open_string(
  zone_parser_t *par, const zone_options_t *opts, const char *str, size_t len)
{
  zone_return_t ret;
  zone_file_t *file;

  if (!str)
    return ZONE_BAD_PARAMETER;
  if ((ret = check_options(opts)) < 0)
    return ret;

  memset(par, 0, sizeof(*par));
  file = &par->first;
  file->name = not_a_file;
  file->path = not_a_file;
  file->handle = -1; // valid for fixed buffer icw string
  file->buffer.used = file->buffer.size = len;
  file->buffer.data.read = str;
  file->position.line = 1;
  file->position.column = 1;
  par->scanner.state = ZONE_INITIAL;
  par->parser.state = ZONE_INITIAL;
  par->file = file;
  par->options = *opts;
  return 0;
}

zone_return_t zone_open(
  zone_parser_t *par, const zone_options_t *ropts, const char *path)
{
  zone_return_t ret;
  zone_file_t *file;
  zone_options_t opts = *ropts;
  int fd = -1;
  char buf[PATH_MAX], *relpath = NULL, *abspath = NULL;

  if (!path)
    return ZONE_BAD_PARAMETER;
  if ((ret = check_options(&opts)) < 0)
    return ret;
  if (!realpath(path, buf))
    return ZONE_BAD_PARAMETER;

  if (!(relpath = zone_strdup(&opts, path)))
    goto err_relpath;
  if (!(abspath = zone_strdup(&opts, buf)))
    goto err_abspath;
  if ((fd = open(buf, O_RDONLY)) == -1)
    goto err_open;

  memset(par, 0, sizeof(*par));
  file = &par->first;
  file->name = relpath;
  file->path = abspath;
  file->handle = fd;
  file->buffer.used = file->buffer.size = 0;
  file->buffer.data.write = NULL;
  file->position.line = 1;
  file->position.column = 1;
  par->scanner.state = ZONE_INITIAL;
  par->parser.state = ZONE_INITIAL;
  par->file = file;
  par->options = opts;
  if (!par->options.block_size)
    par->options.block_size = 4096;
  return 0;
err_open:
  zone_free(&opts, abspath);
err_abspath:
  zone_free(&opts, relpath);
err_relpath:
  return ZONE_OUT_OF_MEMORY;
}

void zone_close(zone_parser_t *par)
{
  if (!par)
    return;

  for (zone_file_t *file = par->file, *includer; file; file = includer) {
    includer = file->includer;
    if (file->handle != -1) {
      if (file->buffer.data.write)
        zone_free(par, file->buffer.data.write);
      assert(file->name != not_a_file);
      assert(file->path != not_a_file);
      zone_free(par, (char *)file->name);
      zone_free(par, (char *)file->path);
      (void)close(file->handle);
      if (file != &par->first)
        zone_free(par, file);
    } else {
      assert(file->name == not_a_file);
      assert(file->path == not_a_file);
      assert(file == &par->first);
      assert(!includer);
    }
  }
}

static int mapcmp(const void *p1, const void *p2)
{
  const zone_map_t *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->length);
  assert(m2 && m2->name && m2->length);
  return zone_strcasecmp(m1->name, m1->length, m2->name, m2->length);
}

int32_t zone_is_class(const char *str, size_t len, uint32_t flags)
{
  char buf[32];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  if (len < 2)
    return 0;
  if (strncasecmp(str, "IN", 2) == 0)
    return 1;
  if (strncasecmp(str, "CH", 2) == 0)
    return 2;
  if (strncasecmp(str, "CS", 2) == 0)
    return 3;
  if (strncasecmp(str, "HS", 2) == 0)
    return 4;

  // support unknown DNS class (rfc 3597)
  if (len <= 5 || strncasecmp(str, "CLASS", 5) != 0)
    return 0;

  int32_t class = 0;
  for (size_t i = 5; i < len; i++) {
    if (str[i] < '0' || str[i] > '9')
      return 0;
    class *= 10;
    class += (uint32_t)(str[i] - '0');
    if (class >= UINT16_MAX)
      return 0;
  }

  return class;
}

#include "types.h"

int32_t zone_is_type(const char *str, size_t len, uint32_t flags)
{
  char buf[64];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  const zone_map_t *map, key = { str, len, 0 };
  static const size_t size = sizeof(types[0]);
  static const size_t nmemb = sizeof(types)/size;

  if ((map = bsearch(&key, types, nmemb, size, mapcmp)))
    return (int32_t)map->id;
  if (!(flags & ZONE_GENERIC))
    return 0;

  // support unknown DNS record types (rfc 3597)
  if (len <= 4 || strncasecmp(str, "TYPE", 4) != 0)
    return 0;

  int32_t type = 0;
  for (size_t i = 4; i < len; i++) {
    if (str[i] < '0' || str[i] > '9')
      return 0;
    type *= 10;
    type += (uint32_t)(str[i] - '0');
    if (type > UINT16_MAX)
      return 0;
  }

  return type;
}
