/*
 * zone.c -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>

#include "zone.h"
#include "isadetection.h"

#ifndef NDEBUG
static const char not_a_file[] = "<string>";
#endif

void *zone_malloc(zone_options_t *opts, size_t size)
{
  if (!opts->allocator.malloc)
    return malloc(size);
  return opts->allocator.malloc(opts->allocator.arena, size);
}

void *zone_realloc(zone_options_t *opts, void *ptr, size_t size)
{
  if (!opts->allocator.realloc)
    return realloc(ptr, size);
  return opts->allocator.realloc(opts->allocator.arena, ptr, size);
}

void zone_free(zone_options_t *opts, void *ptr)
{
  if (!opts->allocator.free)
    free(ptr);
  else
    opts->allocator.free(opts->allocator.arena, ptr);
}

char *zone_strdup(zone_options_t *opts, const char *str)
{
  size_t len = strlen(str);
  char *ptr;
  if (!(ptr = zone_malloc(opts, len + 1)))
    return NULL;
  memcpy(ptr, str, len);
  ptr[len] = '\0';
  return ptr;
}

static zone_return_t check_options(const zone_options_t *opts)
{
  // custom allocator must be fully specified or not at all
  int alloc = (opts->allocator.malloc != 0) +
              (opts->allocator.realloc != 0) +
              (opts->allocator.free != 0) +
              (opts->allocator.arena != NULL);
  if (alloc != 0 && alloc != 4)
    return ZONE_BAD_PARAMETER;
#if 0
  if (!opts->accept.rr)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rdata)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.delimiter)
    return ZONE_BAD_PARAMETER;
#endif

  return 0;
}

// support escaped characters here too!
static int parse_origin(const char *origin, uint8_t str[255], size_t *len)
{
  size_t lab = 0, oct = 1;

  assert(origin);

  for (size_t i=0; ; i++) {
    char chr = origin[i];
    if (oct >= 255)
      return -1;

    if (chr == '.' || chr == '\0') {
      if (oct - 1 == lab && lab > 0 && chr != '\0')
        return -1;
      else if ((oct - lab) - 1 > 63)
        return -1;
      str[lab] = (oct - lab) - 1;
      if (chr != '.')
        break;
      lab = oct++;
      str[lab] = 0;
    } else {
      str[oct++] = chr & 0xff;
    }
  }

  if (str[lab] != 0)
    return -1;

  *len = oct;
  return 0;
}

static zone_return_t set_defaults(
  zone_parser_t *par, const zone_options_t *opts)
{
#if 0
  static const char file[] = "<parameter>";

  static const zone_location_t loc = {
    .begin = { .file = file, .line = 1, .column = 1 },
    .end = { .file = file, .line = 1, .column = sizeof(file)-1 }
  };

  par->file->position.file = par->file->name;
  par->file->position.line = 1;
  par->file->position.column = 1;
#endif

  par->options = *opts;
  if (!par->options.origin)
    par->options.origin = "."; // use root by default?
  if (!par->options.default_ttl)
    par->options.default_ttl = 3600;

  // origin
  //zone_name_t *name = &par->file->origin.name;
  if (parse_origin(par->options.origin,
        par->file->origin.name.octets,
       &par->file->origin.name.length) < 0)
    return ZONE_BAD_PARAMETER;
  // owner (replicate origin)
  par->file->owner = par->file->origin;
  //memcpy(&par->file->owner, &par->file->origin, sizeof(par->file->owner));
  // ttl
  par->file->last_ttl = par->file->default_ttl = opts->default_ttl;

#if 0
  par->file->ttl.location = loc;

  par->rr.items[OWNER].field = (zone_field_t){
    .code = ZONE_OWNER|ZONE_NAME,
    .location = loc,
    .octets = par->file->owner.name.octets,
    .length = par->file->owner.name.length };
  par->rr.items[TTL].field = (zone_field_t){
    .code = ZONE_TTL|ZONE_INT32,
    .location = loc,
    .int32 = &opts->ttl,
    .length = sizeof(opts->ttl) };
  par->rr.items[CLASS].int16 = 2;
  par->rr.items[CLASS].field = (zone_field_t){
    .code = ZONE_CLASS|ZONE_INT16,
    .location = loc,
    .int16 = &par->rr.items[CLASS].int16,
    .length = sizeof(par->rr.items[CLASS].int16) };
  par->rr.items[TYPE].field = (zone_field_t){
    .code = ZONE_TYPE|ZONE_INT16,
    .location = loc,
    .length = sizeof(uint16_t) };
#endif

  return 0;
}

zone_return_t zone_open(
  zone_parser_t *par, const zone_options_t *ropts, const char *path)
{
  zone_return_t ret;
  zone_file_t *file;
  zone_options_t opts = *ropts;
  int fd = -1;
  char buf[PATH_MAX];
  char *window = NULL, *relpath = NULL, *abspath = NULL;

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
  if (!(window = zone_malloc(&opts, 2)))
    goto err_window;
  window[0] = '\n';
  window[1] = '\0';

  memset(par, 0, sizeof(*par));// - sizeof(par->rdata));
  file = &par->first;
  file->name = relpath;
  file->path = abspath;
  file->handle = fd;
  file->buffer.index = 1;
  file->buffer.length = 1;
  file->buffer.size = 2;
  file->buffer.data = window;
  file->start_of_line = 1;
  file->end_of_file = 0;
  file->origin.name.octets = &file->names[256];
  file->indexer.head = &file->indexer.tape[1];
  file->indexer.tail = &file->indexer.tape[1];
  file->indexer.tape[0] = (zone_transition_t){ window,   0 };
  file->indexer.tape[1] = (zone_transition_t){ window+1, 0 };
  file->last_type = 0;
  file->last_class = opts.default_class;
  file->last_ttl = opts.default_ttl;
  par->file = file;
  if (set_defaults(par, &opts) < 0)
    return ZONE_BAD_PARAMETER;
  par->state.scanner = 0;
  par->state.base16 = 0;
  par->state.base32 = 0;
  par->state.base64 = 0;
  // FIXME: magic numbers, bad
  par->items[1].data.int16 = &par->file->last_type;
  par->items[2].data.int16 = &par->file->last_class;
  par->items[3].data.int32 = &par->file->last_ttl;
  return 0;
err_window:
  close(fd);
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
      if (file->buffer.data)
        zone_free(&par->options, file->buffer.data);
      assert(file->name != not_a_file);
      assert(file->path != not_a_file);
      zone_free(&par->options, (char *)file->name);
      zone_free(&par->options, (char *)file->path);
      (void)close(file->handle);
      if (file != &par->first)
        zone_free(&par->options, file);
    } else {
      assert(file->name == not_a_file);
      assert(file->path == not_a_file);
      assert(file == &par->first);
      assert(!includer);
    }
  }
}

#include "config.h"
#include "isadetection.h"

#if ZONE_SUPPORTS_HASWELL
extern zone_return_t zone_parse_haswell(zone_parser_t *, void *);
#endif

#if ZONE_SUPPORTS_WESTMERE
extern zone_return_t zone_parse_westmere(zone_parser_t *, void *);
#endif

typedef struct {
  const char *name;
  uint32_t instruction_set;
  zone_return_t (*parse)(zone_parser_t *, void *);
} implementation_t;

static const implementation_t implementations[] = {
#if ZONE_SUPPORTS_HASWELL
  { "haswell", AVX2, &zone_parse_haswell },
#endif
#if ZONE_SUPPORTS_WESTMERE
  { "westmere", SSE42, &zone_parse_westmere },
#endif
  { "generic", 0, 0 } // generic implementation pending
};

static inline const implementation_t *
select_implementation(void)
{
  const char *preferred;
  const uint32_t supported = detect_supported_architectures();
  const size_t length = sizeof(implementations)/sizeof(implementations[0]);
  size_t count = 0;

  if ((preferred = getenv("ZONE_IMPLEMENTATION"))) {
    for (; count < length; count++)
      if (strcasecmp(preferred, implementations[count].name) == 0)
        break;
    if (count == length)
      count = 0;
  }

  for (; count < length; count++)
    if (implementations[count].instruction_set & supported)
      return &implementations[count];

  return &implementations[length - 1];
}

zone_return_t zone_parse(zone_parser_t *parser, void *user_data)
{
  const implementation_t *implementation;

  // FIXME: do setjmp here so longjmp can be used?

  implementation = select_implementation();
  assert(implementation);
  return implementation->parse(parser, user_data);
}
