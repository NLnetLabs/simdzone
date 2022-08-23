/*
 * zone.c -- zone parser.
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
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "parser.h"

static const char not_a_file[] = "<string>";

extern inline zone_type_t zone_type(const zone_code_t code);
extern inline zone_item_t zone_item(const zone_code_t code);

static void *zone_malloc(zone_options_t *opts, size_t size)
{
  if (!opts->allocator.malloc)
    return malloc(size);
  return opts->allocator.malloc(opts->allocator.arena, size);
}

#if 0
static void *zone_realloc(zone_options_t *opts, void *ptr, size_t size)
{
  if (!opts->allocator.realloc)
    return realloc(ptr, size);
  return opts->allocator.realloc(opts->allocator.arena, ptr, size);
}
#endif

static void zone_free(zone_options_t *opts, void *ptr)
{
  if (!opts->allocator.free)
    free(ptr);
  else
    opts->allocator.free(opts->allocator.arena, ptr);
}

static char *zone_strdup(zone_options_t *opts, const char *str)
{
  size_t len = strlen(str);
  char *ptr;
  if (!(ptr = zone_malloc(opts, len + 1)))
    return NULL;
  memcpy(ptr, str, len);
  ptr[len] = '\0';
  return ptr;
}

#if 0
zone_return_t zone_refill(zone_parser_t *par, zone_token_t *tok)
{
  zone_file_t *file = par->file;
  uintptr_t diff = 0;

  assert(file->handle != -1 && !file->empty);
  assert(file->name != file->path);
  if (tok) {
    assert((uintptr_t)tok->slice.data >= (uintptr_t)par->file->buffer.read &&
           (uintptr_t)tok->slice.data <= (uintptr_t)par->file->buffer.read + par->file->buffer.size);
    diff = tok->slice.data - par->file->buffer.read;
  }

  // shuffle buffer if sensible
  if (file->buffer.offset > file->buffer.length / 2) {
    memmove(file->buffer.data.write,
            file->buffer.data.write + file->buffer.offset,
            file->buffer.length - file->buffer.offset);
    file->buffer.length = file->buffer.length - file->buffer.offset;
    file->buffer.offset = 0;
  }

  // grow buffer if no space is available
  if (file->buffer.length == file->buffer.size) {
    // highly unlikely, but still
    if (file->buffer.size > SIZE_MAX - par->options.block_size)
      return (par->state.scanner = ZONE_OUT_OF_MEMORY);

    size_t size = file->buffer.size + par->options.block_size;
    char *buf;
    if (!(buf = zone_realloc(&par->options, file->buffer.data.write, size)))
      return (par->state.scanner = ZONE_OUT_OF_MEMORY);
    file->buffer.size = size;
    file->buffer.data.write = buf;
  }

  ssize_t cnt;

  do {
    cnt = read(file->handle,
               file->buffer.data.write + file->buffer.length,
               file->buffer.size - file->buffer.length);
  } while (cnt == -1 && errno == EINTR);

  if (cnt == -1)
    return (par->state.scanner = ZONE_READ_ERROR);
  assert(cnt >= 0);
  if (cnt == 0)
    file->empty = true;

  if (tok) {
    tok->slice.data = par->file->buffer.read + diff;
  }
  file->buffer.length += (size_t)cnt;
  return 0;
}
#endif

void zone_error(const zone_parser_t *par, const char *fmt, ...)
{
  assert(par);
  assert(fmt);
  (void)par;
  // pending a proper implementation
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
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
  if (!opts->accept.rr)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rdata)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.delimiter)
    return ZONE_BAD_PARAMETER;

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
  static const char file[] = "<parameter>";

  static const zone_location_t loc = {
    .begin = { .file = file, .line = 1, .column = 1 },
    .end = { .file = file, .line = 1, .column = sizeof(file)-1 }
  };

  par->file->position.file = par->file->name;
  par->file->position.line = 1;
  par->file->position.column = 1;

  par->options = *opts;
  if (!par->options.origin)
    par->options.origin = "."; // use root by default?
  if (!par->options.ttl)
    par->options.ttl = 3600;
  if (!par->options.block_size)
    par->options.block_size = 4096;

  // origin
  zone_name_t *name = &par->file->origin.name;
  if (parse_origin(par->options.origin, name->octets, &name->length) == -1)
    return ZONE_BAD_PARAMETER;
  // owner (replicate origin)
  memcpy(&par->file->owner, &par->file->origin, sizeof(par->file->owner));
  // ttl
  par->file->ttl.seconds = opts->ttl;
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

  memset(par, 0, sizeof(*par) - sizeof(par->rdata.base64));
  file = &par->first;
  file->name = not_a_file;
  file->path = not_a_file;
  file->handle = -1; // valid for fixed buffer icw string
  file->buffer.offset = 0;
  file->buffer.length = len;
  file->buffer.data = str;
  par->file = file;
  if (set_defaults(par, opts) < 0)
    return ZONE_BAD_PARAMETER;
  par->state.scanner = ZONE_INITIAL;
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
  struct stat st;
  if (fstat(fd, &st) == -1)
    goto err_mmap;
  const char *mmap_addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mmap_addr == MAP_FAILED)
    goto err_mmap;

  memset(par, 0, sizeof(*par) - sizeof(par->rdata.base64));
  file = &par->first;
  file->name = relpath;
  file->path = abspath;
  file->handle = fd;
  file->buffer.offset = 0;
  file->buffer.length = st.st_size;
  file->buffer.data = mmap_addr;
  par->file = file;
  if (set_defaults(par, &opts) < 0)
    return ZONE_BAD_PARAMETER;
  par->state.scanner = ZONE_INITIAL;
  return 0;
err_mmap:
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
      // FIXME: munmap
      //if (file->buffer.data.write)
      //  zone_free(&par->options, file->buffer.data.write);
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
