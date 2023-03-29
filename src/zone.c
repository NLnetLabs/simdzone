/*
 * zone.c -- zone parser
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>
#include <setjmp.h>
#if _WIN32
# include <windows.h>
#endif

#include "zone.h"
#include "heap.h"
#include "diagnostic.h"
#include "isadetection.h"

#if _WIN32
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#endif

static const char not_a_file[] = "<string>";

static zone_return_t check_options(const zone_options_t *options)
{
  // custom allocator must be fully specified or not at all
  int alloc = (options->allocator.malloc != 0) +
              (options->allocator.realloc != 0) +
              (options->allocator.free != 0) +
              (options->allocator.arena != NULL);
  if (alloc != 0 && alloc != 4)
    return ZONE_BAD_PARAMETER;
  if (!options->accept)
    return ZONE_BAD_PARAMETER;
  if (!options->origin)
    return ZONE_BAD_PARAMETER;
  if (!options->default_ttl || options->default_ttl > INT32_MAX)
    return ZONE_BAD_PARAMETER;

  switch (options->default_class) {
    case ZONE_IN:
    case ZONE_CS:
    case ZONE_CH:
    case ZONE_HS:
      break;
    default:
      return ZONE_BAD_PARAMETER;
  }

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
      str[lab] = (uint8_t)((oct - lab) - 1);
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

#include "config.h"
#include "isadetection.h"

#if ZONE_SUPPORTS_HASWELL
extern zone_return_t zone_haswell_parse(zone_parser_t *, void *);
#endif

#if ZONE_SUPPORTS_WESTMERE
extern zone_return_t zone_westmere_parse(zone_parser_t *, void *);
#endif

extern zone_return_t zone_fallback_parse(zone_parser_t *, void *);

typedef struct target target_t;
struct target {
  const char *name;
  uint32_t instruction_set;
  zone_return_t (*parse)(zone_parser_t *, void *);
};

static const target_t targets[] = {
#if ZONE_SUPPORTS_HASWELL
  { "haswell", AVX2, &zone_haswell_parse },
#endif
#if ZONE_SUPPORTS_WESTMERE
  { "westmere", SSE42, &zone_westmere_parse },
#endif
  { "fallback", 0, &zone_fallback_parse }
};

static inline const target_t *
select_target(void)
{
  const char *preferred;
  const uint32_t supported = detect_supported_architectures();
  const size_t length = sizeof(targets)/sizeof(targets[0]);
  size_t count = 0;

  if ((preferred = getenv("ZONE_TARGET"))) {
    for (; count < length; count++)
      if (strcasecmp(preferred, targets[count].name) == 0)
        break;
    if (count == length)
      count = 0;
  }

  for (; count < length; count++)
    if (!targets[count].instruction_set || (targets[count].instruction_set & supported))
      return &targets[count];

  return &targets[length - 1];
}

static zone_return_t parse(zone_parser_t *parser, void *user_data)
{
  const target_t *target;
  zone_return_t result;

  target = select_target();
  assert(target);

  switch ((result = setjmp((void *)parser->environment))) {
    case 0:
      result = target->parse(parser, user_data);
      assert(result == ZONE_SUCCESS);
      break;
    default:
      assert(result < 0);
      break;
  }

  return result;
}

zone_nonnull_all()
static zone_return_t open_file(
  zone_parser_t *parser,
  zone_file_t *file,
  const char *name,
  const char *origin)
{
#if _WIN32
  char path[1];
  size_t length, size = GetFullPathName(name, sizeof(path), path, NULL);
  if (!size)
    return ZONE_IO_ERROR;
  if (!(file->path = zone_malloc(&parser->options, size)))
    return ZONE_OUT_OF_MEMORY;
  if (!(length = GetFullPathName(name, size, file->path, NULL)))
    return ZONE_IO_ERROR;
  if (length != size - 1)
    return ZONE_IO_ERROR;
#else
  char path[PATH_MAX];
  if (!realpath(name, path))
    return ZONE_IO_ERROR;
  if (!(file->path = zone_strdup(parser, path)))
    return ZONE_OUT_OF_MEMORY;
#endif

  if (!(file->name = zone_strdup(parser, name)))
    return ZONE_OUT_OF_MEMORY;
  if (parse_origin(origin, file->origin.octets, &file->origin.length) < 0)
    return ZONE_BAD_PARAMETER;
  if (!(file->handle = fopen(file->path, "rb")))
    switch (errno) {
      case ENOMEM:
        return ZONE_OUT_OF_MEMORY;
      default:
        return ZONE_IO_ERROR;
    }

  if (!(file->buffer.data = zone_malloc(parser, ZONE_WINDOW_SIZE + 1)))
    return ZONE_OUT_OF_MEMORY;

  file->buffer.data[0] = '\0';
  file->buffer.size = ZONE_WINDOW_SIZE;
  file->buffer.length = 0;
  file->buffer.index = 0;
  file->start_of_line = true;
  file->end_of_file = ZONE_HAVE_DATA;
  file->indexer.tape[0] = (zone_index_t){ file->buffer.data, 0 };
  file->indexer.tape[1] = (zone_index_t){ file->buffer.data, 0 };
  file->indexer.head = file->indexer.tape;
  file->indexer.tail = file->indexer.tape;
  return 0;
}

zone_nonnull_all()
static void close_file(
  zone_parser_t *parser, zone_file_t *file)
{
  assert((file->name == not_a_file) == !file->handle);
  assert((file->path == not_a_file) == !file->handle);

  if (file->buffer.data)
    zone_free(parser, file->buffer.data);
  if (file->name)
    zone_free(parser, (char *)file->name);
  if (file->path)
    zone_free(parser, (char *)file->path);
  (void)fclose(file->handle);
  if (file != &parser->first)
    zone_free(parser, file);
}

static void set_defaults(zone_parser_t *parser)
{
  if (!parser->options.log.write && !parser->options.log.categories)
    parser->options.log.categories = (uint32_t)-1;
  parser->items[0].code = ZONE_OWNER | ZONE_NAME;
  parser->items[1].code = ZONE_TYPE | ZONE_INT16;
  parser->items[1].length = sizeof(parser->file->last_type);
  parser->items[1].data.int16 = &parser->file->last_type;
  parser->items[2].code = ZONE_CLASS | ZONE_INT16;
  parser->items[2].length = sizeof(parser->file->last_class);
  parser->items[2].data.int16 = &parser->file->last_class;
  parser->items[3].code = ZONE_TTL | ZONE_INT32;
  parser->items[3].length = sizeof(parser->file->last_ttl);
  parser->items[3].data.int32 = &parser->file->last_ttl;
}

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

void zone_close(zone_parser_t *parser)
{
  if (!parser)
    return;

  for (zone_file_t *file = parser->file, *includer; file; file = includer) {
    includer = file->includer;
    if (file->handle)
      close_file(parser, file);
  }
}

zone_return_t zone_open(
  zone_parser_t *parser,
  const zone_options_t *options,
  const char *filename,
  void *user_data)
{
  zone_file_t *file;
  zone_return_t result;

  if ((result = check_options(options)) < 0)
    return result;

  memset(parser, 0, sizeof(*parser));
  parser->options = *options;
  parser->user_data = user_data;
  file = parser->file = &parser->first;
  if ((result = open_file(parser, file, filename, options->origin)) < 0)
    goto error;

  file->owner = file->origin;
  file->last_type = 0;
  file->last_class = options->default_class;
  file->last_ttl = options->default_ttl;
  file->line = 1;

  set_defaults(parser);
  return 0;
error:
  zone_close(parser);
  return result;
}

diagnostic_pop()

zone_return_t zone_parse(
  zone_parser_t *parser,
  const zone_options_t *options,
  const char *filename,
  void *user_data)
{
  zone_return_t result;
  volatile jmp_buf environment;

  if ((result = zone_open(parser, options, filename, user_data)) < 0)
    return result;
  parser->environment = &environment;
  result = parse(parser, user_data);
  zone_close(parser);
  return result;
}

zone_return_t zone_parse_string(
  zone_parser_t *parser,
  const zone_options_t *options,
  const char *string,
  size_t length,
  void *user_data)
{
  zone_file_t *file;
  zone_return_t result;
  volatile jmp_buf environment;

  if ((result = check_options(options)) < 0)
    return result;

  memset(parser, 0, sizeof(*parser));
  parser->options = *options;
  parser->user_data = user_data;
  file = parser->file = &parser->first;
  if ((result = parse_origin(options->origin, file->origin.octets, &file->origin.length)) < 0)
    return result;

  file->name = not_a_file;
  file->path = not_a_file;
  file->handle = NULL;
  file->buffer.index = 0;
  file->buffer.length = length;
  file->buffer.size = length;
  file->buffer.data = (char *)string;
  file->start_of_line = true;
  file->end_of_file = ZONE_READ_ALL_DATA;
  file->indexer.tape[0] = (zone_index_t){ "\0", 0 };
  file->indexer.tape[1] = (zone_index_t){ "\0", 0 };
  file->indexer.head = file->indexer.tape;
  file->indexer.tail = file->indexer.tape;

  file->owner = file->origin;
  file->last_type = 0;
  file->last_class = options->default_class;
  file->last_ttl = options->default_ttl;
  file->line = 1;

  set_defaults(parser);
  parser->environment = &environment;
  result = parse(parser, user_data);
  zone_close(parser);
  return result;
}
