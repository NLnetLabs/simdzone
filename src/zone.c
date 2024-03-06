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
#if _WIN32
# include <Windows.h>
# include <shlwapi.h>
#endif

#include "zone.h"

typedef zone_parser_t parser_t; // convenience

#include "attributes.h"
#include "diagnostic.h"
#include "isadetection.h"

#if _WIN32
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)

static char *strndup(const char *s, size_t n)
{
  char *p;
  if ((p = malloc(n + 1))) {
    memcpy(p, s, n);
    p[n] = '\0';
  }
  return p;
}
#endif

static const char not_a_file[] = "<string>";

static int32_t check_options(const zone_options_t *options)
{
  if (!options->accept.callback)
    return ZONE_BAD_PARAMETER;
  if (!options->default_ttl || options->default_ttl > INT32_MAX)
    return ZONE_BAD_PARAMETER;
  if (!options->origin.octets || !options->origin.length)
    return ZONE_BAD_PARAMETER;

  const uint8_t *root = &options->origin.octets[options->origin.length - 1];
  if (root[0] != 0)
    return ZONE_BAD_PARAMETER;
  const uint8_t *label = &options->origin.octets[0];
  while (label < root) {
    if (root - label < label[0])
      return ZONE_BAD_PARAMETER;
    label += label[0] + 1;
  }

  if (label != root)
    return ZONE_BAD_PARAMETER;

  return 0;
}

#include "config.h"
#include "isadetection.h"

#if HAVE_HASWELL
extern int32_t zone_haswell_parse(parser_t *, void *);
#endif

#if HAVE_WESTMERE
extern int32_t zone_westmere_parse(parser_t *, void *);
#endif

extern int32_t zone_fallback_parse(parser_t *, void *);

typedef struct kernel kernel_t;
struct kernel {
  const char *name;
  uint32_t instruction_set;
  int32_t (*parse)(parser_t *, void *);
};

static const kernel_t kernels[] = {
#if HAVE_HASWELL
  { "haswell", AVX2, &zone_haswell_parse },
#endif
#if HAVE_WESTMERE
  { "westmere", SSE42, &zone_westmere_parse },
#endif
  { "fallback", DEFAULT, &zone_fallback_parse }
};

diagnostic_push()
msvc_diagnostic_ignored(4996)

static inline const kernel_t *
select_kernel(void)
{
  const char *preferred;
  const uint32_t supported = detect_supported_architectures();
  const size_t length = sizeof(kernels)/sizeof(kernels[0]);
  size_t count = 0;

  if ((preferred = getenv("ZONE_KERNEL"))) {
    for (; count < length; count++)
      if (strcasecmp(preferred, kernels[count].name) == 0)
        break;
    if (count == length)
      count = 0;
  }

  for (; count < length; count++)
    if ((kernels[count].instruction_set & supported) == (kernels[count].instruction_set))
      return &kernels[count];

  return &kernels[length - 1];
}

diagnostic_pop()

static int32_t parse(parser_t *parser, void *user_data)
{
  const kernel_t *kernel;

  kernel = select_kernel();
  assert(kernel);
  parser->user_data = user_data;
  return kernel->parse(parser, user_data);
}

diagnostic_push()
msvc_diagnostic_ignored(4996)

nonnull_all
static int32_t open_file(
  parser_t *parser, zone_file_t *file, const char *path, size_t length)
{
  char *abs = NULL;

  (void)parser;

  if (!(file->name = strndup(path, length)))
    return ZONE_OUT_OF_MEMORY;

  const char *rel = file->name;

#if _WIN32
  char buf[1];
  // relative include paths are relative to including file
  if (file != &parser->first && PathIsRelative(path)) {
    assert(parser->file->path != not_a_file);
    assert(parser->file->handle != NULL);
    const char *dir = parser->file->path;
    int dirlen = 0;
    for (int i = 0; i < INT32_MAX && dir[i]; i++) {
      if (dir[i] == '/' || dir[i] == '\\')
        dirlen = i + 1;
    }
    int len;
    len = snprintf(buf, sizeof(buf), "%.*s\\%s", dirlen, dir, file->name);
    assert(len != -1);
    if (!(abs = malloc(len + 1)))
      return ZONE_READ_ERROR;
    (void)snprintf(abs, len + 1, "%.*s\\%s", dirlen, dir, file->name);
    rel = abs;
  }
  DWORD size = GetFullPathName(rel, sizeof(buf), buf, NULL);
  if (!size)
    goto read_error;
  if (!(file->path = malloc(size)))
    goto out_of_memory;
  (void)GetFullPathName(rel, size, file->path, NULL);
#else
  char buf[PATH_MAX];
  if (file != &parser->first && path[0] != '/') {
    assert(parser->file->path != not_a_file);
    assert(parser->file->handle != NULL);
    const char *dir = parser->file->path;
    int dirlen = 0;
    for (int i = 0; i < INT32_MAX && dir[i]; i++) {
      if (dir[i] == '/')
        dirlen = i + 1;
    }
    int len;
    len = snprintf(buf, sizeof(buf), "%.*s/%s", dirlen, dir, file->name);
    if (!(abs = malloc((size_t)len + 1)))
      return ZONE_OUT_OF_MEMORY;
    (void)snprintf(abs, (size_t)len + 1, "%.*s/%s", dirlen, dir, file->name);
    rel = abs;
  }
  if (!realpath(rel, buf))
    goto read_error;
  if (!(file->path = strdup(buf)))
    goto out_of_memory;
#endif
  if (abs)
    free(abs);
  abs = NULL;

  if (!(file->handle = fopen(file->path, "rb")))
    switch (errno) {
      case ENOMEM:
        return ZONE_OUT_OF_MEMORY;
      default:
        return ZONE_READ_ERROR;
    }

  if (!(file->buffer.data = malloc(ZONE_WINDOW_SIZE + 1)))
    return ZONE_OUT_OF_MEMORY;

  file->buffer.data[0] = '\0';
  file->buffer.size = ZONE_WINDOW_SIZE;
  file->buffer.length = 0;
  file->buffer.index = 0;
  file->start_of_line = true;
  file->end_of_file = 0;
  file->fields.tape[0] = file->fields.tape[1] = file->buffer.data;
  file->fields.head = file->fields.tape;
  file->fields.tail = file->fields.tape;
  file->lines.tape[0] = 0;
  file->lines.head = file->lines.tape;
  file->lines.tail = file->lines.tape;
  return 0;
read_error:
  if (abs) free(abs);
  return ZONE_READ_ERROR;
out_of_memory:
  if (abs) free(abs);
  return ZONE_OUT_OF_MEMORY;
}

diagnostic_pop()

static void set_defaults(parser_t *parser)
{
  if (!parser->options.log.callback && !parser->options.log.categories)
    parser->options.log.categories = (uint32_t)-1;
  parser->owner = &parser->file->owner;
  parser->rdata = &parser->buffers.rdata.blocks[0];
}

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

nonnull_all
void zone_close_file(
  parser_t *parser, zone_file_t *file)
{
  assert((file->name == not_a_file) == !file->handle);
  assert((file->path == not_a_file) == !file->handle);

  if (!file->handle)
    return;

  if (file->buffer.data)
    free(file->buffer.data);
  file->buffer.data = NULL;
  if (file->name && file->name != not_a_file)
    free((char *)file->name);
  file->name = NULL;
  if (file->path && file->name != not_a_file)
    free((char *)file->path);
  file->path = NULL;
  (void)fclose(file->handle);
  file->handle = NULL;
  if (file != &parser->first)
    free(file);
}

nonnull_all
int32_t zone_open_file(
  parser_t *parser, const char *path, size_t length, zone_file_t **fileptr)
{
  zone_file_t *file;
  int32_t result;

  if (!(file = malloc(sizeof(*file))))
    return ZONE_OUT_OF_MEMORY;
  memset(file, 0, sizeof(*file));// - sizeof(file->fields.tape));
  if ((result = open_file(parser, file, path, length)) < 0)
    goto err_open;

  *fileptr = file;
  return 0;
err_open:
  zone_close_file(parser, file);
  return result;
}

void zone_close(parser_t *parser)
{
  if (!parser)
    return;

  for (zone_file_t *file = parser->file, *includer; file; file = includer) {
    includer = file->includer;
    if (file->handle)
      zone_close_file(parser, file);
  }
}

int32_t zone_open(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *path,
  void *user_data)
{
  zone_file_t *file;
  int32_t result;

  if ((result = check_options(options)) < 0)
    return result;

  memset(parser, 0, sizeof(*parser));
  parser->options = *options;
  parser->user_data = user_data;
  file = parser->file = &parser->first;
  if ((result = open_file(parser, file, path, strlen(path))) < 0)
    goto error;
  memcpy(file->origin.octets, options->origin.octets, options->origin.length);
  file->origin.length = options->origin.length;
  parser->buffers.size = buffers->size;
  parser->buffers.owner.serial = 0;
  parser->buffers.owner.blocks = buffers->owner;
  parser->buffers.rdata.blocks = buffers->rdata;
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

int32_t zone_parse(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *path,
  void *user_data)
{
  int32_t result;

  if ((result = zone_open(parser, options, buffers, path, user_data)) < 0)
    return result;
  result = parse(parser, user_data);
  zone_close(parser);
  return result;
}

int32_t zone_parse_string(
  parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *string,
  size_t length,
  void *user_data)
{
  zone_file_t *file;
  int32_t result;

  if (!length || string[length] != '\0')
    return ZONE_BAD_PARAMETER;
  if ((result = check_options(options)) < 0)
    return result;

  memset(parser, 0, sizeof(*parser));
  parser->options = *options;
  parser->user_data = user_data;
  file = parser->file = &parser->first;
  memcpy(file->origin.octets, options->origin.octets, options->origin.length);
  file->origin.length = options->origin.length;
  file->name = (char *)not_a_file;
  file->path = (char *)not_a_file;
  file->handle = NULL;
  file->buffer.index = 0;
  file->buffer.length = length;
  file->buffer.size = length;
  file->buffer.data = (char *)string;
  file->start_of_line = true;
  file->end_of_file = 1;
  file->fields.tape[0] = file->fields.tape[1] = &string[length];
  file->fields.head = file->fields.tape;
  file->fields.tail = file->fields.tape;
  file->lines.tape[0] = 0;
  file->lines.head = file->lines.tape;
  file->lines.tail = file->lines.tape;

  parser->buffers.size = buffers->size;
  parser->buffers.owner.serial = 0;
  parser->buffers.owner.blocks = buffers->owner;
  parser->buffers.rdata.blocks = buffers->rdata;
  file->owner = file->origin;
  file->last_type = 0;
  file->last_class = options->default_class;
  file->last_ttl = options->default_ttl;
  file->line = 1;

  set_defaults(parser);
  result = parse(parser, user_data);
  zone_close(parser);
  return result;
}

zone_nonnull((1,3))
static void print_message(
  zone_parser_t *parser,
  uint32_t category,
  const char *message,
  void *user_data)
{
  FILE *output = category == ZONE_INFO ? stdout : stderr;
  const char *format = "%s:%zu: %s\n";
  (void)user_data;
  fprintf(output, format, parser->file->name, parser->file->line, message);
}

void zone_vlog(
  zone_parser_t *parser,
  uint32_t category,
  const char *format,
  va_list arguments)
{
  char message[2048];
  int length;
  zone_log_t callback = print_message;

  length = vsnprintf(message, sizeof(message), format, arguments);
  assert(length >= 0);
  if ((size_t)length >= sizeof(message))
    memcpy(message+(sizeof(message) - 4), "...", 3);
  if (parser->options.log.callback)
    callback = parser->options.log.callback;

  callback(parser, category, message, parser->user_data);
}

void zone_log(
  zone_parser_t *parser,
  uint32_t category,
  const char *format,
  ...)
{
  va_list arguments;

  if (!(parser->options.log.categories & category))
    return;

  va_start(arguments, format);
  zone_vlog(parser, category, format, arguments);
  va_end(arguments);
}

ZONE_EXPORT extern inline void
zone_error(zone_parser_t *parser, const char *format, ...);

ZONE_EXPORT extern inline void
zone_warning(zone_parser_t *parser, const char *format, ...);

ZONE_EXPORT extern inline void
zone_info(zone_parser_t *parser, const char *format, ...);
