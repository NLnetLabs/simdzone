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
#include <stddef.h>

#include "zone.h"

typedef zone_parser_t parser_t; // convenience
typedef zone_file_t file_t;

#include "attributes.h"
#include "diagnostic.h"

#if _MSC_VER
# define strcasecmp(s1, s2) _stricmp(s1, s2)
# define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#endif

static const char not_a_file[] = "<string>";

#include "config.h"
#include "isadetection.h"

#if HAVE_HASWELL
extern int32_t zone_haswell_parse(parser_t *);
#endif

#if HAVE_WESTMERE
extern int32_t zone_westmere_parse(parser_t *);
#endif

extern int32_t zone_fallback_parse(parser_t *);

typedef struct kernel kernel_t;
struct kernel {
  const char *name;
  uint32_t instruction_set;
  int32_t (*parse)(parser_t *);
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
  return kernel->parse(parser);
}

diagnostic_push()
msvc_diagnostic_ignored(4996)

#if _WIN32
nonnull_all
static bool is_separator(int c)
{
  return c == '\\' || c == '/';
}

nonnull_all
static bool is_rooted(const char *s)
{
  if ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'))
    return s[1] == ':';
  return false;
}

nonnull_all
static bool is_relative(const char *s)
{
  // rooted paths can be relative, e.g. C:foo
  if (is_rooted(s))
    return !is_separator((unsigned char)s[2]);
  if (is_separator((unsigned char)s[0]))
    return !(s[1] == '?' || is_separator((unsigned char)s[1]));
  return false;
}

// The Win32 API offers PathIsRelative, but it requires linking with shlwapi.
// Rewriting a relative path is not too complex, unlike correct conversion of
// Windows paths in general (https://googleprojectzero.blogspot.com/2016/02/).
// Rooted paths, relative or not, unc and extended paths are never resolved
// relative to the includer.
nonnull((2,3))
static int32_t resolve_path(
  const char *includer, const char *include, char **path)
{
  // support relative non-rooted paths only
  if (*includer && is_relative(include) && !is_rooted(include)) {
    assert(!is_relative(includer));
    const char *separator = include;
    for (const char *p = include; *p; p++)
      if (is_separator((unsigned char)*p))
        separator = p;
    if (separator - include > INT_MAX)
      return ZONE_OUT_OF_MEMORY;
    char buffer[16];
    int offset = (int)(separator - includer);
    int length = snprintf(
      buffer, sizeof(buffer), "%.*s/%s", offset, includer, include);
    if (length < 0)
      return ZONE_OUT_OF_MEMORY;
    char *absolute;
    if (!(absolute = malloc(length + 1)))
      return ZONE_OUT_OF_MEMORY;
    (void)snprintf(
      absolute, (size_t)length + 1, "%.*s/%s", offset, includer, include);
    *path = _fullpath(NULL, absolute, 0);
    free(absolute);
  } else {
    *path = _fullpath(NULL, include, 0);
  }

  if (*path)
    return 0;
  return (errno == ENOMEM) ? ZONE_OUT_OF_MEMORY : ZONE_NOT_A_FILE;
}
#else
nonnull_all
static int32_t resolve_path(
  const char *includer, const char *include, char **path)
{
  if (*includer && *include != '/') {
    assert(*includer == '/');
    const char *separator = strrchr(includer, '/');
    if (separator - include > INT_MAX)
      return ZONE_OUT_OF_MEMORY;
    char buffer[16];
    int offset = (int)(separator - includer);
    int length = snprintf(
      buffer, sizeof(buffer), "%.*s/%s", offset, includer, include);
    if (length < 0)
      return ZONE_OUT_OF_MEMORY;
    char *absolute;
    if (!(absolute = malloc((size_t)length + 1)))
      return ZONE_OUT_OF_MEMORY;
    (void)snprintf(
      absolute, (size_t)length + 1, "%.*s/%s", offset, includer, include);
    *path = realpath(absolute, NULL);
    free(absolute);
  } else {
    *path = realpath(include, NULL);
  }

  if (*path)
    return 0;
  return (errno == ENOMEM) ? ZONE_OUT_OF_MEMORY : ZONE_NOT_A_FILE;
}
#endif

nonnull((1))
static void close_file(
  parser_t *parser, file_t *file)
{
  assert((file->name == not_a_file) == (file->path == not_a_file));

  const bool is_string = file->name == not_a_file || file->path == not_a_file;

  assert(!is_string || file == &parser->first);
  assert(!is_string || file->handle == NULL);
  (void)parser;

  if (file->buffer.data && !is_string)
    free(file->buffer.data);
  file->buffer.data = NULL;
  if (file->name && file->name != not_a_file)
    free((char *)file->name);
  file->name = NULL;
  if (file->path && file->path != not_a_file)
    free((char *)file->path);
  file->path = NULL;
  if (file->handle)
    (void)fclose(file->handle);
  file->handle = NULL;
}

nonnull_all
static void initialize_file(
  parser_t *parser, file_t *file)
{
  const size_t size = offsetof(file_t, fields.head);
  memset(file, 0, size);

  if (file == &parser->first) {
    file->includer = NULL;
    memcpy(file->origin.octets,
           parser->options.origin.octets,
           parser->options.origin.length);
    file->origin.length = parser->options.origin.length;
    file->last_class = parser->options.default_class;
    file->last_ttl = parser->options.default_ttl;
  } else {
    assert(parser->file);
    file->includer = parser->file;
    memcpy(&file->origin, &parser->file->origin, sizeof(file->origin));
    // retain class and TTL
    file->last_class = parser->file->last_class;
    file->last_ttl = parser->file->last_ttl;
  }

  file->line = 1;
  file->name = (char *)not_a_file;
  file->path = (char *)not_a_file;
  file->handle = NULL;
  file->buffer.data = NULL;
  file->start_of_line = true;
  file->end_of_file = 1;
  file->fields.tape[0] = NULL;
  file->fields.head = file->fields.tail = file->fields.tape;
  file->delimiters.tape[0] = NULL;
  file->delimiters.head = file->delimiters.tail = file->delimiters.tape;
  file->newlines.tape[0] = 0;
  file->newlines.head = file->newlines.tail = file->newlines.tape;
}

nonnull_all
static int32_t open_file(
  parser_t *parser, file_t *file, const char *include, size_t length)
{
  int32_t code;
  const size_t size = ZONE_WINDOW_SIZE + 1 + ZONE_PADDING_SIZE;

  initialize_file(parser, file);

  if (!(file->name = malloc(length + 1)))
    return ZONE_OUT_OF_MEMORY;
  memcpy(file->name, include, length);
  file->name[length] = '\0';
  if (!(file->buffer.data = malloc(size)))
    return (void)close_file(parser, file), ZONE_OUT_OF_MEMORY;
  file->buffer.data[0] = '\0';
  file->buffer.size = ZONE_WINDOW_SIZE;
  file->end_of_file = 0;
  file->fields.tape[0] = &file->buffer.data[0];
  file->fields.tape[1] = &file->buffer.data[0];

  const char *includer = "";
  if (file != &parser->first)
    includer = parser->file->path;
  if ((code = resolve_path(includer, file->name, &file->path)))
    return (void)close_file(parser, file), code;

  if ((file->handle = fopen(file->path, "rb")))
    return 0;

  switch (errno) {
    case ENOMEM:
      code = ZONE_OUT_OF_MEMORY;
      break;
    case EACCES:
      code = ZONE_NOT_PERMITTED;
      break;
    default:
      code = ZONE_NOT_A_FILE;
      break;
  }

  close_file(parser, file);
  return code;
}

diagnostic_pop()

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

nonnull((1))
void zone_close_file(
  parser_t *parser, zone_file_t *file)
{
  if (!file)
    return;
  close_file(parser, file);
  free(file);
}

nonnull_all
int32_t zone_open_file(
  parser_t *parser, const char *path, size_t length, zone_file_t **file)
{
  int32_t code;

  if (!(*file = malloc(sizeof(**file))))
    return ZONE_OUT_OF_MEMORY;
  if ((code = open_file(parser, *file, path, length)) < 0)
    return (void)free(*file), code;
  return 0;
}

nonnull_all
void zone_close(parser_t *parser)
{
  assert(parser);
  for (zone_file_t *file = parser->file, *includer; file; file = includer) {
    includer = file->includer;
    close_file(parser, file);
    if (file != &parser->first)
      free(file);
  }
}

nonnull((1,2,3))
static int32_t initialize_parser(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  void *user_data)
{
  if (!options->accept.callback)
    return ZONE_BAD_PARAMETER;
  if (!options->default_ttl)
    return ZONE_BAD_PARAMETER;
  if (!options->non_strict && options->default_ttl > INT32_MAX)
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

  const size_t size = offsetof(parser_t, file);
  memset(parser, 0, size);
  parser->options = *options;
  parser->user_data = user_data;
  parser->file = &parser->first;
  parser->buffers.size = buffers->size;
  parser->buffers.owner.active = 0;
  parser->buffers.owner.blocks = buffers->owner;
  parser->buffers.rdata.active = 0;
  parser->buffers.rdata.blocks = buffers->rdata;
  parser->owner = &parser->buffers.owner.blocks[0];
  parser->owner->length = 0;
  parser->rdata = &parser->buffers.rdata.blocks[0];

  if (!parser->options.no_includes && !parser->options.include_limit)
    parser->options.include_limit = 10; // arbitrary, default in NSD

  return 0;
}

int32_t zone_open(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *path,
  void *user_data)
{
  int32_t code;

  if ((code = initialize_parser(parser, options, buffers, user_data)) < 0)
    return code;
  if ((code = open_file(parser, &parser->first, path, strlen(path))) < 0)
    return code;
  return 0;
}

diagnostic_pop()

int32_t zone_parse(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *path,
  void *user_data)
{
  int32_t code;

  if ((code = zone_open(parser, options, buffers, path, user_data)) < 0)
    return code;
  code = parse(parser, user_data);
  zone_close(parser);
  return code;
}

int32_t zone_parse_string(
  parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *string,
  size_t length,
  void *user_data)
{
  int32_t code;

  if ((code = initialize_parser(parser, options, buffers, user_data)) < 0)
    return code;
  if (!length || string[length] != '\0')
    return ZONE_BAD_PARAMETER;
  initialize_file(parser, parser->file);
  parser->file->buffer.data = (char *)string;
  parser->file->buffer.size = length;
  parser->file->buffer.length = length;
  parser->file->fields.tape[0] = &string[length];
  parser->file->fields.tape[1] = &string[length];
  assert(parser->file->end_of_file == 1);

  code = parse(parser, user_data);
  zone_close(parser);
  return code;
}

zone_nonnull((1,3))
static void print_message(
  zone_parser_t *parser,
  uint32_t priority,
  const char *message,
  void *user_data)
{
  FILE *output = priority == ZONE_INFO ? stdout : stderr;
  const char *format = "%s:%zu: %s\n";
  (void)user_data;
  fprintf(output, format, parser->file->name, parser->file->line, message);
}

void zone_vlog(
  zone_parser_t *parser,
  uint32_t priority,
  const char *format,
  va_list arguments);

void zone_vlog(
  zone_parser_t *parser,
  uint32_t priority,
  const char *format,
  va_list arguments)
{
  char message[2048];
  int length;
  zone_log_t callback = print_message;

  if (!(priority & ~parser->options.log.mask))
    return;

  length = vsnprintf(message, sizeof(message), format, arguments);
  assert(length >= 0);
  if ((size_t)length >= sizeof(message))
    memcpy(message+(sizeof(message) - 4), "...", 3);
  if (parser->options.log.callback)
    callback = parser->options.log.callback;

  callback(parser, priority, message, parser->user_data);
}

void zone_log(
  zone_parser_t *parser,
  uint32_t priority,
  const char *format,
  ...)
{
  va_list arguments;
  va_start(arguments, format);
  zone_vlog(parser, priority, format, arguments);
  va_end(arguments);
}
