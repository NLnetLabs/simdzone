/*
 * error.c -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

#include "zone.h"
#include "log.h"

zone_nonnull((1,2,4,7))
static void print_message(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  uint32_t category,
  const char *message,
  void *user_data)
{
  FILE *output = category == ZONE_INFO ? stdout : stderr;
  const char *format = "%s:%zu: %s\n";
  (void)file;
  (void)line;
  (void)function;
  (void)user_data;
  fprintf(output, format, parser->file->name, parser->file->line, message);
}

static void log_message(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  uint32_t category,
  const char *format,
  va_list arguments)
{
  char message[2048];
  int length;
  zone_log_t log = print_message;

  length = vsnprintf(message, sizeof(message), format, arguments);
  assert(length >= 0);
  if ((size_t)length >= sizeof(message))
    memcpy(message+(sizeof(message) - 4), "...", 3);
  if (parser->options.log.write)
    log = parser->options.log.write;

  log(parser, file, line, function, category, message, parser->user_data);
}

void zone_log(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  uint32_t category,
  const char *format,
  ...)
{
  va_list ap;

  if (!(parser->options.log.categories & category))
    return;

  va_start(ap, format);
  log_message(parser, file, line, function, category, format, ap);
  va_end(ap);
}

void zone_raise(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  zone_return_t code,
  const char *format,
  ...)
{
  va_list ap;

  va_start(ap, format);
  log_message(parser, file, line, function, ZONE_ERROR, format, ap);
  va_end(ap);
  longjmp((void *)parser->environment, code);
}
