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
#include <setjmp.h>

#include "zone.h"
#include "error.h"

zone_nonnull((1,2))
static void vlog(
  zone_parser_t *parser,
  const char *format,
  va_list ap)
{
  (void)parser;
  vfprintf(stderr, format, ap);
  fputs("\n", stderr);
}

void zone_error(
  zone_parser_t *parser,
  zone_return_t code,
  const char *file,
  uint32_t line,
  const char *function,
  const char *format,
  ...)
{
  va_list ap;

  (void)code;
  (void)file;
  (void)line;
  (void)function;

  va_start(ap, format);
  vlog(parser, format, ap);
  va_end(ap);
}

void zone_raise_error(
  zone_parser_t *parser,
  zone_return_t code,
  const char *file,
  uint32_t line,
  const char *function,
  const char *format,
  ...)
{
  va_list ap;

  (void)file;
  (void)line;
  (void)function;

  va_start(ap, format);
  vlog(parser, format, ap);
  va_end(ap);
  longjmp((void *)parser->environment, code);
}
