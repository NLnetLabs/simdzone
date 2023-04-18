/*
 * log.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdint.h>

#include "zone.h"

ZONE_EXPORT
zone_noreturn()
void zone_raise(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  zone_return_t code,
  const char *format,
  ...)
zone_nonnull((1,2,4,6))
zone_format_printf(6,7);

#define RAISE(parser, code, ...) \
  zone_raise(parser, __FILE__, __LINE__, __func__, code, __VA_ARGS__)

#define SYNTAX_ERROR(parser, ...) \
  RAISE(parser, ZONE_SYNTAX_ERROR, __VA_ARGS__)

#define SEMANTIC_ERROR(parser, ...) \
  RAISE(parser, ZONE_SEMANTIC_ERROR, __VA_ARGS__)

#define NOT_IMPLEMENTED(parser, ...) \
  RAISE(parser, ZONE_NOT_IMPLEMENTED, __VA_ARGS__)

#define OUT_OF_MEMORY(parser, ...) \
  RAISE(parser, ZONE_OUT_OF_MEMORY, __VA_ARGS__)

#define NOT_PERMITTED(parser, ...) \
  RAISE(parser, ZONE_NOT_PERMITTED, __VA_ARGS__)

#endif // LOG_H
