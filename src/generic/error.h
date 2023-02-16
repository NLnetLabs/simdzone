/*
 * generic/error.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ERROR_H
#define ERROR_H

#include <stdarg.h>
#include <stdint.h>

#include "zone.h"

ZONE_EXPORT void zone_raise_error(
  zone_parser_t *parser,
  zone_return_t code,
  const char *file,
  uint32_t line,
  const char *function,
  zone_format_string(const char *format),
  ...)
zone_nonnull((1,3,5,6))
zone_format_printf(6,7)
zone_noreturn();

#define RAISE_ERROR(parser, code, ...) \
  zone_raise_error(parser, code, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define SYNTAX_ERROR(parser, ...) \
  RAISE_ERROR(parser, ZONE_SYNTAX_ERROR, __VA_ARGS__)

#define SEMANTIC_ERROR(parser, ...) \
  RAISE_ERROR(parser, ZONE_SEMANTIC_ERROR, __VA_ARGS__)

#define NOT_IMPLEMENTED(parser, ...) \
  RAISE_ERROR(parser, ZONE_NOT_IMPLEMENTED, __VA_ARGS__)

#define OUT_OF_MEMORY(parser, ...) \
  RAISE_ERROR(parser, ZONE_OUT_OF_MEMORY, __VA_ARGS__)

#endif // ERROR_H
