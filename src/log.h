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
#include <stdbool.h>

#include "zone.h"

#define NAME(info) ((info)->name.data)

#define RAISE(parser, code, ...) \
  do { \
    ZONE_LOG(parser, ZONE_ERROR, __VA_ARGS__); \
    return code; \
  } while (0)

#define SYNTAX_ERROR(parser, ...) \
  RAISE(parser, ZONE_SYNTAX_ERROR, __VA_ARGS__)

// semantic errors in the zone format are special as a secondary may choose
// to report, but otherwise ignore them. e.g. a TTL with the MSB set. cases
// where the data can be presented in wire format but is otherwise considered
// invalid. e.g. a TTL is limited to 32-bits, values that require more bits
// are invalid without exception, but secondaries may choose to accept values
// with the MSB set in order to update the zone
#define SEMANTIC_ERROR(parser, ...) \
  do { \
    ZONE_LOG(parser, ZONE_ERROR, __VA_ARGS__); \
    if (!parser->options.secondary) \
      return ZONE_SEMANTIC_ERROR; \
  } while (0)

#define NOT_IMPLEMENTED(parser, ...) \
  RAISE(parser, ZONE_NOT_IMPLEMENTED, __VA_ARGS__)

#define OUT_OF_MEMORY(parser, ...) \
  RAISE(parser, ZONE_OUT_OF_MEMORY, __VA_ARGS__)

#define NOT_PERMITTED(parser, ...) \
  RAISE(parser, ZONE_NOT_PERMITTED, __VA_ARGS__)

#endif // LOG_H
