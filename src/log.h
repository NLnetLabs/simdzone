/*
 * zone.h -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_LOG_H
#define ZONE_LOG_H

#include "zone.h"

#define SYNTAX_ERROR(par, ...) \
  do { zone_error(par, __VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0)
#define SEMANTIC_ERROR(par, ...) \
  do { zone_error(par, __VA_ARGS__); return ZONE_SEMANTIC_ERROR; } while (0)

#endif // ZONE_LOG_H
