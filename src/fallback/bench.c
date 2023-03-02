/*
 * bench.c -- benchmark function(s) for fallback (non-simd) implementation
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"
#include "generic/error.h"
#include "fallback/scanner.h"
#include "generic/lexer.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

zone_return_t zone_bench_fallback_lex(zone_parser_t *parser, size_t *tokens)
{
  zone_token_t token;
  zone_return_t result;

  (*tokens) = 0;
  while ((result = lex(parser, &token)) >= 0 && *token.data)
    (*tokens)++;

  return result;
}

#pragma clang diagnostic pop
