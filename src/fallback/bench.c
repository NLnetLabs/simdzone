/*
 * bench.c -- benchmark function(s) for fallback (non-simd) implementation
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"
#include "diagnostic.h"
#include "heap.h"
#include "log.h"
#include "lexer.h"
#include "fallback/scanner.h"

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

zone_return_t zone_bench_fallback_lex(zone_parser_t *parser, size_t *tokens)
{
  zone_token_t token;
  zone_return_t result;

  (*tokens) = 0;
  while ((result = lex(parser, &token)) >= 0 && token.data != zone_end_of_file)
    (*tokens)++;

  return result;
}

diagnostic_pop()
