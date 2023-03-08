/*
 * bench.c -- SSE4.2 compilation target for benchmark function(s)
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"
#include "westmere/simd.h"
#include "westmere/bits.h"
#include "generic/scanner.h"
#include "generic/lexer.h"

zone_diagnostic_push()
zone_clang_diagnostic_ignored(missing-prototypes)

zone_return_t zone_bench_westmere_lex(zone_parser_t *parser, size_t *tokens)
{
  zone_token_t token;
  zone_return_t result;

  (*tokens) = 0;
  while ((result = lex(parser, &token)) >= 0 && *token.data)
    (*tokens)++;

  return result;
}

zone_diagnostic_pop()
