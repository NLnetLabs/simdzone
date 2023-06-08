/*
 * bench.c -- AVX2 compilation target for benchmark function(s)
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"
#include "diagnostic.h"
#include "log.h"
#include "haswell/simd.h"
#include "haswell/bits.h"
#include "lexer.h"
#include "generic/scanner.h"

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

int32_t zone_bench_haswell_lex(zone_parser_t *parser, size_t *tokens)
{
  token_t token;

  (*tokens) = 0;
  lex(parser, &token);
  while (token.code > 0) {
    (*tokens)++;
    lex(parser, &token);
  }

  return token.code ? -1 : 0;
}

diagnostic_pop()
