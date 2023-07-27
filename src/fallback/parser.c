/*
 * parser.c -- compilation target for fallback (DNS) zone parser
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "zone.h"
#include "diagnostic.h"
#include "log.h"
#include "lexer.h"
#include "table.h"
#include "fallback/scanner.h"
#include "generic/number.h"
#include "generic/ttl.h"
#include "fallback/time.h"
#include "fallback/name.h"
#include "fallback/ip4.h"
#include "generic/ip6.h"
#include "fallback/text.h"
#include "generic/base16.h"
#include "fallback/base32.h"
#include "generic/base64.h"
#include "generic/nsec.h"
#include "generic/caa.h"
#include "generic/ilnp64.h"
#include "visit.h"
#include "types.h"
#include "fallback/type.h"
#include "parser.h"

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

int32_t zone_fallback_parse(zone_parser_t *parser)
{
  return parse(parser);
}

diagnostic_pop()
