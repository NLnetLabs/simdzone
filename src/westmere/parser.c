/*
 * parser.c -- SSE4.2 specific compilation target for (DNS) zone file parser
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "zone.h"
#include "diagnostic.h"
#include "log.h"
#include "westmere/simd.h"
#include "westmere/bits.h"
#include "lexer.h"
#include "table.h"
#include "generic/scanner.h"
#include "generic/number.h"
#include "generic/ttl.h"
#include "westmere/time.h"
#include "westmere/ip4.h"
#include "generic/ip6.h"
#include "generic/text.h"
#include "generic/name.h"
#include "fallback/base16.h"
#include "westmere/base32.h"
#include "generic/base64.h"
#include "generic/nsec.h"
#include "generic/caa.h"
#include "generic/ilnp64.h"
#include "fallback/eui.h"
#include "fallback/nsap.h"
#include "types.h"
#include "westmere/type.h"
#include "parser.h"

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

int32_t zone_westmere_parse(zone_parser_t *parser)
{
  return parse(parser);
}

diagnostic_pop()
