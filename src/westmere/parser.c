/*
 * parser.c -- SSE4.2 specific compilation target for (DNS) zone file parser
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#define _XOPEN_SOURCE
#include <time.h>
#undef _XOPEN_SOURCE

#include "zone.h"
#include "westmere/simd.h"
#include "westmere/bits.h"
#include "generic/scanner.h"
#include "generic/lexer.h"
#include "generic/number.h"
#include "generic/ttl.h"
#include "generic/time.h"
#include "generic/name.h"
#include "generic/type.h"
#include "generic/ip4.h"
#include "generic/ip6.h"
#include "generic/text.h"
#include "generic/base16.h"
#include "generic/base32.h"
#include "generic/base64.h"
#include "generic/nsec.h"
#include "generic/parser.h"

zone_diagnostic_push()
zone_clang_diagnostic_ignored(missing-prototypes)

zone_return_t zone_westmere_parse(zone_parser_t *parser, void *user_data)
{
  return parse(parser, user_data);
}

zone_diagnostic_pop()
