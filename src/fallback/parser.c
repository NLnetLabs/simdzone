/*
 * parser.c -- compilation target for fallback (DNS) zone parser
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#define _XOPEN_SOURCE
#include <time.h>
#undef _XOPEN_SOURCE

#include "zone.h"
#include "diagnostic.h"
#include "error.h"
#include "lexer.h"
#include "fallback/scanner.h"
#include "generic/number.h"
#include "generic/ttl.h"
#include "generic/time.h"
#include "fallback/name.h"
#include "fallback/type.h"
#include "generic/ip4.h"
#include "generic/ip6.h"
#include "fallback/text.h"
#include "generic/base16.h"
#include "generic/base32.h"
#include "generic/base64.h"
#include "generic/nsec.h"
#include "parser.h"

diagnostic_push()
clang_diagnostic_ignored(missing-prototypes)

zone_return_t zone_fallback_parse(zone_parser_t *parser, void *user_data)
{
  return parse(parser, user_data);
}

diagnostic_pop()
