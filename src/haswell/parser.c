/*
 * parser.c -- AVX2 specific compilation target for (DNS) zone file parser
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#define _XOPEN_SOURCE
#include <time.h>
#include "haswell/simd.h"
#include "haswell/bits.h"
#include "parser.h"

zone_return_t zone_parse_haswell(zone_parser_t *parser, void *user_data)
{
  //printf("using %s\n", __func__);
  return parse(parser, user_data);
}
