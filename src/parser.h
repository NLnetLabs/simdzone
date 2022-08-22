/*
 * parser.h -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_PARSER_H
#define ZONE_PARSER_H

#include "scanner.h"

typedef zone_return_t(*rdata_parse_t)(
  zone_parser_t *, zone_token_t *);

typedef zone_return_t(*rdata_accept_t)(
  zone_parser_t *, zone_field_t *, void *);

struct rdata_descriptor {
  zone_field_descriptor_t base;
  rdata_parse_t typed;
  rdata_parse_t generic;
  rdata_accept_t accept;
};

struct type_descriptor {
  zone_type_descriptor_t base;
  const struct rdata_descriptor *rdata;
};

#endif // ZONE_PARSER_H
