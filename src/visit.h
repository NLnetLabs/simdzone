/*
 * visit.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef VISIT_H
#define VISIT_H

static zone_really_inline int32_t accept_rr(zone_parser_t *parser)
{
  zone_return_t result;

  assert(parser->owner->length <= UINT8_MAX);
  assert(parser->rdata->length <= UINT16_MAX);
  result = parser->options.accept.add(
    parser,
    &(zone_name_t){ (uint8_t)parser->owner->length, parser->owner->octets },
    parser->file->last_type,
    parser->file->last_class,
    parser->file->last_ttl,
    (uint16_t)parser->rdata->length,
    parser->rdata->octets,
    parser->user_data);

  assert((size_t)result < parser->cache.size);
  if (result < 0)
    return result;
  parser->rdata = &parser->cache.rdata.blocks[result];
  return 0;
}

#endif // VISIT_H
