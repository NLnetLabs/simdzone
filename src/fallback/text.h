/*
 * text.h -- fallback string parser
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TEXT_H
#define TEXT_H

nonnull_all
static really_inline uint32_t unescape(const char *text, uint8_t *wire)
{
  uint8_t d[3];

  if ((d[0] = (uint8_t)text[1] - '0') > 9) {
    *wire = (uint8_t)text[1];
    return 2u;
  } else {
    d[1] = (uint8_t)text[2] - '0';
    d[2] = (uint8_t)text[3] - '0';
    uint32_t o = d[0] * 100 + d[1] * 10 + d[2];
    *wire = (uint8_t)o;
    return (o > 255 || d[1] > 9 || d[2] > 9) ? 0 : 4u;
  }
}

nonnull_all
static really_inline int32_t parse_text_inner(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint32_t skip;
  const char *data = token->data, *limit = token->data + token->length;

  if ((uintptr_t)rdata->limit - (uintptr_t)rdata->octets >= token->length) {
    while (data < limit) {
      *rdata->octets = (uint8_t)*data;
      if (likely(*data != '\\'))
        (void)(rdata->octets += 1), data += 1;
      else if (!(skip = unescape(data, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      else
        (void)(rdata->octets += 1), data += skip;
    }

    if (data != limit)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
    return 0;
  } else {
    while (data < limit && rdata->octets < rdata->limit) {
      *rdata->octets = (uint8_t)*data;
      if (likely(*data != '\\'))
        (void)(rdata->octets += 1), data += 1;
      else if (!(skip = unescape(data, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      else
        (void)(rdata->octets += 1), data += skip;
    }

    if (data != limit || rdata->octets >= rdata->limit)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
    return 0;
  }
}

nonnull_all
static really_inline int32_t parse_string(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  int32_t code;
  uint8_t *octets = rdata->octets;
  uint8_t *limit = rdata->limit;
  if ((uintptr_t)rdata->limit - (uintptr_t)rdata->octets > 1 + 255)
    rdata->limit = rdata->octets + 1 + 255;
  rdata->octets += 1;

  code = parse_text_inner(parser, type, field, rdata, token);
  *octets = (uint8_t)((uintptr_t)rdata->octets - (uintptr_t)octets) - 1;
  rdata->limit = limit;
  return code;
}

nonnull_all
static really_inline int32_t parse_text(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  return parse_text_inner(parser, type, field, rdata, token);
}

#endif // TEXT_H
