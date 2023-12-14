/*
 * text.h -- string parser
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
  uint32_t o;

  if ((d[0] = (uint8_t)text[1] - '0') > 9) {
    o = (uint8_t)text[1];
    *wire = (uint8_t)o;
    return 2u;
  } else {
    d[1] = (uint8_t)text[2] - '0';
    d[2] = (uint8_t)text[3] - '0';
    o = d[0] * 100 + d[1] * 10 + d[2];
    *wire = (uint8_t)o;
    return (o > 255 || d[1] > 9 || d[2] > 9) ? 0 : 4u;
  }
}

typedef struct string_block string_block_t;
struct string_block {
  uint64_t backslashes;
};

nonnull_all
static really_inline void copy_string_block(
  string_block_t *block, const char *text, uint8_t *wire)
{
  simd_8x32_t input;
  simd_loadu_8x32(&input, text);
  simd_storeu_8x32(wire, &input);
  block->backslashes = simd_find_8x32(&input, '\\');
}

nonnull_all
static really_inline int32_t parse_text_inner(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  string_block_t b;
  const char *t = token->data, *te = t + token->length;
  uint64_t left = token->length;

  while ((t < te) & (rdata->octets < rdata->limit)) {
    copy_string_block(&b, t, rdata->octets);
    uint64_t n = 32;
    if (left < 32)
      n = left;
    uint64_t mask = (1llu << n) - 1;

    if (unlikely(b.backslashes & mask)) {
      n = trailing_zeroes(b.backslashes);
      rdata->octets += n; t += n;
      if (!(n = unescape(t, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
      rdata->octets += 1; t += n;
    } else {
      rdata->octets += n; t += n;
    }
  }

  if (rdata->octets >= rdata->limit)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  return 0;
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
  uint8_t *octets = rdata->octets, *limit = rdata->limit;
  if (rdata->limit - rdata->octets > 1 + 255)
    rdata->limit = rdata->octets + 1 + 255;
  rdata->octets += 1;

  code = parse_text_inner(parser, type, field, rdata, token);
  *octets = (uint8_t)((rdata->octets - octets) - 1);
  rdata->limit = limit;
  return code;
}

nonnull_all
static really_inline int32_t parse_text(
  zone_parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  return parse_text_inner(parser, type, field, rdata, token);
}

#endif // TEXT_H
