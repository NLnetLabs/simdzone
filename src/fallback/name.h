/*
 * name.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NAME_H
#define NAME_H

zone_nonnull_all
static zone_really_inline int32_t scan_name(
  zone_parser_t *parser,
  const token_t *token,
  uint8_t octets[255 + ZONE_BLOCK_SIZE],
  size_t *lengthp)
{
  uint8_t *l = octets, *w = octets + 1;
  const uint8_t *we = octets + 255;
  const char *t = token->data, *te = t + token->length;

  (void)parser;

  l[0] = 0;

  if (*t == '.')
    return (*lengthp = token->length) == 1 ? 0 : -1;

  while ((t < te) & (w < we)) {
    *w = (uint8_t)*t;
    if (*t == '\\') {
      uint32_t n;
      if (!(n = unescape(t, w)))
        return -1;
      w += 1; t += n;
    } else if (*t == '.') {
      if ((w - 1) - l > 63 || (w - 1) - l == 0)
        return -1;
      l[0] = (uint8_t)((w - 1) - l);
      l = w;
      l[0] = 0;
      w += 1; t += 1;
    } else {
      w += 1; t += 1;
    }
  }

  if ((w - 1) - l > 63)
    return -1;
  *l = (uint8_t)((w - 1) - l);

  if (t != te || w >= we)
    return -1;

  *lengthp = (size_t)(w - octets);
  return *l != 0;
}

zone_nonnull_all
static zone_really_inline int32_t parse_name(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  size_t n = 0;
  uint8_t *o = &parser->rdata->octets[parser->rdata->length];

  if (zone_likely(token->code == CONTIGUOUS)) {
    // a freestanding "@" denotes the current origin
    if (token->data[0] == '@' && token->length > 1)
      goto relative;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r > 0)
      goto relative;
  } else if (token->code == QUOTED) {
    if (token->length == 0)
      goto invalid;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->rdata->length += n), ZONE_NAME;
    if (r > 0)
      goto relative;
  } else {
    return have_string(parser, type, field, token);
  }

invalid:
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

relative:
  if (n > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  memcpy(o+n, parser->file->origin.octets, parser->file->origin.length);
  parser->rdata->length += n + parser->file->origin.length;
  return ZONE_NAME;
}

#endif // NAME_H
