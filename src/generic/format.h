/*
 * format.h
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef FORMAT_H
#define FORMAT_H

#define FIELDS(fields) \
  { (sizeof(fields)/sizeof(fields[0])), fields }

#define FIELD(name) \
  { { { name, sizeof(name) - 1 } } }

#define ENTRY(name, fields) \
  { { { name, sizeof(name) - 1 }, 0 }, 0, false, false, fields, 0, 0 }

nonnull_all
static really_inline int32_t parse_type(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint16_t code;
  const mnemonic_t *mnemonic;

  if (scan_type(token->data, token->length, &code, &mnemonic) != 1)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  code = htobe16(code);
  memcpy(rdata->octets, &code, 2);
  rdata->octets += 2;
  return 0;
}

nonnull_all
static really_inline int32_t parse_name(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  size_t length = 0;

  if (likely(is_contiguous(token))) {
    // a freestanding "@" denotes the current origin
    if (token->length == 1 && token->data[0] == '@')
      goto relative;
    switch (scan_name(token->data, token->length, rdata->octets, &length)) {
      case 0:
        rdata->octets += length;
        return 0;
      case 1:
        goto relative;
    }
  } else if (is_quoted(token)) {
    if (token->length == 0)
      goto invalid;
    switch (scan_name(token->data, token->length, rdata->octets, &length)) {
      case 0:
        rdata->octets += length;
        return 0;
      case 1:
        goto relative;
    }
  }

invalid:
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

relative:
  if (length > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  memcpy(rdata->octets + length, parser->file->origin.octets, parser->file->origin.length);
  rdata->octets += length + parser->file->origin.length;
  return 0;
}

nonnull_all
static really_inline int32_t parse_owner(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  const token_t *token)
{
  size_t length = 0;
  uint8_t *octets = parser->file->owner.octets;

  if (likely(is_contiguous(token))) {
    // a freestanding "@" denotes the origin
    if (token->length == 1 && token->data[0] == '@')
      goto relative;
    switch (scan_name(token->data, token->length, octets, &length)) {
      case 0:
        parser->file->owner.length = length;
        parser->owner = &parser->file->owner;
        return 0;
      case 1:
        goto relative;
    }
  } else {
    assert(is_quoted(token));
    if (token->length == 0)
      goto invalid;
    switch (scan_name(token->data, token->length, octets, &length)) {
      case 0:
        parser->file->owner.length = length;
        parser->owner = &parser->file->owner;
        return 0;
      case 1:
        goto relative;
    }
  }

invalid:
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

relative:
  if (length > 255 - parser->file->origin.length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  memcpy(octets+length, parser->file->origin.octets, parser->file->origin.length);
  parser->file->owner.length = length + parser->file->origin.length;
  parser->owner = &parser->file->owner;
  return 0;
}

nonnull_all
static really_inline int32_t parse_rr(
  parser_t *parser, token_t *token)
{
  static const rdata_info_t fields[] = {
    FIELD("OWNER"),
    FIELD("TYPE"),
    FIELD("CLASS"),
    FIELD("TTL")
  };

  static const type_info_t rr = ENTRY("RR", FIELDS(fields));

  int32_t code;
  const type_info_t *descriptor;
  rdata_t rdata = { parser->rdata->octets, parser->rdata->octets + 65535 };

  if (parser->file->start_of_line) {
    if ((code = have_contiguous_or_quoted(parser, &rr, &fields[0], token)) < 0)
      return code;
    if ((code = parse_owner(parser, &rr, &fields[0], token)) < 0)
      return code;
    if ((code = take_contiguous(parser, &rr, &fields[1], token)) < 0)
      return code;
  } else {
    if ((code = have_contiguous(parser, &rr, &fields[1], token)) < 0)
      return code;
  }

  const mnemonic_t *mnemonic;

  if ((uint8_t)token->data[0] - '0' < 10) {
    if (!scan_ttl(token->data, token->length, parser->options.pretty_ttls, &parser->file->last_ttl))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[3]), NAME(&rr));
    if (parser->file->last_ttl & (1u << 31))
      SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(&fields[3]), NAME(&rr));
    goto class_or_type;
  } else {
    switch (scan_type_or_class(token->data, token->length, &parser->file->last_type, &mnemonic)) {
      case 1:
        goto rdata;
      case 2:
        parser->file->last_class = parser->file->last_type;
        goto ttl_or_type;
      default:
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), NAME(&rr));
    }
  }

ttl_or_type:
  if ((code = take_contiguous(parser, &rr, &fields[1], token)) < 0)
    return code;
  if ((uint8_t)token->data[0] - '0' < 10) {
    if (!scan_ttl(token->data, token->length, parser->options.pretty_ttls, &parser->file->last_ttl))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[3]), NAME(&rr));
    if (parser->file->last_ttl & (1u << 31))
      SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(&fields[3]), NAME(&rr));
    goto type;
  } else {
    if (unlikely(scan_type(token->data, token->length, &parser->file->last_type, &mnemonic) != 1))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), NAME(&rr));
    goto rdata;
  }

class_or_type:
  if ((code = take_contiguous(parser, &rr, &fields[1], token)) < 0)
    return code;
  switch (scan_type_or_class(token->data, token->length, &parser->file->last_type, &mnemonic)) {
    case 1:
      goto rdata;
    case 2:
      parser->file->last_class = parser->file->last_type;
      goto type;
    default:
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), NAME(&rr));
  }

type:
  if ((code = take_contiguous(parser, &rr, &fields[1], token)) < 0)
    return code;
  if (unlikely(scan_type(token->data, token->length, &parser->file->last_type, &mnemonic) != 1))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), NAME(&rr));

rdata:
  descriptor = (const type_info_t *)mnemonic;

  // RFC3597
  // parse generic rdata if rdata starts with "\\#"
  take(parser, token);
  if (likely(token->data[0] != '\\'))
    return descriptor->parse(parser, descriptor, &rdata, token);
  else if (is_contiguous(token) && strncmp(token->data, "\\#", token->length) == 0)
    return parse_generic_rdata(parser, descriptor, &rdata, token);
  else
    return descriptor->parse(parser, descriptor, &rdata, token);
}

// RFC1035 section 5.1
// $INCLUDE <file-name> [<domain-name>] [<comment>]
nonnull_all
static really_inline int32_t parse_dollar_include(
  parser_t *parser, token_t *token)
{
  static const rdata_info_t fields[] = {
    FIELD("file-name"),
    FIELD("domain-name")
  };

  static const type_info_t include = ENTRY("$INCLUDE", FIELDS(fields));

  if (parser->options.no_includes)
    NOT_PERMITTED(parser, "%s is disabled", NAME(&include));

  int32_t code;
  file_t *file;
  if ((code = take_quoted_or_contiguous(parser, &include, &fields[0], token)) < 0)
    return code;
  if ((code = zone_open_file(parser, token->data, token->length, &file)) < 0)
    return code;

  name_buffer_t name;
  const name_buffer_t *origin = &parser->file->origin;

  // $INCLUDE directive MAY specify an origin
  take(parser, token);
  if (is_contiguous_or_quoted(token)) {
    if (scan_name(token->data, token->length, name.octets, &name.length) != 0) {
      zone_close_file(parser, file);
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), NAME(&include));
    }
    origin = &name;
    take(parser, token);
  }

  // store the current owner to restore later if necessary
  file_t *includer;
  includer = parser->file;
  includer->owner = *parser->owner;
  file->includer = includer;
  file->owner = *origin;
  file->origin = *origin;
  file->last_type = 0;
  file->last_class = includer->last_class;
  file->last_ttl = includer->last_ttl;
  file->line = 1;

  if (!is_delimiter(token)) {
    zone_close_file(parser, file);
    return have_delimiter(parser, &include, token);
  }

  // check for recursive includes
  do {
    if (strcmp(includer->path, file->path) != 0)
      continue;
    zone_close_file(parser, file);
    SYNTAX_ERROR(parser, "Circular include in %s", NAME(&include));
  } while ((includer = includer->includer));

  parser->file->line += parser->file->span;
  parser->file->span = 0;
  parser->file = file;
  return 0;
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
nonnull_all
static inline int32_t parse_dollar_origin(
  parser_t *parser, token_t *token)
{
  static const rdata_info_t fields[] = { FIELD("name") };
  static const type_info_t origin = ENTRY("$ORIGIN", FIELDS(fields));
  int32_t code;

  if ((code = take_contiguous_or_quoted(parser, &origin, &fields[0], token)) < 0)
    return code;
  if (scan_name(token->data, token->length, parser->file->origin.octets, &parser->file->origin.length) != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), NAME(&origin));
  if ((code = take_delimiter(parser, &origin, token)) < 0)
    return code;

  parser->file->line += parser->file->span;
  parser->file->span = 0;
  return code;
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
nonnull_all
static really_inline int32_t parse_dollar_ttl(
  parser_t *parser, token_t *token)
{
  static const rdata_info_t fields[] = { FIELD("ttl") };
  static const type_info_t ttl = ENTRY("$TTL", FIELDS(fields));
  int32_t code;

  if ((code = take_contiguous(parser, &ttl, &fields[0], token)) < 0)
    return code;
  if (!scan_ttl(token->data, token->length, parser->options.pretty_ttls, &parser->file->default_ttl))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), NAME(&ttl));
  if (parser->file->default_ttl & (1u << 31))
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(&fields[0]), NAME(&ttl));
  if ((code = take_delimiter(parser, &ttl, token)) < 0)
    return code;

  parser->file->last_ttl = parser->file->default_ttl;
  parser->file->line += parser->file->span;
  parser->file->span = 0;
  return 0;
}

static inline int32_t parse(parser_t *parser)
{
  int32_t code = 0;
  token_t token;

  while (code >= 0) {
    take(parser, &token);
    if (likely(is_contiguous(&token))) {
      if (!parser->file->start_of_line || token.data[0] != '$')
        code = parse_rr(parser, &token);
      else if (token.length == 4 && memcmp(token.data, "$TTL", 4) == 0)
        code = parse_dollar_ttl(parser, &token);
      else if (token.length == 7 && memcmp(token.data, "$ORIGIN", 7) == 0)
        code = parse_dollar_origin(parser, &token);
      else if (token.length == 8 && memcmp(token.data, "$INCLUDE", 8) == 0)
        code = parse_dollar_include(parser, &token);
      else
        code = parse_rr(parser, &token);
    } else if (is_quoted(&token)) {
      code = parse_rr(parser, &token);
    } else if (is_end_of_file(&token)) {
      if (parser->file->end_of_file == ZONE_NO_MORE_DATA)
        break;
    }
  }

  return code;
}

#endif // FORMAT_H
