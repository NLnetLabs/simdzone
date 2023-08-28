/*
 * parser.h -- recursive descent parser for (DNS) zone data
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef PARSER_H
#define PARSER_H

zone_nonnull_all
static zone_really_inline int32_t parse_owner(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  size_t n = 0;
  uint8_t *o = parser->file->owner.octets;

  if (zone_likely(token->code == CONTIGUOUS)) {
    // a freestanding "@" denotes the origin
    if (token->data[0] == '@' && !is_contiguous((uint8_t)token->data[1]))
      goto relative;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->owner->length = n), ZONE_NAME;
    if (r > 0)
      goto relative;
  } else if (token->code == QUOTED) {
    if (token->length == 0)
      goto invalid;
    r = scan_name(parser, token, o, &n);
    if (r == 0)
      return (void)(parser->owner->length = n), ZONE_NAME;
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
  parser->owner->length = n + parser->file->origin.length;
  return ZONE_NAME;
}

zone_nonnull_all
static zone_really_inline int32_t parse_rr(
  zone_parser_t *parser, token_t *token)
{
  static const zone_type_info_t unknown =
    { { { "record", 6 }, 0 }, 0, { 0, NULL } };
  static const zone_field_info_t owner =
    { { 5, "owner" }, ZONE_NAME, 0, { 0 } };
  static const zone_field_info_t ttl =
    { { 3, "ttl" }, ZONE_INT32, 0, { 0 } };
  static const zone_field_info_t type =
    { { 4, "type" }, ZONE_INT16, 0, { 0 } };
  static const zone_string_t backslash_hash = { 2, "\\#" };

  int32_t r;
  const type_descriptor_t *descriptor;
  uint16_t code;
  uint32_t epoch;
  const zone_symbol_t *symbol;

  if (parser->file->start_of_line) {
    parse_owner(parser, &unknown, &owner, token);
    lex(parser, token);
  }

  if ((uint8_t)token->data[0] - '0' <= 9) {
    if ((r = scan_ttl(parser, &unknown, &ttl, token, &epoch)) < 0)
      return r;
    goto class_or_type;
  } else {
    r = scan_type_or_class(parser, &unknown, &type, token, &code, &symbol);
    if (zone_likely(r == ZONE_TYPE)) {
      parser->file->last_type = code;
      goto rdata;
    } else if (r == ZONE_CLASS) {
      parser->file->last_class = code;
      goto ttl_or_type;
    } else {
      assert(r < 0);
      return r;
    }
  }

ttl_or_type:
  lex(parser, token);
  if ((uint8_t)token->data[0] - '0' <= 9) {
    if ((r = scan_ttl(parser, &unknown, &ttl, token, &epoch)) < 0)
      return r;
    goto type;
  } else {
    if ((r = scan_type(parser, &unknown, &type, token, &code, &symbol)) < 0)
      return r;
    parser->file->last_type = code;
    goto rdata;
  }

class_or_type:
  lex(parser, token);
  r = scan_type_or_class(parser, &unknown, &type, token, &code, &symbol);
  if (zone_likely(r == ZONE_TYPE)) {
    parser->file->last_type = code;
    goto rdata;
  } else if (r == ZONE_CLASS) {
    parser->file->last_class = code;
    goto type;
  } else {
    assert(r < 0);
    return r;
  }

type:
  lex(parser, token);
  if ((r = scan_type(parser, &unknown, &type, token, &code, &symbol)) < 0)
    return r;
  parser->file->last_type = code;

rdata:
  descriptor = (type_descriptor_t *)symbol;

  parser->rdata->length = 0;

  // RFC3597
  // parse generic rdata if rdata starts with "\\#"
  lex(parser, token);
  if (zone_likely(token->data[0] != '\\'))
    return descriptor->parse(parser, &descriptor->info, token);
  else if (token->code == CONTIGUOUS && compare(token, &backslash_hash) == 0)
    return parse_generic_rdata(parser, &descriptor->info, token);
  else
    return descriptor->parse(parser, &descriptor->info, token);
}

// RFC1035 section 5.1
// $INCLUDE <file-name> [<domain-name>] [<comment>]
zone_nonnull_all
static zone_really_inline int32_t parse_dollar_include(
  zone_parser_t *parser, token_t *token)
{
  static const zone_field_info_t fields[] = {
    { { 9, "file-name" }, ZONE_STRING, 0, { 0 } },
    { { 11, "domain-name" }, ZONE_NAME, 0, { 0 } }
  };
  static const zone_type_info_t type =
    { { { "$INCLUDE", 8 }, 0 }, 0, { 1, fields } };

  int32_t r;
  zone_file_t *includer, *file;
  zone_name_buffer_t name;
  const zone_name_buffer_t *origin = &parser->file->origin;
  const uint8_t *delimiters;

  if (parser->options.no_includes)
    NOT_PERMITTED(parser, "$INCLUDE directive is disabled");
  lex(parser, token);
  if (token->code == CONTIGUOUS)
    delimiters = contiguous;
  else if (token->code == QUOTED)
    delimiters = quoted;
  else
    return have_string(parser, &type, &fields[0], token);

  // FIXME: a more elegant solution probably exists
  const char *p = token->data;
  for (; delimiters[(uint8_t)*p] == token->code; p++) ;
  const size_t n = (size_t)(p - token->data);

  if ((r = zone_open_file(parser, &(zone_string_t){ n, token->data }, &file)) < 0)
    return r;

  // $INCLUDE directive may specify an origin
  lex(parser, token);
  if (token->code == CONTIGUOUS) {
    r = scan_name(parser, token, name.octets, &name.length);
    if (r != 0)
      goto invalid_name;
    origin = &name;
    lex(parser, token);
  } else if (token->code == QUOTED) {
    if (token->length == 0)
      goto invalid_name;
    r = scan_name(parser, token, name.octets, &name.length);
    if (r != 0)
      goto invalid_name;
    origin = &name;
    lex(parser, token);
  }

  // store the current owner to restore later if necessary
  includer = parser->file;
  includer->owner = *parser->owner;
  file->includer = includer;
  file->owner = *origin;
  file->origin = *origin;
  file->last_type = 0;
  file->last_class = includer->last_class;
  file->last_ttl = includer->last_ttl;
  file->line = 1;

  if ((r = have_delimiter(parser, &type, token)) < 0)
    return r;

  // check for recursive includes
  do {
    if (strcmp(includer->path, file->path) != 0)
      continue;
    zone_close_file(parser, file);
    SYNTAX_ERROR(parser, "Circular include in $INCLUDE directive");
  } while ((includer = includer->includer));

  parser->file = file;
  return 0;
invalid_name:
  zone_close_file(parser, file);
  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&fields[1]), TNAME(&type));
}

// RFC1035 section 5.1
// $ORIGIN <domain-name> [<comment>]
zone_nonnull((1,2))
static inline int32_t parse_dollar_origin(
  zone_parser_t *parser, token_t *token)
{
  static const zone_field_info_t field =
    { { 4, "name" }, ZONE_NAME, 0, { 0 } };
  static const zone_type_info_t type =
    { { { "$ORIGIN", 7 }, 0 }, 0, { 1, &field } };

  int32_t r;

  lex(parser, token);
  if (zone_likely(token->code == CONTIGUOUS))
    r = scan_name(parser, token,
                             parser->file->origin.octets,
                            &parser->file->origin.length);
  else if (token->code == QUOTED)
    r = scan_name(parser, token,
                         parser->file->origin.octets,
                        &parser->file->origin.length);
  else
    return have_string(parser, &type, &field, token);

  if (r != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(&field), TNAME(&type));

  lex(parser, token);
  return have_delimiter(parser, &type, token);
}

// RFC2308 section 4
// $TTL <TTL> [<comment>]
zone_nonnull((1,2))
static inline int32_t parse_dollar_ttl(
  zone_parser_t *parser, token_t *token)
{
  static const zone_field_info_t field =
    { { 3, "ttl" }, ZONE_INT32, 0, { 0 } };
  static const zone_type_info_t type =
    { { { "$TTL", 4 }, 0 }, 0, { 1, &field } };

  int32_t r;

  lex(parser, token);
  if ((r = scan_ttl(parser, &type, &field, token,
                   &parser->file->last_ttl)) < 0)
    return r;
  lex(parser, token);
  if ((r = have_delimiter(parser, &type, token)) < 0)
    return r;

  parser->file->default_ttl = parser->file->last_ttl;
  return 0;
}

static inline int32_t parse(zone_parser_t *parser)
{
  static const zone_string_t ttl = { 4, "$TTL" };
  static const zone_string_t origin = { 7, "$ORIGIN" };
  static const zone_string_t include = { 8, "$INCLUDE" };

  int32_t r = 0;
  token_t token;

  while (r >= 0) {
    lex(parser, &token);
    if (zone_likely(token.code == CONTIGUOUS)) {
      if (!parser->file->start_of_line || token.data[0] != '$')
        r = parse_rr(parser, &token);
      else if (compare(&token, &ttl) == 0)
        r = parse_dollar_ttl(parser, &token);
      else if (compare(&token, &origin) == 0)
        r = parse_dollar_origin(parser, &token);
      else if (compare(&token, &include) == 0)
        r = parse_dollar_include(parser, &token);
      else
        r = parse_rr(parser, &token);
    } else if (token.code == QUOTED) {
      r = parse_rr(parser, &token);
    } else if (token.code == END_OF_FILE) {
      if (parser->file->end_of_file == ZONE_NO_MORE_DATA)
        break;
    }
  }

  return r;
}

#endif // PARSER_H
