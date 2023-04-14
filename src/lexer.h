/*
 * lexer.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef LEXER_H
#define LEXER_H

#include <assert.h>

extern zone_return_t zone_open_file(
  zone_parser_t *, const zone_string_t *, zone_file_t **);

extern void zone_close_file(
  zone_parser_t *, zone_file_t *);

extern const uint8_t *zone_forward;
extern const uint8_t *zone_jump;
extern const char *zone_end_of_file;

#define ZONE_DELIMITER (0u)
#define ZONE_CONTIGUOUS (1u<<1)
#define ZONE_QUOTED (1u<<2)

typedef zone_string_t zone_token_t;

zone_never_inline()
zone_nonnull_all()
static zone_return_t step(zone_parser_t *parser, zone_token_t *token);

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t lex(zone_parser_t *parser, zone_token_t *token)
{
  do {
    // safe, as tape is doubly terminated
    const char *start = parser->file->indexer.head[0].data;
    const char *end   = parser->file->indexer.head[1].data;
    assert(start < end || (start == end && *start == '\0'));

    switch (zone_jump[ (unsigned char)*start ]) {
      case 0: // contiguous
        *token = (zone_token_t){ (size_t)(end - start), start };
        // discard index for blank or semicolon
        parser->file->indexer.head += zone_forward[ (unsigned char)*end ];
        return ZONE_CONTIGUOUS;
      case 1: // quoted
        *token = (zone_token_t){ (size_t)(end - start), start + 1 };
        // discard index for closing quote
        parser->file->indexer.head += 2;
        return ZONE_QUOTED;
      case 2: // newline
        parser->file->line += parser->file->indexer.head[0].newlines + 1;
        parser->file->indexer.head++;
        if (parser->file->grouped)
          break;
        parser->file->start_of_line = (end - start) == 1;
        *token = (zone_token_t){ 1, start };
        return ZONE_DELIMITER;
      case 3: // end of file
        return step(parser, token);
      case 4: // left parenthesis
        if (parser->file->grouped)
          SYNTAX_ERROR(parser, "Nested opening brace");
        parser->file->indexer.head++;
        parser->file->grouped = true;
        break;
      case 5: // right parenthesis
        if (!parser->file->grouped)
          SYNTAX_ERROR(parser, "Closing brace without opening brace");
        parser->file->indexer.head++;
        parser->file->grouped = false;
        break;
    }
  } while (1);
}

zone_always_inline()
zone_nonnull_all()
static inline void lex_field(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  if (!lex(parser, token))
    SYNTAX_ERROR(parser, "Missing %s in %s record",
                 type->name.data, field->name.data);
}

zone_always_inline()
zone_nonnull_all()
static inline void lex_delimiter(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  zone_token_t *token)
{
  if (lex(parser, token))
    SYNTAX_ERROR(parser, "Trailing data in %s record",
                 type->name.data);
}

#endif // LEXER_H
