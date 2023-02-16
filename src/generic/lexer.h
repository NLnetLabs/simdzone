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

extern const uint8_t *zone_forward;
extern const uint8_t *zone_jump;

zone_always_inline()
zone_nonnull_all()
static inline zone_return_t lex(zone_parser_t *parser, zone_token_t *token)
{
  do {
    // safe, as tape is doubly terminated
    const char *begin = parser->file->indexer.head[0].address;
    const char *end   = parser->file->indexer.head[1].address;

    switch (zone_jump[ (uint8_t)*begin ]) {
      case 0: // contiguous
        *token = (zone_token_t){ end - begin, begin };
        // discard index for blank or semicolon
        parser->file->indexer.head += zone_forward[ (uint8_t)*end ];
        return ZONE_CONTIGUOUS;
      case 1: // quoted
        *token = (zone_token_t){ end - begin, begin + 1 };
        // discard index for closing quote
        parser->file->indexer.head += 2;
        return ZONE_QUOTED;
      case 2: // newline
        parser->file->line += parser->file->indexer.head[0].newlines + 1;
        parser->file->indexer.head++;
        if (parser->file->grouped)
          break;
        parser->file->start_of_line = (end - begin) == 1;
        *token = (zone_token_t){ 1, begin };
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
  const zone_type_info_t *type_info,
  const zone_field_info_t *field_info,
  zone_token_t *token)
{
  if (!lex(parser, token))
    SYNTAX_ERROR(parser, "Missing %s in %s record",
                 type_info->name.data, field_info->name.data);
}

zone_always_inline()
zone_nonnull_all()
static inline void lex_delimiter(
  zone_parser_t *parser,
  const zone_type_info_t *type_info,
  zone_token_t *token)
{
  if (lex(parser, token))
    SYNTAX_ERROR(parser, "Trailing data in %s record", type_info->name.data);
}

#endif // LEXER_H
