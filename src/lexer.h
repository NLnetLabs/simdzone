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

extern int32_t zone_open_file(
  zone_parser_t *, const zone_string_t *, zone_file_t **);

extern void zone_close_file(
  zone_parser_t *, zone_file_t *);

typedef struct token token_t;
struct token {
  int32_t code;
  const char *data;
};

// sorted so that errors, end of file and line feeds are less than contiguous
#define END_OF_FILE (0)
#define CONTIGUOUS (1<<0)
#define QUOTED (1<<1)
#define LINE_FEED (1<<2)
#define LEFT_PAREN (1<<4)
#define RIGHT_PAREN (1<<5)
#define BLANK (1<<6)
#define COMMENT (1<<7)

static const uint8_t contiguous[256] = {
  // 0x00 = "\0"
  0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x00 - 0x07
  // 0x09 = "\t", 0x0a = "\n", 0x0d = "\r"
  0x01, 0x40, 0x04, 0x01, 0x01, 0x40, 0x01, 0x01,  // 0x08 - 0x0f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x10 - 0x17
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x18 - 0x1f
  // 0x20 = " ", 0x22 = "\""
  0x40, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x20 - 0x27
  // 0x28 = "(", 0x29 = ")"
  0x10, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x28 - 0x2f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x30 - 0x37
  // 0x3b = ";"
  0x01, 0x01, 0x01, 0x80, 0x01, 0x01, 0x01, 0x01,  // 0x38 - 0x3f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x40 - 0x47
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x48 - 0x4f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x50 - 0x57
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x58 - 0x5f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x60 - 0x67
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x68 - 0x6f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x70 - 0x77
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x78 - 0x7f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x80 - 0x87
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x88 - 0x8f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x90 - 0x97
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x98 - 0x9f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xa0 - 0xa7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xa8 - 0xaf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xb0 - 0xb7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xb8 - 0xbf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xc0 - 0xc7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xc8 - 0xcf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xd0 - 0xd7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xd8 - 0xdf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xe0 - 0xe7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xe8 - 0xef
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0xf8 - 0xf7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01   // 0xf8 - 0xff
};

static const uint8_t quoted[256] = {
  // 0x00 = "\0"
  0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x00 - 0x07
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x08 - 0x0f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x10 - 0x17
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x18 - 0x1f
  // 0x22 = "\""
  0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x20 - 0x27
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x28 - 0x2f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x30 - 0x37
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x30 - 0x3f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x40 - 0x47
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x40 - 0x4f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x50 - 0x57
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x50 - 0x5f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x60 - 0x67
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x60 - 0x6f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x70 - 0x77
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x70 - 0x7f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x80 - 0x87
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x80 - 0x8f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x90 - 0x97
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x90 - 0x9f
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xa0 - 0xa7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xa0 - 0xaf
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xb0 - 0xb7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xb0 - 0xbf
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xc0 - 0xc7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xc0 - 0xcf
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xd0 - 0xd7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xd0 - 0xdf
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xe0 - 0xe7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xe0 - 0xef
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0xf0 - 0xf7
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02   // 0xf0 - 0xff
};

//
// special buffer used to mark newlines with additional embedded newline count
//
static const char line_feed[ZONE_BLOCK_SIZE] = { '\n', '\0' };

zone_nonnull_all
static zone_never_inline void step(zone_parser_t *parser, token_t *token);

zone_nonnull_all
zone_warn_unused_result
static zone_really_inline int32_t have_contiguous(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code == CONTIGUOUS))
    return token->code;
  else if (token->code < 0)
    return token->code;
  else if (token->code == QUOTED)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  assert(token->code == END_OF_FILE || token->code == LINE_FEED);
  SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), NAME(type));
}

zone_nonnull_all
zone_warn_unused_result
static zone_really_inline int32_t have_string(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  if (zone_likely(token->code & (CONTIGUOUS | QUOTED)))
    return token->code;
  else if (token->code < 0)
    return token->code;
  assert(token->code == END_OF_FILE || token->code == LINE_FEED);
  SYNTAX_ERROR(parser, "Missing %s in %s", NAME(field), NAME(type));
}

zone_nonnull_all
zone_warn_unused_result
static zone_really_inline int32_t have_delimiter(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const token_t *token)
{
  if (zone_likely(!(token->code & (CONTIGUOUS | QUOTED))))
    return token->code;
  else if (token->code < 0)
    return token->code;
  assert(token->code == CONTIGUOUS || token->code == QUOTED);
  SYNTAX_ERROR(parser, "Trailing data in %s", NAME(type));
}

static zone_really_inline bool is_quoted(uint8_t octet)
{
  return quoted[octet] == QUOTED;
}

static zone_really_inline bool is_contiguous(uint8_t octet)
{
  return contiguous[octet] == CONTIGUOUS;
}

static zone_really_inline bool is_blank(uint8_t octet)
{
  return contiguous[octet] == BLANK;
}

zone_nonnull_all
static zone_really_inline int32_t refill(zone_parser_t *parser)
{
  if (parser->file->buffer.length == parser->file->buffer.size) {
    size_t size = parser->file->buffer.size + ZONE_WINDOW_SIZE;
    char *data = parser->file->buffer.data;
    if (!(data = realloc(data, size + 1)))
      OUT_OF_MEMORY(parser, "Cannot increase buffer size to %zu", size);
    parser->file->buffer.size = size;
    parser->file->buffer.data = data;
  }

  size_t count = fread(parser->file->buffer.data + parser->file->buffer.length,
                       sizeof(parser->file->buffer.data[0]),
                       parser->file->buffer.size - parser->file->buffer.length,
                       parser->file->handle);

  if (count == 0 && ferror(parser->file->handle))
    SYNTAX_ERROR(parser, "actually a read error");

  // always null-terminate so terminating token can point to something
  parser->file->buffer.length += (size_t)count;
  parser->file->buffer.data[parser->file->buffer.length] = '\0';
  parser->file->end_of_file = feof(parser->file->handle) != 0;
  return 0;
}

#define DEFER_ERROR(parser, token, error) \
  do { \
    token->data = NULL; \
    token->code = error; \
    return; \
  } while (0)

#define DEFER_SYNTAX_ERROR(parser, token, ...) \
  do { \
    ZONE_LOG(parser, ZONE_ERROR, __VA_ARGS__); \
    token->data = NULL; \
    token->code = ZONE_SYNTAX_ERROR; \
    return; \
  } while (0)

zone_nonnull_all
static zone_really_inline void lex(zone_parser_t *parser, token_t *token)
{
  for (;;) {
    token->data = *parser->file->fields.head++;
    token->code = (int32_t)contiguous[ (uint8_t)*token->data ];
    if (zone_likely(token->code == CONTIGUOUS)) {
      return;
    } else if (token->code == LINE_FEED) {
      if (zone_unlikely(token->data == line_feed))
        parser->file->span += *parser->file->lines.head++;
      parser->file->span++;
      if (parser->file->grouped)
        continue;
      parser->file->line += parser->file->span;
      parser->file->span = 0;
      parser->file->start_of_line = !is_blank((uint8_t)*(token->data+1));
      return;
    } else if (token->code == QUOTED) {
      token->data++;
      return;
    } else if (token->code == END_OF_FILE) {
      break;
    } else if (token->code == LEFT_PAREN) {
      if (parser->file->grouped)
        DEFER_SYNTAX_ERROR(parser, token, "Nested opening brace");
      parser->file->grouped = true;
    } else {
      assert(token->code == RIGHT_PAREN);
      if (!parser->file->grouped)
        DEFER_SYNTAX_ERROR(parser, token, "Missing opening brace");
      parser->file->grouped = false;
    }
  }

  step(parser, token);
}

#endif // LEXER_H
