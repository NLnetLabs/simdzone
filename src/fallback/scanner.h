/*
 * scanner.h -- fallback (non-simd) lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>
#include <stdint.h>
#include <string.h>

zone_always_inline()
zone_nonnull_all()
static inline const char *scan_comment(
  zone_parser_t *parser, const char *start, const char *end)
{
  for (; start < end; start++) {
    if (*start == '\n')
      return start;
  }

  parser->file->indexer.in_comment = 1;
  return end;
}

zone_always_inline()
zone_nonnull_all()
static inline const char *scan_quoted(
  zone_parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    switch (*start) {
      case '\\':
        parser->file->indexer.newlines += start[1] == '\n';
        start += 2;
        break;
      case '\"':
       *parser->file->indexer.tail++ = (zone_index_t){ start, 0 };
        return start + 1;
      case '\n':
        parser->file->indexer.newlines += 1;
        start += 1;
        break;
      default:
        start += 1;
        break;
    }
  }

  parser->file->indexer.newlines -= *end == '\n';
  parser->file->indexer.in_quoted = 1;
  parser->file->indexer.is_escaped = (start > end);
  return end;
}

zone_always_inline()
zone_nonnull_all()
static inline const char *scan_contiguous(
  zone_parser_t *parser, const char *start, const char *end)
{
  while (start < end) {
    switch (*start) {
      case '\\':
        parser->file->indexer.newlines += start[1] == '\n';
        start += 2;
        break;
      case '\n':
      case '(':
      case ')':
      case '"':
        return start;
      case '\t':
      case '\r':
      case ' ':
       *parser->file->indexer.tail++ = (zone_index_t){ start, 0 };
        return start + 1;
      case ';':
       *parser->file->indexer.tail++ = (zone_index_t){ start, 0 };
        return start;
      default:
        start += 1;
        break;
    }
  }

  parser->file->indexer.newlines -= *end == '\n';
  parser->file->indexer.is_escaped = (start > end);
  parser->file->indexer.follows_contiguous = 1;
  return end;
}

zone_always_inline()
zone_nonnull_all()
static inline void scan(
  zone_parser_t *parser, const char *start, const char *end)
{
  zone_file_t *file = parser->file;

  if (file->indexer.is_escaped) {
    file->indexer.is_escaped = 0;
    file->indexer.newlines = *start++ == '\n';
  }

  if (file->indexer.in_comment) {
    file->indexer.in_comment = 0;
    start = scan_comment(parser, start, end);
  } else if (file->indexer.in_quoted) {
    file->indexer.in_quoted = 0;
    start = scan_quoted(parser, start, end);
  } else if (file->indexer.follows_contiguous) {
    file->indexer.follows_contiguous = 0;
    start = scan_contiguous(parser, start, end);
  }

  while (start < end) {
    switch (*start) {
      case '\n':
       *file->indexer.tail++ =
          (zone_index_t){ start++, file->indexer.newlines };
        file->indexer.newlines = 0;
        break;
      case '\t':
      case '\r':
      case ' ':
        start++;
        break;
      case ';':
        start = scan_comment(parser, start, end);
        break;
      case '(':
      case ')':
       *file->indexer.tail++ = (zone_index_t){ start++, 0 };
        break;
      case '"':
       *file->indexer.tail++ = (zone_index_t){ start++, 0 };
        start = scan_quoted(parser, start, end);
        break;
      default:
       *file->indexer.tail++ = (zone_index_t){ start, 0 };
        start = scan_contiguous(parser, start, end);
        break;
    }
  }
}

zone_always_inline()
zone_nonnull_all()
static inline void refill(zone_parser_t *parser)
{
  zone_file_t *file = parser->file;

  // grow buffer if necessary
  if (file->buffer.length == file->buffer.size) {
    size_t size = file->buffer.size + ZONE_WINDOW_SIZE;
    char *data = file->buffer.data;
    if (!(data = zone_realloc(parser, data, size + 1)))
      SYNTAX_ERROR(parser, "actually out of memory");
    file->buffer.size = size;
    file->buffer.data = data;
  }

  size_t count = fread(file->buffer.data + file->buffer.length,
                       sizeof(file->buffer.data[0]),
                       file->buffer.size - file->buffer.length,
                       file->handle);

  if (count == 0 && ferror(file->handle))
    SYNTAX_ERROR(parser, "actually a read error");

  // always null-terminate so terminating token can point to something
  file->buffer.length += (size_t)count;
  file->buffer.data[file->buffer.length] = '\0';
  file->end_of_file = feof(file->handle) != 0;
}

extern const uint8_t *zone_forward;
extern const uint8_t *zone_jump;

zone_never_inline()
zone_nonnull_all()
static zone_return_t step(zone_parser_t *parser, zone_token_t *token)
{
  zone_file_t *file = parser->file;
  const char *start, *end;
  bool start_of_line = false;

  // start of line is initially always true
  if (file->indexer.tail == file->indexer.tape)
    start_of_line = true;
  else if (*(end = file->indexer.tail[-1].data) == '\n')
    start_of_line = (file->buffer.data + file->buffer.index) - end == 1;

  file->indexer.head = file->indexer.tape;
  file->indexer.tail = file->indexer.tape;

shuffle:
  // refill if required
  if (file->end_of_file == ZONE_HAVE_DATA) {
    memmove(file->buffer.data,
            file->buffer.data + file->buffer.index,
            file->buffer.length - file->buffer.index);
    file->buffer.length -= file->buffer.index;
    file->buffer.index = 0;
    refill(parser);
  }

  start = file->buffer.data + file->buffer.index;

  while (file->buffer.length - file->buffer.index >= ZONE_BLOCK_SIZE) {
    if ((file->indexer.tape + ZONE_TAPE_SIZE) - file->indexer.tail < ZONE_BLOCK_SIZE)
      goto terminate;
    const char *block = &file->buffer.data[file->buffer.index];
    scan(parser, block, block + ZONE_BLOCK_SIZE);
    file->buffer.index += ZONE_BLOCK_SIZE;
  }

  const size_t length = file->buffer.length - file->buffer.index;
  if (length > (size_t)((file->indexer.tape + ZONE_TAPE_SIZE) - file->indexer.tail))
    goto terminate;

  const char *block = &file->buffer.data[file->buffer.index];
  scan(parser, block, block + length);
  file->buffer.index += length;
  file->end_of_file = ZONE_NO_MORE_DATA;

terminate:
  // ensure tape contains no partial tokens
  if ((file->indexer.follows_contiguous || file->indexer.in_quoted) && file->end_of_file != ZONE_NO_MORE_DATA) {
    assert(file->indexer.tail > file->indexer.tape);
    assert(file->indexer.in_comment == 0);
    file->indexer.tail--;
    file->indexer.in_quoted = 0;
    file->indexer.is_escaped = 0;
    file->indexer.follows_contiguous = 0;
    file->buffer.index = (size_t)(file->indexer.tail[0].data - file->buffer.data);
  }

  file->indexer.tail[0] =
    (zone_index_t){ file->buffer.data + file->buffer.length, 0 };
  file->indexer.tail[1] =
    (zone_index_t){ file->buffer.data + file->buffer.length, 0 };
  file->start_of_line = file->indexer.head[0].data == start && start_of_line;

  do {
    start = file->indexer.head[0].data;
    end   = file->indexer.head[1].data;
    assert(start < end || (start == end && *start == '\0' && *end == '\0'));

    switch (zone_jump[ (unsigned char)*start ]) {
      case 0: // contiguous
        *token = (zone_token_t){ (size_t)(end - start), start };
        // discard index for blank or semicolon
        file->indexer.head += zone_forward[ (unsigned char)*end ];
        return ZONE_CONTIGUOUS;
      case 1: // quoted
        *token = (zone_token_t){ (size_t)(end - start), start + 1 };
        // discard index for closing quote
        file->indexer.head += 2;
        return ZONE_QUOTED;
      case 2: // newline
        file->line += file->indexer.head[0].newlines + 1;
        file->indexer.head++;
        if (file->grouped)
          break;
        file->start_of_line = (end - start) == 1;
        *token = (zone_token_t){ 1, start };
        return ZONE_DELIMITER;
      case 3: // end of file
        if (file->end_of_file != ZONE_NO_MORE_DATA)
          goto shuffle;
        if (file->grouped)
          SYNTAX_ERROR(parser, "Missing closing brace");
        assert(start == file->buffer.data + file->buffer.length);
        assert(end == file->buffer.data + file->buffer.length);
        *token = (zone_token_t){ 1, start };
        return ZONE_DELIMITER;
      case 4: // left parenthesis
        if (file->grouped)
          SYNTAX_ERROR(parser, "Nested opening brace");
        file->grouped = true;
        file->indexer.head++;
        break;
      case 5: // right parenthesis
        if (!file->grouped)
          SYNTAX_ERROR(parser, "Closing brace without opening brace");
        file->grouped = false;
        file->indexer.head++;
        break;
    }
  } while (1);
}

#endif // SCANNER_H
