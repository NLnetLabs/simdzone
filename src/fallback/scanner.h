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
#include <unistd.h>

extern void *zone_malloc(zone_options_t *opts, size_t size);
extern void *zone_realloc(zone_options_t *opts, void *ptr, size_t size);
extern void zone_free(zone_options_t *opts, void *ptr);
extern char *zone_strdup(zone_options_t *opts, const char *str);

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
       *parser->file->indexer.tail++ = (zone_transition_t){ start, 0 };
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
       *parser->file->indexer.tail++ = (zone_transition_t){ start, 0 };
        return start + 1;
      case ';':
       *parser->file->indexer.tail++ = (zone_transition_t){ start, 0 };
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
          (zone_transition_t){ start++, file->indexer.newlines };
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
       *file->indexer.tail++ = (zone_transition_t){ start++, 0 };
        break;
      case '"':
       *file->indexer.tail++ = (zone_transition_t){ start++, 0 };
        start = scan_quoted(parser, start, end);
        break;
      default:
       *file->indexer.tail++ = (zone_transition_t){ start, 0 };
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
    size_t size = file->buffer.size + 16384; // should be a compile time constant!
    char *data = file->buffer.data;
    if (!(data = zone_realloc(&parser->options, data, size + 1)))
      SYNTAX_ERROR(parser, "actually out of memory");//return ZONE_OUT_OF_MEMORY;
    file->buffer.size = size;
    file->buffer.data = data;
  }

  ssize_t count = read(file->handle,
                       file->buffer.data + file->buffer.length,
                       file->buffer.size - file->buffer.length);
  if (count < 0)
    SYNTAX_ERROR(parser, "some error, blabla");
//    return ZONE_IO_ERROR;
  // always null-terminate so terminating token can point to something
  file->buffer.length += (size_t)count;
  file->buffer.data[file->buffer.length] = '\0';
  file->end_of_file = count == 0;
}

extern const uint8_t *zone_forward;
extern const uint8_t *zone_jump;

zone_never_inline()
zone_nonnull_all()
static zone_return_t step(zone_parser_t *parser, zone_token_t *token)
{
  zone_file_t *file;
  bool start_of_line;
  const zone_transition_t *tail = parser->file->indexer.tape + ZONE_TAPE_SIZE;
  const char *base, *start, *end;

  assert(parser);
  assert(token);

  file = parser->file;
  assert(file);
  assert(file->indexer.tail > file->indexer.tape);
  base = file->indexer.tail[-1].address;
  start_of_line =
    base[0] == '\n' && &base[1] == file->buffer.data + file->buffer.index;

  file->indexer.head = file->indexer.tape;
  file->indexer.tail = file->indexer.tape;

  // refill if required
  if (file->buffer.length - file->buffer.index <= ZONE_BLOCK_SIZE) {
shuffle:
    memmove(file->buffer.data,
            file->buffer.data + file->buffer.index,
            file->buffer.length - file->buffer.index);
    file->buffer.length -= file->buffer.index;
    file->buffer.index = 0;
    refill(parser);
  }

  base = file->buffer.data + file->buffer.index;

  while (file->buffer.length - file->buffer.index >= ZONE_BLOCK_SIZE) {
    if (tail - file->indexer.tail < ZONE_BLOCK_SIZE)
      goto terminate;
    start = &file->buffer.data[file->buffer.index];
    scan(parser, start, start + ZONE_BLOCK_SIZE);
    file->buffer.index += ZONE_BLOCK_SIZE;
  }

  const size_t length = file->buffer.length - file->buffer.index;
  if (!file->end_of_file || (size_t)(tail - file->indexer.tail) < length)
    goto terminate;

  start = &file->buffer.data[file->buffer.index];
  scan(parser, start, start + length);
  file->buffer.index += length;
  file->end_of_file = ZONE_NO_MORE_DATA;

terminate:
  // ensure tape contains no partial tokens
  if (file->indexer.follows_contiguous || file->indexer.in_quoted) {
    assert(file->indexer.tail > file->indexer.tape);
    assert(file->indexer.in_comment == 0);
    file->indexer.tail--;
    file->indexer.in_quoted = 0;
    file->indexer.is_escaped = 0;
    file->indexer.follows_contiguous = 0;
    file->buffer.index = file->indexer.tail[0].address - file->buffer.data;
  }

  file->indexer.tail[0] =
    (zone_transition_t){ file->buffer.data + file->buffer.length, 0 };
  file->indexer.tail[1] =
    (zone_transition_t){ file->buffer.data + file->buffer.length, 0 };
  file->start_of_line = file->indexer.head[0].address == base && start_of_line;

  do {
    start = file->indexer.head[0].address;
    end   = file->indexer.head[1].address;

    switch (zone_jump[ (unsigned char)*start ]) {
      case 0: // contiguous
        *token = (zone_token_t){ end - start, start };
        // discard index for blank or semicolon
        file->indexer.head += zone_forward[ (unsigned char)*end ];
        return ZONE_CONTIGUOUS;
      case 1: // quoted
        *token = (zone_token_t){ end - start, start + 1 };
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
