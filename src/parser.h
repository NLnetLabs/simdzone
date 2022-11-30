/*
 * parser.c -- recursive descent parser for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "scanner.h"

static inline zone_return_t parse(zone_parser_t *parser, void *user_data)
{
  zone_return_t result;
  zone_token_t token;

  size_t tokens = 0;

  (void)user_data;

  while ((result = lex(parser, &token)) > 0) {
#if 0
    printf("token [index: %4zu, length: %4zu]: ", token.offset, token.length);
    const size_t n = token.length;// - token.offset;
    const char *text = &parser->file->buffer.data[token.offset];
    if (n == 1 && parser->file->buffer.data[token.offset] == '\n')
      printf("<newline>\n");
    else
      printf("%.*s\n", n, &parser->file->buffer.data[token.offset]);
#endif
    tokens++;
  }

  printf("saw %zu tokens\n", tokens);
  return 0;
}
