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
    printf("token [length: %4zu]: ", token.string.length);
    const size_t n = token.string.length;// - token.offset;
    const char *text = token.string.data;
    if (n == 1 && *text == '\n')
      printf("<newline>\n");
    else
      printf("%.*s\n", n, text);
#endif
    tokens++;
  }

  printf("saw %zu tokens\n", tokens);
  return 0;
}
