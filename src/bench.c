/*
 * bench.c -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

#include "zone.h"
#include "config.h"
#include "isadetection.h"

#if ZONE_SUPPORTS_HASWELL
extern zone_return_t zone_bench_haswell_lex(zone_parser_t *, size_t *);
extern zone_return_t zone_haswell_parse(zone_parser_t *, void *);
#endif

#if ZONE_SUPPORTS_WESTMERE
extern zone_return_t zone_bench_westmere_lex(zone_parser_t *, size_t *);
extern zone_return_t zone_westmere_parse(zone_parser_t *, void *);
#endif

extern zone_return_t zone_bench_fallback_lex(zone_parser_t *, size_t *);
extern zone_return_t zone_fallback_parse(zone_parser_t *, void *);

typedef struct target target_t;
struct target {
  const char *name;
  uint32_t instruction_set;
  zone_return_t (*bench_lex)(zone_parser_t *, size_t *);
  zone_return_t (*parse)(zone_parser_t *, void *);
};

static const target_t targets[] = {
#if ZONE_SUPPORTS_HASWELL
  { "haswell", AVX2, &zone_bench_haswell_lex, &zone_haswell_parse },
#endif
#if ZONE_SUPPORTS_WESTMERE
  { "westmere", SSE42, &zone_bench_westmere_lex, &zone_westmere_parse },
#endif
  { "fallback", 0, &zone_bench_fallback_lex, &zone_fallback_parse }
};

static zone_return_t bench_lex(zone_parser_t *parser, const target_t *target)
{
  size_t tokens = 0;
  zone_return_t result;
  volatile jmp_buf environment;

  switch ((result = setjmp((void *)environment))) {
    case 0:
      parser->environment = environment;
      result = target->bench_lex(parser, &tokens);
      assert(result == ZONE_SUCCESS);
      break;
    default:
      assert(result < 0);
      assert(parser->environment == environment);
      break;
  }

  printf("Lexed %zu tokens\n", tokens);
  return result;
}

static zone_return_t bench_accept(
  zone_parser_t *parser,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  const zone_field_t *rdatas,
  uint16_t rdlength,
  const uint8_t *rdata,
  void *user_data)
{
  (void)parser;
  (void)owner;
  (void)ttl;
  (void)class;
  (void)type;
  (void)rdatas;
  (void)rdlength;
  (void)rdata;
  (*(size_t *)user_data)++;
  return ZONE_SUCCESS;
}

static zone_return_t bench_parse(zone_parser_t *parser, const target_t *target)
{
  size_t records = 0;
  zone_return_t result;
  volatile jmp_buf environment;

  switch ((result = setjmp((void *)environment))) {
    case 0:
      parser->environment = environment;
      result = target->parse(parser, &records);
      assert(result == ZONE_SUCCESS);
      break;
    default:
      assert(result < 0);
      assert(parser->environment == environment);
      break;
  }

  printf("Parsed %zu records\n", records);
  return result;
}

static const target_t *select_target(const char *name)
{
  const size_t n = sizeof(targets)/sizeof(targets[0]);
  const uint32_t supported = detect_supported_architectures();
  const target_t *target = NULL;

  if ((!name || !*name) && !(name = getenv("ZONE_TARGET"))) {
    for (size_t i=0; !target && i < n; i++) {
      if (targets[i].instruction_set & supported)
        target = &targets[i];
    }
  } else {
    for (size_t i=0; !target && i < n; i++) {
      if (strcasecmp(name, targets[i].name) == 0)
        target = &targets[i];
    }

    if (!target || (target->instruction_set && !(target->instruction_set & supported))) {
      fprintf(stderr, "Target %s is unavailable\n", name);
      return NULL;
    }
  }

  printf("Selected target %s\n", target->name);
  return target;
}

static void help(const char *program)
{
  const char *format =
    "Usage: %s [OPTION] <lex or parse> <zone file>\n"
    "\n"
    "Options:\n"
    "  -h         Display available options.\n"
    "  -t target  Select target (default:%s)\n"
    "\n"
    "Targets:\n";

  printf(format, program, targets[0].name);

  for (size_t i=0, n=sizeof(targets)/sizeof(targets[0]); i < n; i++)
    printf("  %s\n", targets[i].name);
}

static void usage(const char *program)
{
  fprintf(stderr, "Usage: %s [OPTION] <lex or parse> <zone file>\n", program);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  const char *name = NULL, *program = argv[0];

  for (const char *slash = argv[0]; *slash; slash++)
    if (*slash == '/' || *slash == '\\')
      program = slash + 1;

  for (int option; (option = getopt(argc, argv, "ht:")) != -1;) {
    switch (option) {
      case 'h':
        help(program);
        exit(EXIT_SUCCESS);
      case 't':
        name = optarg;
        break;
      default:
        usage(program);
    }
  }

  if (optind > argc || argc - optind < 2)
    usage(program);

  zone_return_t (*bench)(zone_parser_t *, const target_t *) = 0;
  if (strcasecmp(argv[optind], "lex") == 0)
    bench = &bench_lex;
  else if (strcasecmp(argv[optind], "parse") == 0)
    bench = &bench_parse;
  else
    usage(program);

  const target_t *target;
  if (!(target = select_target(name)))
    exit(EXIT_FAILURE);

  zone_parser_t parser = { 0 };
  zone_options_t options = { 0 };

  options.accept = &bench_accept;

  if (zone_open(&parser, &options, argv[argc-1]) < 0)
    exit(EXIT_FAILURE);
  if (bench(&parser, target) < 0)
    exit(EXIT_FAILURE);

  zone_close(&parser);
  return EXIT_SUCCESS;
}
