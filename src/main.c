#include <stdio.h>
#include <stdlib.h>

#include "zone.h"

zone_return_t accept_rr(
  const zone_parser_t *parser,
  const zone_field_t *owner,
  const zone_field_t *ttl,
  const zone_field_t *class,
  const zone_field_t *type,
  void *user_data)
{
  (void)parser;
  (void)owner;
  (void)ttl;
  (void)class;
  (void)type;
  (void)user_data;
  return ZONE_SUCCESS;
}

static zone_return_t accept_rdata(
  const zone_parser_t *parser,
  const zone_field_t *rdata,
  void *user_data)
{
  (void)parser;
  (void)rdata;
  (void)user_data;
  return ZONE_SUCCESS;
}

zone_return_t accept_delimiter(
  const zone_parser_t *parser,
  const zone_field_t *delimiter,
  void *user_data)
{
  size_t *count = user_data;
  (void)parser;
  (void)delimiter;
  (*count)++;
//  printf("and that's %zu\n", *count);
  return ZONE_SUCCESS;
}

int main(int argc, char *argv[])
{
  size_t count = 0;
  zone_parser_t parser = { 0 };
  zone_options_t options = { 0 };

  options.accept.rr = &accept_rr;
  options.accept.rdata = &accept_rdata;
  options.accept.delimiter = &accept_delimiter;

  if (argc != 2)
    return 1;
  if (zone_open(&parser, &options, argv[1]) < 0)
    return 1;
  if (zone_parse(&parser, &count) < 0)
    return 1;
  printf("parsed %zu records\n", count);
  zone_close(&parser);
  return 0;
}
