#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zone.h"

static int32_t add_rr(zone_parser_t *parser, const zone_name_t *owner,
                      uint16_t type, uint16_t class, uint32_t ttl,
                      uint16_t rdlength, const uint8_t *rdata,
                      void *user_data) {
  (void)parser;
  (void)owner;
  (void)type;
  (void)class;
  (void)ttl;
  (void)rdlength;
  (void)rdata;
  (void)user_data;
  return ZONE_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  size_t size_of_input = size + ZONE_BLOCK_SIZE + 1;
  char *null_terminated = (char*)malloc(size_of_input);
  memcpy(null_terminated, data, size);
  null_terminated[size_of_input-1] = '\0';

  zone_parser_t parser = {0};
  zone_name_buffer_t name;
  zone_rdata_buffer_t rdata;
  zone_buffers_t buffers = {1, &name, &rdata};
  zone_options_t options = {0};

  options.accept.callback = add_rr;
  options.origin = "example.com.";
  options.default_ttl = 3600;
  options.default_class = 1;

  zone_parse_string(&parser, &options, &buffers, null_terminated, size_of_input,
                    NULL);

  free(null_terminated);
  return 0;
}