/*
 * zone.h -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_H
#define ZONE_H

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// FIXME: properly implement support for RFC 3597

typedef struct zone_position zone_position_t;
struct zone_position {
  const char *file;
  off_t line, column;
};

typedef struct zone_location zone_location_t;
struct zone_location {
  zone_position_t begin, end;
};

// parser states
#define ZONE_INITIAL (1 << 19)
#define ZONE_GROUPED (1 << 20)
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)

// zone code is a concatenation of the item and value types. the 8 least
// significant bits are reserved to embed ascii codes. e.g. end-of-file and
// line feed delimiters are simply encoded as '\0' and '\n' respectively. the
// 8 least significant bits must only be considered valid ascii if no other
// bits are set as they are reserved for private state if there are.
// bits 8 - 12 encode the the value type, the remaining bits encode the item
// type. negative values indicate an error condition
typedef int32_t zone_code_t;

typedef enum {
  ZONE_DELIMITER = 0, // single character embedded in 8 least significant bits
  // record items
  ZONE_COMMENT = (1 << 13),
  ZONE_OWNER = (1 << 14),
  ZONE_TTL = (1 << 15),
  ZONE_CLASS = (1 << 16),
  ZONE_TYPE = (1 << 17),
  ZONE_RDATA = (1 << 18)
  // pending implementation of control types
} zone_item_t;

inline zone_item_t zone_item(zone_code_t code)
{
  int32_t x = code & 0x000ff000;
  assert((!x && !(code & 0xf00)) || (x >= ZONE_COMMENT && x <= ZONE_RDATA));
  return (zone_item_t)x;
}

typedef enum {
  ZONE_CHAR = 0, // single character embedded in 8 least significant bits
  ZONE_INT8 = (1 << 8),
  ZONE_INT16 = (2 << 8),
  ZONE_INT32 = (3 << 8),
  ZONE_STRING = (4 << 8),
  // httpsvc requires an additional token type to allow for clear seperation
  // between scan and parse states to remain intact. while a string can be
  // used, doing so requires unescaping to be moved up into the parser, the
  // parser to split the parameter and value again and possibly require more
  // memory as the value cannot be referenced in unquoted fashion
  ZONE_SVC_PARAM = (5 << 8)
} zone_type_t;

inline zone_type_t zone_type(zone_code_t code)
{
  int32_t x = code & 0x00000f00;
  assert((!x && (code & 0xff)) || (x >= ZONE_INT8 && x <= ZONE_SVC_PARAM));
  return (zone_type_t)x;
}

typedef struct zone_string zone_string_t;
struct zone_string {
  const char *data;
  size_t length;
  int32_t escaped;
};

typedef struct zone_token zone_token_t;
struct zone_token {
  zone_location_t location;
  zone_code_t code;
  union {
    uint8_t int8;
    uint16_t int16;
    uint32_t int32;
    zone_string_t string;
    struct { zone_string_t key; zone_string_t value; } svc_param;
  }; // c11 anonymous struct
};

typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  //zone_domain_t origin;
  zone_position_t position;
  const char *name; // file name in include directive
  const char *path; // fully-qualified path to include file
  FILE *handle;
  struct {
    // moved after each record is parsed, controlled by parser
    //size_t offset;
    // moved after each token is parsed, controlled by scanner
    size_t cursor;
    size_t used;
    size_t size;
    union { const char *read; char *write; } data;
  } buffer;
};

// FIXME: add a flags member. e.g. to allow for includes icw static buffers
//
// perhaps simply add a struct named zone_options?
//struct zone_options {
//  uint16_t default_class;
//  uint32_t default_ttl;
//};

typedef struct zone_parser zone_parser_t;
struct zone_parser;

typedef zone_code_t(*zone_rdata_scanner_t)(zone_parser_t *, zone_token_t *);

struct zone_parser {
  zone_file_t *file;
  zone_code_t state;
  zone_rdata_scanner_t scanner;
  //uint32_t default_ttl;
  //uint16_t default_class;
  // buffer used if token was escaped. created as required.
  // FIXME: probably necessary to hold multiple buffers as more than one field
  //        can be escaped. reset counters etc if zone_parse is invoked
  struct {
    size_t size;
    char *data;
  } buffer;
};

// return codes
#define ZONE_SYNTAX_ERROR (-1)
#define ZONE_SEMANTIC_ERROR (-2)
#define ZONE_NO_MEMORY (-3)
#define ZONE_NEED_REFILL (-4) // internal error code used to trigger refill

// initializes the parser with a static fixed buffer
int32_t zone_open_string(zone_parser_t *parser, const char *str, size_t len);

// initializes the parser and opens a zone file
int32_t zone_open(zone_parser_t *parser, const char *file);

void zone_close(zone_parser_t *parser);

// basic mode of operation is iterative. users must iterate over records by
// calling zone_parse repetitively. called zone_parse as that fits nicely
// with zone_scan
// FIXME: maybe offer a callback interface too?
//int32_t zone_parse(zone_parser_t *parser, zone_rr_t *record);

// raw scanner interface that simply returns tokens initially required for
// testing purposes, but may be useful for users too. merely handles splitting
// and identification of fields. i.e. owner, ttl, class, type and rdata.
// does not handle includes directives as that must be handled by the parse
// step. also does not parse owner or rdata fields, again because that must be
// taken care of by the parser
int32_t zone_scan(zone_parser_t *parser, zone_token_t *token);

#endif // ZONE_H
