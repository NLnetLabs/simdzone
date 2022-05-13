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

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef struct zone_position zone_position_t;
struct zone_position {
  off_t line, column;
};

typedef struct zone_location zone_location_t;
struct zone_location {
  zone_position_t begin, end;
};

typedef struct zone_token zone_token_t;
struct zone_token {
  zone_location_t location;
  int32_t code;
  int32_t escaped;
  union {
    struct { const char *data; size_t length; } string, comment;
    uint16_t type, class;
    uint32_t ttl;
  }; // c11 anonymous struct
};

// 8 least significant bits are reserved for delimiting characters so that
// some state is retained on transitions. bits 9 - 16 are reserved to
// specialized primary state. bits 17 and up are reserved to
// maintain stacked states. stacked states can be combined with primary
// and other stacked in some cases. e.g. GROUPED can be set while scanning
// RR information when a comment is started. i.e. SOA record examples
// scattered across the internet often contain comments explaining what
// each RDATA item represents

// tokens
#define ZONE_COMMENT (1u << 8)
#define ZONE_STRING (2u << 8)

// state
#define ZONE_INITIAL (1u << 15)
#define ZONE_CONTROL (1u << 16)
#define ZONE_GROUPED (1u << 17)
// record states
#define ZONE_OWNER (1u << 18) // doubles as token code
#define ZONE_TTL (1u << 19) // doubles as token (valid icw ZONE_CONTROL too)
#define ZONE_CLASS (1u << 20) // doubles as token code
#define ZONE_TYPE (1u << 21) // doubles as token code
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)
#define ZONE_RDATA (1u << 22) // doubles as token code
// control states
#define ZONE_ORIGIN (1u << 23)
#define ZONE_INCLUDE (1u << 24)

// FIXME: implement copy of dname struct as found in NSD for parse interface
typedef struct zone_domain zone_domain_t;
struct zone_domain {
  uint8_t size;
  uint8_t count;
};

typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  zone_domain_t origin;
  zone_position_t position;
  const char *name; // file name in include directive
  const char *path; // fully-qualified path to include file
  FILE *handle;
  struct {
    // moved after each record is parsed, controlled by parser
    size_t offset;
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

// FIXME: add support for dnsextlang in the parser(?)
typedef struct zone_parser zone_parser_t;
struct zone_parser {
  zone_file_t *file;
  uint32_t state;
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
int32_t zone_parse(zone_parser_t *parser, zone_rr_t *record);

// raw scanner interface that simply returns tokens initially required for
// testing purposes, but may be useful for users too. merely handles splitting
// and identification of fields. i.e. owner, ttl, class, type and rdata.
// does not handle includes directives as that must be handled by the parse
// step. also does not parse owner or rdata fields, again because that must be
// taken care of by the parser
int32_t zone_scan(zone_parser_t *parser, zone_token_t *token);

#endif // ZONE_H
