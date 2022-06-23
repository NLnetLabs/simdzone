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
#include <netinet/in.h>

typedef int32_t zone_return_t;

typedef struct zone_position zone_position_t;
struct zone_position {
  const char *file;
  off_t line, column;
};

typedef struct zone_location zone_location_t;
struct zone_location {
  zone_position_t begin, end;
};

typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  struct {
    const void *domain; // reference received by accept_name if applicable
    struct { size_t length; uint8_t octets[255]; } name;
  } origin; // current origin
  struct {
    const void *domain; // reference received by accept_name if applicable
    struct { size_t length; uint8_t octets[255]; } name;
  } owner; // current owner
  zone_position_t position;
  const char *name; // file name in include directive
  const char *path; // fully-qualified path to include file
  FILE *handle;
  struct {
    size_t cursor;
    size_t used;
    size_t size;
    union { const char *read; char *write; } data;
  } buffer;
};

#define ZONE_FORMAT (0xff00)

typedef enum {
  ZONE_DOMAIN = (1 << 8),
  ZONE_INT8 = (2 << 8),
  ZONE_INT16 = (3 << 8),
  ZONE_INT32 = (4 << 8),
  ZONE_IP4 = (5 << 8),
  ZONE_IP6 = (6 << 8),
  ZONE_NAME = (7 << 8),
  ZONE_STRING = (9 << 8)
} zone_format_t;

typedef struct zone_field zone_field_t;
struct zone_field {
  zone_location_t location;
  zone_format_t format;
  union {
    const void *domain;
    uint8_t int8;
    uint16_t int16;
    uint32_t int32;
    struct { uint8_t length; uint8_t *octets; } name;
    struct in_addr *ip4;
    struct in6_addr *ip6;
  };
};

typedef struct zone_parser zone_parser_t;
struct zone_parser;

// accept name is invoked whenever a domain name, e.g. OWNER, ORIGIN or
// CNAME, is encountered. the function must return a persistent reference to
// the internal representation. the reference is passed as an argument if a
// function is registered, otherwise the default behaviour is to pass the name
// in wire format
typedef const void *(*zone_accept_name_t)(
  const zone_parser_t *,
  const zone_field_t *, // name
  void *); // user data

// invoked at the start of each record (host order). the four fields are
// passed in one go for convenience. arguably, avoiding needless
// callbacks has a positive impact on performance as well
typedef zone_return_t(*zone_accept_rr_t)(
  const zone_parser_t *,
  zone_field_t *, // owner
  zone_field_t *, // ttl
  zone_field_t *, // class
  zone_field_t *, // type
  void *); // user data

// invoked for each rdata item in a record (network order)
typedef zone_return_t(*zone_accept_rdata_t)(
  const zone_parser_t *,
  zone_field_t *, // rdata,
  void *); // user data

// invoked to finish each record. i.e. end-of-file and newline
typedef zone_return_t(*zone_accept_t)(
  const zone_parser_t *,
  zone_field_t *, // end-of-file or newline
  void *); // user data

typedef void *(*zone_malloc_t)(void *arena, size_t size);
typedef void *(*zone_realloc_t)(void *arena, void *ptr, size_t size);
typedef void(*zone_free_t)(void *arena, void *ptr);

typedef struct zone_options zone_options_t;
struct zone_options {
  // FIXME: add a flags member. e.g. to allow for includes in combination
  //        with static buffers, signal ownership of allocated memory, etc
  // FIXME: a compiler flag indicating host or network order might be useful
  uint16_t default_class;
  uint32_t default_ttl;
  struct {
    zone_malloc_t malloc;
    zone_realloc_t realloc;
    zone_free_t free;
    void *arena;
  } allocator;
  struct {
    zone_accept_name_t name;
    zone_accept_rr_t rr;
    // FIXME: add callback to accept rdlength for generic records?
    zone_accept_rdata_t rdata;
    zone_accept_t terminator;
  } accept;
};

struct zone_parser {
  zone_file_t *file;
  int32_t state;
  zone_options_t options;
  struct {
    // small backlog to track items before invoking accept_rr. memory for
    // owner, if no accept_name was registered, is allocated just before
    // invoking accept_rr to simplify memory management
    zone_field_t fields[4]; // { owner, ttl, class, type }
    struct {
      // number of expected octets in rdata. valid if rdata is in generic
      // presetation. i.e. if "\#" is encountered as per RFC3597
      size_t expect;
      size_t count;
    } rdlength;
    struct {
      const void *type; // pointer to type descriptor (private)
      const void *rdata; // pointer to rdata descriptor (private)
    } descriptor;
    // FIXME: keep track of svcb parameters seen
  } record;
  // FIXME: keep error count?
};

// return codes
#define ZONE_SUCCESS (0)
#define ZONE_SYNTAX_ERROR (-1)
#define ZONE_SEMANTIC_ERROR (-2)
#define ZONE_OUT_OF_MEMORY (-3)
#define ZONE_BAD_PARAMETER (-4)

#define ZONE_NEED_REFILL (-5) // internal error code used to trigger refill

// initializes the parser with a static fixed buffer
zone_return_t zone_open_string(
  zone_parser_t *parser, const zone_options_t *options, const char *str, size_t len);

// initializes the parser and opens a zone file
zone_return_t zone_open(
  zone_parser_t *parser, const zone_options_t *options, const char *file);

void zone_close(zone_parser_t *parser);

// basic mode of operation is iterative. users must iterate over records by
// calling zone_parse repetitively
zone_return_t zone_parse(zone_parser_t *parser, void *user_data);

// FIXME: implement zone_process

// convenience function for reporting parser errors. supports custom flags
// for easy printing of location. more flags may follow later
void zone_error(const zone_parser_t *parser, const char *fmt, ...);

// FIXME: probably should implement zone_warning, zone_info, zone_debug too?

#endif // ZONE_H
