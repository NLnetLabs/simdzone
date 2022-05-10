/*
 * zonec.h -- zone compiler.
 *
 * Copyright (c) 2001-2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef ZONEC_H
#define ZONEC_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct position position_t;
struct position {
  off_t line, column;
};

typedef struct location location_t;
struct location {
  position_t begin, end;
};

typedef struct token token_t;
struct token {
  int32_t code;
  int32_t escaped; // contains at least one escaped sequence
                   //   >> if true, before anlysis, we unescape it!
  location_t location;
  union {
    struct { const char *data; size_t length; } string, comment;
    uint16_t type, class;
    uint32_t ttl;
  } value;
  struct {
    size_t size;
    uint8_t *data;
  } buffer;
  //
  // we could add a buffer here for when the type or rdata isn't
  // known. we can then depend on future dnsextlang work to handle that
  // part correctly?!?!
  //
};

// entries
#define INITIAL (1u << 0)
#define OWNER (1u << 1)
#define TTL (1u << 2)
#define CLASS (1u << 3)
#define TYPE (1u << 4)
#define RR (TTL|CLASS|TYPE)
#define RDATA (1u << 5)
// control entries
#define ORIGIN (1u << 6)
#define INCLUDE (1u << 7)

#define GROUPED (1u << 0)




#define INITIAL (1u << 8)
#define CONTROL (2u << 8)
#define OWNER (4u << 8)
#define BLANK (3u << 8)
#define RR (5u << 8)
//#define DELIMITER (255u) // mask, not a bit!

#define QUOTED (1u << 18)
#define COMMENT (1u << 19) // comment must be a secondary state because
                           // we must be able to fall back to the previous
                           // state in case it's grouped. so we must know
                           // what to fallback to
                           // if it's not grouped, of course, it's always
                           // the initial state after the newline!


// 8 least significant bits are reserved for delimiting character so that
// some state is retained on transitions. bits 9 - 16 are reserved to
// register specialized primary state. bits 17 and up are reserved to
// maintain stacked states. stacked states can be combined with primary
// and other stacked in some cases. e.g. GROUPED can be set while scanning
// RR information when a comment is started. i.e. SOA record examples
// scattered across the internet often contain comments explaining what
// each RDATA item represents
#define COMMENT (1 << 8)
#define STRING (2 << 8)
#define QUOTED_STRING (3 << 8)

typedef struct file file_t;
struct file {
  file_t *includer;
  char *name; // file name in include directive
  char *path; // fully-qualified path to include file
//  struct {
//    size_t length;
//    uint8_t *data;
//  } item;
  struct {
    size_t offset; // moved after each record is parsed!
    size_t cursor; // moved after each token is parsed!
    size_t used;
    size_t size;
    uint8_t *data;
  } buffer;
};

typedef struct parser parser_t;
struct parser {
  //
  // members
  //
  zone_file_t *zone_file;
  uint32_t state; // >> state is a property of the parser, not the file?!?!
  position_t position;
  //
  // we could add dnsextlang extension here in the future that can be used
  // to parse unknown types and verify field data...
  //
};

#if defined(__cplusplus)
}
#endif

#endif // ZONE_PARSER_H
