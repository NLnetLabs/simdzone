/*
 * scanner.h -- lexical analyzer for (DNS) zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_SCANNER_H
#define ZONE_SCANNER_H

#include "zone.h"

// parser states
#define ZONE_INITIAL (1 << 22)
#define ZONE_GROUPED (1 << 23)
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)

typedef enum {
  ZONE_DELIMITER = 0, // single character embedded in 8 least significant bits
  // record items
  ZONE_COMMENT = (1 << 15),
  ZONE_OWNER = (1 << 16),
  ZONE_TTL = (1 << 17),
  ZONE_CLASS = (1 << 18),
  ZONE_TYPE = (1 << 19),
  ZONE_RDATA = (1 << 20),
  ZONE_SVCB_RDATA = (1 << 21)
  // pending implementation of control types
} zone_item_t;

// ZONE_xxx constants defined here are solely used during scan stage
#define ZONE_CHAR (0) // single character embedded in 8 least significant bits
// ZONE_INTx are used for ttl, class and type tokens. ensure values do NOT
// conflict with each other
#define ZONE_STRING (9 << 8)
// httpsvc requires an additional token type to allow for clear seperation
// between scan and parse states to remain intact. while a string can be
// used, doing so requires unescaping to be moved up into the parser, the
// parser to split the parameter and value again and possibly require more
// memory as the value cannot be referenced in unquoted fashion
#define ZONE_SVC_PARAM (10 << 8)

// zone code is a concatenation of the item and value types. the 8 least
// significant bits are reserved to embed ascii codes. e.g. end-of-file and
// line feed delimiters are simply encoded as '\0' and '\n' respectively. the
// 8 least significant bits must only be considered valid ascii if no other
// bits are set as they are reserved for private state if there are.
// bits 8 - 15 encode the the value type, the remaining bits encode the item
// type. negative values indicate an error condition
typedef zone_return_t zone_code_t;

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

// raw scanner interface that simply returns tokens initially required for
// testing purposes, but may be useful for users too. merely handles splitting
// and identification of fields. i.e. owner, ttl, class, type and rdata.
// does not handle includes directives as that must be handled by the parse
// step. also does not parse owner or rdata fields, again because that must be
// taken care of by the parser
zone_return_t zone_scan(zone_parser_t *parser, zone_token_t *token);

// convenience macros for internal use only
//   >> these should be located elsewhere!
//     >> maybe log.h or something...
#define SYNTAX_ERROR(parser, ...) \
  do { zone_error(parser, __VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0)
#define SEMANTIC_ERROR(parser, ...) \
  do { zone_error(parser, __VA_ARGS__); return ZONE_SEMANTIC_ERROR; } while (0)

// remove \DDD constructs from input. see RFC 1035, section 5.1
ssize_t zone_unescape(const char *str, size_t len, char *buf, size_t size, int strict);

uint16_t zone_is_type(const char *str, size_t len);

uint16_t zone_is_class(const char *str, size_t len);

#endif
