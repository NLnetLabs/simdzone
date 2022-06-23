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

// additional parser states
#define ZONE_INITIAL (1 << 15)
#define ZONE_GROUPED (1 << 16)
#define ZONE_GENERIC_RDATA (1 << 17) // parsing generic rdata (RFC3597)
#define ZONE_RR (ZONE_TTL|ZONE_CLASS|ZONE_TYPE)

#define ZONE_ITEM (~0xfffff)

typedef enum {
  ZONE_DELIMITER = 0, // single character embedded in 8 least significant bits
  // record items
  ZONE_COMMENT = (1 << 19),
  ZONE_OWNER = (1 << 20), // string
  ZONE_TTL = (1 << 21), // int32
  ZONE_CLASS = (1 << 22), // int16
  ZONE_TYPE = (1 << 23), // int16
  ZONE_RDATA = (1 << 24), // string
  // NOTE: backslash_hash may transition to rdata if "\#" is not found
  ZONE_BACKSLASH_HASH = (1<<25), // string, for consistency
  // NOTE: rdlength transitions to rdata as syntax rules remain the same
  ZONE_RDLENGTH = (1<<26), // int16
  // svcb-https introduces syntax changes. svc_priority and target_name
  // must not parse the value as is done for e.g. ttl and rdlength as doing
  // so would break the parser interface
  // NOTE: svc_priority may transition to rdlength if "\#" is found
  ZONE_SVC_PRIORITY = (1<<27), // string
  ZONE_TARGET_NAME = (1<<28), // string
  // svcb-https requires an additional token type to allow for clear
  // seperation between scan and parse states to remain intact. while a string
  // can be used, doing so requires the parser to split the parameter and
  // value again and possibly require more memory as the value cannot be
  // referenced in unquoted fashion
  ZONE_SVC_PARAM = (1<<29) // svc_param
  // FIXME: pending implementation of control types
} zone_item_t;

// ZONE_xxx constants defined here are solely used during scan stage
#define ZONE_CHAR (0) // single character embedded in 8 least significant bits

// zone code is a concatenation of the item and value types. the 8 least
// significant bits are reserved to embed ascii codes. e.g. end-of-file and
// line feed delimiters are simply encoded as '\0' and '\n' respectively. the
// 8 least significant bits must only be considered valid ascii if no other
// bits are set as they are reserved for private state if there are.
// bits 8 - 15 encode the the value type, bits 16-19 are reserved for
// additional parser states, e.g. ZONE_GENERIC and never occur in tokens. the
// remaining bits encode the item. negative values indicate an error condition
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

// convenience macros for internal use only (FIXME: move somewhere else)
#define SYNTAX_ERROR(parser, ...) \
  do { zone_error(parser, __VA_ARGS__); return ZONE_SYNTAX_ERROR; } while (0)
#define SEMANTIC_ERROR(parser, ...) \
  do { zone_error(parser, __VA_ARGS__); return ZONE_SEMANTIC_ERROR; } while (0)

// remove \DDD constructs from input. see RFC 1035, section 5.1
ssize_t zone_unescape(const char *str, size_t len, char *buf, size_t size, int strict);

ssize_t zone_decode(const char *enc, size_t enclen, uint8_t *dec, size_t decsize);

uint16_t zone_is_type(const char *str, size_t len);

uint16_t zone_is_class(const char *str, size_t len);

#endif
