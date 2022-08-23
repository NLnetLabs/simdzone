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
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

// compiler attributes
#if __clang__
# define ZONE_CLANG \
    (__clang_major__ * 100000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif __GNUC__
# define ZONE_GCC \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
#endif

#if defined __has_attribute
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#elif zone_gnuc
# define zone_has_attribute(x) __has_attribute(x)
# define zone_attribute(x) __attribute__(x)
#else
# define zone_has_attribute(x)
# define zone_attribute(x)
#endif

#define zone_nonnull(x) zone_attribute((__nonnull__ x))
#define zone_nonnull_all() zone_attribute((__nonnull__))

#if zone_has_attribute(returns_nonnull) && (zone_clang || zone_gnuc >= 40900)
# define zone_returns_nonnull zone_attribute((__returns_nonnull__))
#else
# define zone_returns_nonnull
#endif

#if !zone_has_attribute(alloc_size) || zone_gnuc <= 40204
# define zone_alloc_size(x)
#else
# define zone_alloc_size(x) __attribute__((__alloc_size__ x))
#endif

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

typedef struct zone_name zone_name_t;
struct zone_name {
  size_t length;
  uint8_t octets[255];
};

typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  struct {
    const void *domain; // reference received by accept_name if applicable
    zone_name_t name;
    zone_location_t location;
  } origin, owner; // current origin and owner
  struct {
    uint32_t seconds;
    zone_location_t location;
  } ttl;
  zone_position_t position;
  const char *name; // file name in include directive
  const char *path; // fully-qualified path to include file
  int handle;
  struct {
    size_t offset;
    size_t length;
    const char *data;
  } buffer;
};

// zone code is a concatenation of the item and the format. the 8 least
// significant bits are reserved to embed ascii internally. e.g. end-of-file
// and line feed delimiters are simply encoded as '\0' and '\n' by the
// scanner. the 8 least significant bits must only be considered valid ascii
// if no other bits are set as they are reserved for private state if there
// are. bits 8 - 15 encode the the value type, bits 16-27 are reserved for the
// field type. negative values indicate an error condition
typedef zone_return_t zone_code_t;

typedef enum {
  ZONE_TTL = (1 << 0), // may be used as qualifier for int32 rdata
  ZONE_CLASS = (1 << 1),
  ZONE_TYPE = (1 << 2), // may be used as qualifier for int16 rdata
  ZONE_DELIMITER = (1 << 3),
  ZONE_OWNER = (2 << 3),
  ZONE_RDATA = (3 << 3)
} zone_item_t;

inline zone_item_t zone_item(const zone_code_t code)
{
  return code & 0xff;
}

typedef enum {
  ZONE_INT8 = (1 << 14),
  ZONE_INT16 = (2 << 14),
  ZONE_INT32 = (3 << 14),
  ZONE_IP4 = (4 << 14),
  ZONE_IP6 = (5 << 14),
  ZONE_NAME = (6 << 14),
  ZONE_STRING = (1 << 8), // (used by scanner)
  // (B)inary (L)arge (Ob)ject. Inspired by relation database terminology.
  // Must be last.
  ZONE_BLOB = (7 << 14),
  // hex fields
  // ZONE_EUI48 (ZONE_HEX6?)
  // ZONE_EUI64 (ZONE_HEX8?)
  // miscellaneous fields
  ZONE_SVC_PARAM = (1 << 9), // (used by scanner)
  ZONE_WKS = (8 << 14),
  ZONE_NSEC = (9 << 14)
} zone_type_t;

inline zone_type_t zone_type(const zone_code_t code)
{
  // bits for ZONE_ESCAPED + ZONE_DECIMAL come after ZONE_STRING so width can
  // be determined using a simple shift operation
  return code & 0xfcf00;
}

// qualifiers (can be combined in various ways, hence not an enumeration)
//
// NOTE: ZONE_TYPE and ZONE_TTL may be used as qualifier for ZONE_INT32 RDATA
//       to indicate a type code or time-to-live respectively. Type codes may
//       be presented as numeric values, by the name of the record, or by the
//       correspondig generic notation, i.e. TYPExx. Time-to-live values may
//       be presented as numeric value or in the "1h2m3s" notation.
#define ZONE_COMPRESSED (1 << 8)
#define ZONE_MAILBOX (1 << 9)
#define ZONE_LOWER_CASE (1 << 10)
#define ZONE_OPTIONAL (1 << 11)
// string fields may occur in a sequence. must be last
#define ZONE_SEQUENCE (1 << 12)
// int32 fields, require "YYYYMMDDHHmmSS" format
#define ZONE_TIME (1 << 13)
// string and blob fields, require base16, may span presentation fields
#define ZONE_BASE16 (1 << 14)
// blob fields, require base32 format, may span presentation fields
#define ZONE_BASE32 (1 << 15)
// blob fields, require base64 format, may span presentation fields
#define ZONE_BASE64 (1 << 16)


typedef struct zone_key_value zone_key_value_t;
struct zone_key_value {
  const char *name;
  const size_t length;
  uint32_t value;
};

typedef struct zone_map zone_map_t;
struct zone_map {
  const zone_key_value_t *sorted;
  size_t length;
};

typedef struct zone_field_descriptor zone_field_descriptor_t;
struct zone_field_descriptor {
  const char *name;
  const size_t length;
  zone_type_t type;
  uint32_t qualifiers;
  zone_map_t labels;
  const char *description;
};

// type options
#define ZONE_IN (1<<1)
#define ZONE_ANY (1<<2)
#define ZONE_EXPERIMENTAL (1<<3)
#define ZONE_OBSOLETE (1<<4)

typedef struct zone_type_descriptor zone_type_descriptor_t;
struct zone_type_descriptor {
  const char *name;
  const size_t length;
  uint16_t type;
  uint32_t options;
  const char *description;
};

typedef struct zone_field zone_field_t;
struct zone_field {
  zone_location_t location;
  zone_code_t code; // OR'ed combination of type and item
  union {
    const zone_type_descriptor_t *type; // type field
    const zone_field_descriptor_t *rdata; // rdata fields
  } descriptor;
  const void *domain;
  // rdata is NOT stored in heap memory or allocated using a potentially
  // custom allocator. a scratch buffer specific to the parser is used to
  // avoid any memory leaks (there are NO allocations) when parsing a string
  union {
    const uint8_t *int8;
    const uint16_t *int16;
    const uint32_t *int32;
    const struct in_addr *ip4;
    const struct in6_addr *ip6;
    const uint8_t *octets;
  };
  uint16_t length;
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
  const zone_field_t *, // owner
  const zone_field_t *, // ttl
  const zone_field_t *, // class
  const zone_field_t *, // type
  void *); // user data

// invoked for each rdata item in a record (network order)
typedef zone_return_t(*zone_accept_rdata_t)(
  const zone_parser_t *,
  const zone_field_t *, // rdata,
  void *); // user data

// invoked to finish each record. i.e. end-of-file and newline
typedef zone_return_t(*zone_accept_t)(
  const zone_parser_t *,
  const zone_field_t *, // end-of-file or newline
  void *); // user data

typedef void *(*zone_malloc_t)(void *arena, size_t size);
typedef void *(*zone_realloc_t)(void *arena, void *ptr, size_t size);
typedef void(*zone_free_t)(void *arena, void *ptr);

// be leanient when parsing zone files. use of this flag is discouraged as
// servers may interpret fields differently, but can be useful in sitations
// where provisioning software or the primary name server outputs slightly
// malformed zone files
#define ZONE_LENIENT (1<<0)

typedef struct zone_options zone_options_t;
struct zone_options {
  // FIXME: add a flags member. e.g. to allow for includes in combination
  //        with static buffers, signal ownership of allocated memory, etc
  // FIXME: a compiler flag indicating host or network order might be useful
  uint32_t flags;
  const char *origin;
  uint16_t default_class; // << don't think we need this, right?!?!
  uint32_t ttl;
  size_t block_size;
  struct {
    zone_malloc_t malloc;
    zone_realloc_t realloc;
    zone_free_t free;
    void *arena;
  } allocator;
  struct {
    // FIXME: add callback to accept rdlength for generic records?
    zone_accept_name_t name;
    zone_accept_rr_t rr;
    zone_accept_rdata_t rdata;
    zone_accept_t delimiter;
  } accept;
};

struct zone_parser {
  zone_options_t options;
  zone_file_t first, *file;
  struct {
    zone_code_t scanner;
    // some record types require special handling of rdata. e.g.
    //   WKS: bitmap of services for the given protocol
    //   NSEC: bitmap of rrtypes available in next secure record
    //   BASE64: base64 encoded data that may contain spaces
    //
    // state information is separated to allow for generic reset
    struct {
      const void *protocol;
      uint16_t highest_port;
    } wks;
    struct {
      uint16_t highest_bit;
    } nsec;
    // base16 state can be any of:
    //   0: parse bits 0-3
    //   1: parse bits 4-7
    uint8_t base16;
    uint8_t base32;
    // base64 state can be any of:
    //   0: parse bits 0-5
    //   1: parse bits 6-11
    //   2: parse bits 12-17
    //   3: parse bits 18-23
    //   4: parsed 8 bits and have one '='
    //   5: parsed 8 or 16 bits and have one '='
    uint8_t base64;
  } state;
  struct {
    // small backlog to track items before invoking accept_rr
    struct {
      zone_field_t field;
      union {
        // owner name is stored on a per-file base
        uint16_t int16; // class + type
        uint32_t int32; // ttl
      };
    } items[5]; // { owner, ttl, class, type, rdata }
    struct {
      const zone_type_descriptor_t *type;
      const zone_field_descriptor_t *rdata;
    } descriptors;
  } rr;
  struct {
    size_t length;
    union {
      uint8_t int8;
      uint16_t int16;
      uint32_t int32;
      struct in_addr ip4;
      struct in6_addr ip6;
      uint8_t name[255];
      uint8_t string[1 + 255];
      uint8_t wks[UINT16_MAX / 8];
      uint8_t nsec[256][2 + 256 / 8];
      uint8_t svcb[UINT16_MAX];
      uint8_t base16[UINT16_MAX];
      uint8_t base32[UINT16_MAX];
      uint8_t base64[UINT16_MAX];
    };
  } rdata;
};

// return codes
#define ZONE_SUCCESS (0)
#define ZONE_SYNTAX_ERROR (-1)
#define ZONE_SEMANTIC_ERROR (-2)
#define ZONE_OUT_OF_MEMORY (-3)
#define ZONE_BAD_PARAMETER (-4)
#define ZONE_READ_ERROR (-5)
#define ZONE_NOT_IMPLEMENTED (-6)

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

#endif // ZONE_H
