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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// FIXME: need to remove these includes
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>

typedef int32_t zone_return_t;

typedef struct zone_string zone_string_t;
struct zone_string {
  size_t length;
  const char *data;
};

// @private
typedef struct zone_token zone_token_t;
struct zone_token {
  zone_string_t string;
};

typedef struct zone_symbol zone_symbol_t;
struct zone_symbol {
  zone_string_t key;
  uint32_t value;
};

typedef struct zone_table zone_table_t;
struct zone_table {
  size_t length;
  const zone_symbol_t *symbols; // sorted for use with bsearch
};

typedef struct zone_name zone_name_t;
struct zone_name {
  size_t length;
  uint8_t octets[256];
};

typedef int32_t zone_code_t;

// types are defined by their binary representation. this is different from
// dnsextlang, which defines types mostly by their textual representation.
// e.g. I4, T and T[L] are different field types in dnsextlang, but the wire
// format is identical. qualifiers, like time and ttl, are available from the
// field descriptor for completeness.
typedef enum {
  ZONE_INT8 = (1 << 14),
  ZONE_INT16 = (2 << 14),
  ZONE_INT32 = (3 << 14),
  ZONE_IP4 = (4 << 14),
  ZONE_IP6 = (5 << 14),
  ZONE_NAME = (6 << 14),
  ZONE_STRING = (1 << 8),
  // (B)inary (L)arge (Ob)ject. Inspired by relational database terminology.
  // Must be last.
  ZONE_BLOB = (7 << 14),
  // hex fields
  // ZONE_EUI48 (ZONE_HEX6?)
  // ZONE_EUI64 (ZONE_HEX8?)
  // miscellaneous fields
  ZONE_SVC_PARAM = (1 << 9),
  ZONE_WKS = (8 << 14),
  ZONE_NSEC = (9 << 14)
} zone_type_t;

typedef enum {
  ZONE_TTL = (1 << 0), // may be used as qualifier for int32 rdata
  ZONE_CLASS = (1 << 1),
  ZONE_TYPE = (1 << 2), // may be used as qualifier for int16 rdata
  ZONE_OWNER = (2 << 3),
  ZONE_RDATA = (3 << 3),
  ZONE_DOLLAR_ORIGIN
} zone_item_t;

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

typedef struct zone_field_info zone_field_info_t;
struct zone_field_info {
  const char *name;
  const size_t length;
  zone_type_t type;
  uint32_t qualifiers;
  zone_table_t symbols;
  const char *description;
};

// type options
#define ZONE_IN (1<<1)
#define ZONE_ANY (1<<2)
#define ZONE_EXPERIMENTAL (1<<3)
#define ZONE_OBSOLETE (1<<4)

typedef struct zone_type_info zone_type_info_t;
struct zone_type_info {
  const char *name;
  const size_t length;
  uint16_t type;
  uint32_t options;
  const char *description;
};

typedef struct zone_field zone_field_t;
struct zone_field {
  zone_code_t code; // OR'ed combination of type and item
  union {
    const zone_type_info_t *type; // type fields
    const zone_field_info_t *rdata; // rdata fields
  } info;
  uint16_t length;
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
  } data;
};

#define ZONE_BLOCK_SIZE (64)

// tape capacity must be large enough to hold every token from a single
// worst-case read (e.g. 64 consecutive line feeds). in practice a single
// block will never contain 64 tokens, therefore, to optimize throughput,
// allocate twice the size so consecutive index operations can be done
#define ZONE_TAPE_SIZE (100 * (ZONE_BLOCK_SIZE + ZONE_BLOCK_SIZE))

// @private
typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  struct {
    const void *domain;
    zone_name_t name;
  } origin, owner;
  uint16_t last_type;
  uint32_t last_ttl, default_ttl;
  uint16_t last_class;
  size_t line;
  const char *name;
  const char *path;
  int handle;
  bool start_of_line;
  bool end_of_file;
  struct {
    size_t index, length, size;
    char *data;
  } buffer;
  // indexer state is stored per-file
  struct {
    uint64_t in_comment;
    uint64_t in_quoted;
    uint64_t is_escaped;
    uint64_t follows_contiguous;
    // vector of tokens generated by the indexer. guaranteed to be large
    // enough to hold every token for a single read + terminator
    size_t *head, *tail, tape[ZONE_TAPE_SIZE + 1];
  } indexer;
};

typedef struct zone_parser zone_parser_t;
struct zone_parser;

// invoked for each record (host order). header (owner, type, class and ttl)
// fields are passed individually for convenience. rdata fields can be visited
// individually by means of the iterator
typedef zone_return_t(*zone_accept_rr_t)(
  zone_parser_t *,
  const zone_field_t *, // owner
  const zone_field_t *, // type
  const zone_field_t *, // class
  const zone_field_t *, // ttl
  const zone_field_t *, // rdatas
  uint16_t, // rdlength
  const uint8_t *, // rdata
  void *); // user data


typedef void *(*zone_malloc_t)(void *arena, size_t size);
typedef void *(*zone_realloc_t)(void *arena, void *ptr, size_t size);
typedef void(*zone_free_t)(void *arena, void *ptr);

typedef struct zone_options zone_options_t;
struct zone_options {
  // FIXME: add a flags member. e.g. to allow for includes in combination
  //        with static buffers, signal ownership of allocated memory, etc
  // FIXME: a compiler flag indicating host or network order might be useful
  uint32_t flags;
  const char *origin;
  uint32_t default_ttl;
  uint32_t default_class;
  struct {
    zone_malloc_t malloc;
    zone_realloc_t realloc;
    zone_free_t free;
    void *arena;
  } allocator;
  zone_accept_rr_t accept;
};

// FIXME: add option to mmap?!
typedef struct zone_parser zone_parser_t;
struct zone_parser {
  zone_options_t options;
  zone_file_t first, *file;
  size_t line;
  struct {
    zone_code_t scanner;
    uint32_t base16;
    uint32_t base32;
    uint32_t base64;
    struct {
      uint16_t highest_bit;
      uint8_t bitmap[256][2 + 256 / 8];
    } nsec;
  } state;
  zone_field_t items[5]; // { owner, type, class, ttl, rdata }
  zone_field_t *rdata_items;
  size_t rdlength;
  uint8_t rdata[UINT16_MAX];
};

// return codes
#define ZONE_SUCCESS (0)
#define ZONE_SYNTAX_ERROR (-1)
#define ZONE_SEMANTIC_ERROR (-2)
#define ZONE_OUT_OF_MEMORY (-3)
#define ZONE_BAD_PARAMETER (-4)
#define ZONE_READ_ERROR (-5)
#define ZONE_NOT_IMPLEMENTED (-6)

zone_return_t zone_open_string(
  zone_parser_t *parser, const zone_options_t *options, const char *str, size_t len);

zone_return_t zone_open(
  zone_parser_t *parser, const zone_options_t *options, const char *file);

void zone_close(zone_parser_t *parser);

zone_return_t zone_parse(zone_parser_t *parser, void *user_data);

inline zone_item_t zone_item(const zone_field_t *field)
{
  (void)field;
  return 0; // implement
}

inline zone_type_t zone_type(const zone_field_t *field)
{
  (void)field;
  return 0; // implement
}

inline uint32_t zone_qualifiers(const zone_field_t *field)
{
  (void)field;
  return 0; // implement
}

/**
 * @brief Iterate fields in record
 *
 * @note Must only be used from within @zone_accept_rr_t callback.
 *
 * @param[in]  parser  Parser
 * @param[in]  field   Field
 *
 * @returns Next field in record or NULL if there are no more fields
 */
inline zone_field_t *
zone_foreach(zone_parser_t *parser, zone_field_t *field)
{
  assert(parser);
  assert(parser->state.scanner & ZONE_RDATA);
  assert(parser->rdata_items);

  if (!field)
    return &parser->items[0];

  switch (zone_item(field)) {
    case ZONE_OWNER:
      return &parser->items[1]; // type
    case ZONE_TYPE:
      return &parser->items[2]; // class
    case ZONE_CLASS:
      return &parser->items[3]; // ttl
    case ZONE_TTL:
      if (!(zone_qualifiers(&parser->rdata_items[0]) & ZONE_SEQUENCE))
        return &parser->rdata_items[0]; // rdata
      parser->items[4] = parser->rdata_items[0];
      return &parser->items[4]; // sequence rdata
    case ZONE_RDATA:
      if (field == &parser->items[4])
        break;

      assert(field >= parser->rdata_items);
      assert(field[0].code);

      if (!(zone_type(&field[1])))
        return NULL;
      if (!(zone_qualifiers(&field[1]) & ZONE_SEQUENCE))
        return &field[1];
      parser->items[4] = parser->rdata_items[0];
      return &parser->items[4];
    default:
      abort();
  }

  uintptr_t used = (uintptr_t)field->data.octets - (uintptr_t)parser->rdata;
  if (used >= parser->rdlength - field->length)
    return NULL;

  assert(field == &parser->items[4]);
  field->data.octets += field->length;

  switch (zone_type(field)) {
    case ZONE_SVC_PARAM:
      field->length = ntohs(*(uint16_t *)&field->data.octets[2]);
      return field;
    case ZONE_STRING:
      field->length = 1 + field->data.octets[0];
      return field;
    default:
      abort();
  }
}

#endif // ZONE_H
