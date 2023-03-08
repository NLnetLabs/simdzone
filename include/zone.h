/*
 * zone.h -- (DNS) zone parser
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ZONE_H
#define ZONE_H

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "zone/attributes.h"
#include "zone/macros.h"
#include "zone/export.h"

#if defined (__cplusplus)
extern "C" {
#endif

/**
 * @defgroup class_codes Class codes
 *
 * {@
 */
#define ZONE_IN (1u)
#define ZONE_CS (2u)
#define ZONE_CH (3u)
#define ZONE_HS (4u)
/** @} */

/**
 * @defgroup type_codes Type codes
 *
 * {@
 */
#define ZONE_A (1u) /**< Host address [RFC1035] */
#define ZONE_NS (2u) /**< Authoritative name server [RFC1035] */
#define ZONE_MD (3u) /**< Mail destination (obsolete) [RFC1035] */
#define ZONE_MF (4u)
#define ZONE_CNAME (5u)
#define ZONE_SOA (6u)
#define ZONE_MB (7u)
#define ZONE_MG (8u)
#define ZONE_MR (9u)
#define ZONE_NULL (10u)
#define ZONE_WKS (11u)
#define ZONE_PTR (12u)
#define ZONE_HINFO (13u)
#define ZONE_MINFO (14u)
#define ZONE_MX (15u)
#define ZONE_TXT (16u)
#define ZONE_RP (17u)
#define ZONE_AFSDB (18u)
#define ZONE_X25 (19u)
#define ZONE_ISDN (20u)
#define ZONE_RT (21u)
#define ZONE_NSAP (22u)
#define ZONE_NSAP_PTR (23u)
#define ZONE_KEY (25u)
#define ZONE_SIG (24u)
#define ZONE_PX (26u)
#define ZONE_GPOS (27u)
#define ZONE_AAAA (28u)
#define ZONE_LOC (29u)
#define ZONE_NXT (30u)
#define ZONE_SRV (33u)
#define ZONE_NAPTR (35u)
#define ZONE_KX (36u)
#define ZONE_CERT (37u)
#define ZONE_A6 (38u)
#define ZONE_DNAME (39u)
#define ZONE_OPT (41u)
#define ZONE_APL (42u)
#define ZONE_DS (43u)
#define ZONE_SSHFP (44u)
#define ZONE_IPSECKEY (45u)
#define ZONE_RRSIG (46u)
#define ZONE_NSEC (47u)
#define ZONE_DNSKEY (48u)
#define ZONE_DHCID (49u)
#define ZONE_NSEC3 (50u)
#define ZONE_NSEC3PARAM (51u)
#define ZONE_TLSA (52u)
#define ZONE_SMIMEA (53u)
#define ZONE_SVCB (54u)
#define ZONE_HIP (55u)
#define ZONE_CDS (59u)
#define ZONE_CDNSKEY (60u)
#define ZONE_CSYNC (62u)
#define ZONE_ZONEMD (63u)
#define ZONE_HTTPS (65u)
#define ZONE_OPENPGPKEY (69u)
#define ZONE_SPF (99u)
#define ZONE_NID (104u)
#define ZONE_L32 (105u)
#define ZONE_L64 (106u)
#define ZONE_LP (107u)
#define ZONE_EUI48 (108u)
#define ZONE_EUI64 (109u)
#define ZONE_URI (256u)
#define ZONE_CAA (257u)
#define ZONE_DLV (32769u)
/** @} */

typedef int32_t zone_return_t;

typedef struct zone_string zone_string_t;
struct zone_string {
  size_t length;
  const char *data;
};

// @private
#define ZONE_DELIMITER (0u)
#define ZONE_CONTIGUOUS (1u<<0)
#define ZONE_QUOTED (1u<<1)

typedef zone_string_t zone_token_t;

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

ZONE_EXPORT int
zone_compare(const void *s1, const void *s2)
zone_nonnull_all();

zone_always_inline()
zone_nonnull_all()
inline zone_symbol_t *zone_lookup(
  const zone_table_t *table, const zone_string_t *string)
{
  const zone_symbol_t key = { *string, 0 };
  return bsearch(&key, table->symbols, table->length, sizeof(key), zone_compare);
}

// @private
//
// bsearch is quite slow compared to a hash table, but a hash table is either
// quite big or there is a significant chance or collisions. a minimal perfect
// hash table can be used instead, but there is a good chance of misspredicted
// branches.
//
// the fast table provides a hybrid solution. the current incarnation uses the
// first (upper case) character to make a first selection. the last character
// is permuted and used as key for the smaller table. in practice, it should
// effectively function as a one-level radix trie without branching.
//
// the permutation used is the following.
//  1. use the last character as one always exists, token length is available,
//     is very likely alphanumeric and likely does not reoccur too often for
//     records starting with the same alphabetic character. this will provide
//     a unique key for e.g. MB, MD, MF MG, MR, MX and e.g. NSEC, NSEC3.
//  2. multiply the character by a given number to get a reasonbly good
//     distribution.
//  3. increment the character by the length of the identifier to ensure
//     unique keys for identifiers that begin and end with the same
//     characters. e.g. A and AAAA.
typedef struct zone_fast_table zone_fast_table_t;
struct zone_fast_table {
  uint8_t keys[16];
  const zone_symbol_t *symbols[16];
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
  //ZONE_WKS = (8 << 14), // << will have to be renamed
  //ZONE_NSEC = (9 << 14)
  ZONE_TYPE_BITMAP = (9 << 14) // << nsec type bitmap list
} zone_type_t;

typedef enum {
  ZONE_TTL = (1 << 0), // may be used as qualifier for int32 rdata
  ZONE_CLASS = (1 << 1),
  ZONE_TYPE = (1 << 2), // may be used as qualifier for int16 rdata
  ZONE_OWNER = (2 << 3),
  ZONE_RDATA = (3 << 3),
  ZONE_DOLLAR_INCLUDE,
  ZONE_DOLLAR_ORIGIN,
  ZONE_DOLLAR_TTL
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
  zone_string_t name;
  uint32_t type;
  uint32_t qualifiers;
  zone_table_t symbols;
};

typedef struct zone_class_info zone_class_info_t;
struct zone_class_info {
  zone_string_t name;
  uint16_t code;
};

// type options
// ZONE_IN goes here too!
#define ZONE_ANY (1<<2)
#define ZONE_EXPERIMENTAL (1<<3)
#define ZONE_OBSOLETE (1<<4)

typedef struct zone_type_info zone_type_info_t;
struct zone_type_info {
  zone_string_t name;
  uint16_t code;
  uint32_t options;
  struct {
    size_t length;
    const zone_field_info_t *fields;
  } rdata;
};

typedef struct zone_field zone_field_t;
struct zone_field {
  zone_code_t code; // OR'ed combination of type and item
  union {
    const zone_type_info_t *type; // type fields
    const zone_field_info_t *rdata; // rdata fields
  } info;
  uint_fast16_t length;
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
#define ZONE_WINDOW_SIZE (256 * ZONE_BLOCK_SIZE) // 16KB

// tape capacity must be large enough to hold every token from a single
// worst-case read (e.g. 64 consecutive line feeds). in practice a single
// block will never contain 64 tokens, therefore, to optimize throughput,
// allocate twice the size so consecutive index operations can be done
#define ZONE_TAPE_SIZE (100 * (ZONE_BLOCK_SIZE + ZONE_BLOCK_SIZE))

// @private
// non-delimiting tokens may contain (escaped) newlines. tracking newlines
// within tokens by taping them makes the lex operation more complex, resulting
// in a significantly larger binary and slower operation, and may introduce an
// infinite loop if the tape may not be sufficiently large enough. tokens
// containing newlines is very much an edge case, therefore the scanner
// implements an unlikely slow path that tracks the number of escaped newlines
// during tokenization and registers them with each consecutive newline token.
// this mode of operation nicely isolates location tracking in the scanner and
// accommodates parallel processing should that ever be desired
typedef struct zone_transition zone_transition_t;
struct zone_transition {
  const char *address;
  uint32_t newlines; // number of escaped newlines (stored per newline)
};

typedef struct zone_name zone_name_t;
struct zone_name {
  size_t length;
  uint8_t octets[256 + ZONE_BLOCK_SIZE];
};

// @private
typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  zone_name_t origin, owner;
  uint16_t last_type;
  uint32_t last_ttl, default_ttl;
  uint16_t last_class;
  size_t line;
  const char *name;
  const char *path;
  int handle;
  bool grouped;
  bool start_of_line;
  enum { ZONE_HAVE_DATA, ZONE_READ_ALL_DATA, ZONE_NO_MORE_DATA } end_of_file;
  struct {
    size_t index, length, size;
    char *data;
  } buffer;
  // indexer state is kept per-file
  struct {
    uint32_t newlines; // number of escaped newlines
    uint64_t in_comment;
    uint64_t in_quoted;
    uint64_t is_escaped;
    uint64_t follows_contiguous;
    // vector of tokens generated by the indexer. guaranteed to be large
    // enough to hold every token for a single read + terminators
    zone_transition_t *head, *tail, tape[ZONE_TAPE_SIZE + 2];
  } indexer;
};

typedef struct zone_parser zone_parser_t;
struct zone_parser;

typedef void *(*zone_malloc_t)(void *arena, size_t size);
typedef void *(*zone_realloc_t)(void *arena, void *ptr, size_t size);
typedef void(*zone_free_t)(void *arena, void *ptr);

// invoked for each record (host order). header (owner, type, class and ttl)
// fields are passed individually for convenience. rdata fields can be visited
// individually by means of the iterator
typedef zone_return_t(*zone_accept_t)(
  zone_parser_t *,
  const zone_field_t *, // owner
  const zone_field_t *, // type
  const zone_field_t *, // class
  const zone_field_t *, // ttl
  const zone_field_t *, // rdatas
  uint16_t, // rdlength
  const uint8_t *, // rdata
  void *); // user data

// FIXME: add option to mmap?
typedef struct zone_options zone_options_t;
struct zone_options {
  // FIXME: add a flags member. e.g. to allow for includes in combination
  //        with static buffers, signal ownership of allocated memory, etc
  // FIXME: a compiler flag indicating host or network order might be useful
  uint32_t flags;
  const char *origin;
  uint32_t default_ttl;
  uint16_t default_class;
  struct {
    zone_malloc_t malloc;
    zone_realloc_t realloc;
    zone_free_t free;
    void *arena;
  } allocator;
  zone_accept_t accept;
};

// FIXME: add option to mmap?!
typedef struct zone_parser zone_parser_t;
struct zone_parser {
  zone_options_t options;
  volatile void *environment;
  // file should be located towards the end because of the tape that
  // it houses
  zone_file_t first, *file;
  size_t line;
  zone_field_t items[5]; // { owner, type, class, ttl, rdata }
  zone_field_t *rdata_items;
  // >> move rdata to a separate structure. then also merge the nsec (and wks?)
  //    bitmaps etc in there. (increase by 8k), should make for a much saner
  //    interface too!!!!
  size_t rdlength;
  uint8_t rdata[UINT16_MAX + 4096 /* padding for nsec */];
};

/**
 * @brief Write error message
 *
 * Write error message to stderr or active callback.
 *
 * @note Direct use of @zone_error is discouraged. Use @ZONE_ERROR instead.
 *
 * @param[in]  parser    Zone parser
 * @param[in]  code      Error code
 * @param[in]  file      Name of source file
 * @param[in]  line      Line number in source file
 * @param[in]  function  Name of function
 * @param[in]  format    Format string compatible with printf
 */
ZONE_EXPORT void zone_error(
  zone_parser_t *parser,
  zone_code_t code,
  const char *file,
  uint32_t line,
  const char *function,
  zone_format_string(const char *format),
  ...)
zone_nonnull((1,3,5,6))
zone_format_printf(6,7);

/**
 * @brief Write error message
 *
 * Write error message to stderr or active callback.
 *
 * @param[in]  parser  Zone parser
 * @param[in]  code    Error code
 * @param[in]  format  Format string compatible with printf
 *
 * @return void
 */
#define ZONE_ERROR(parser, code, ...) \
  zone_error(parser, code, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @defgroup return_codes Zone return codes
 *
 * @{
 */
/** Success */
#define ZONE_SUCCESS (0)
/** Syntax error */
#define ZONE_SYNTAX_ERROR (-1)
/** Semantic error */
#define ZONE_SEMANTIC_ERROR (-2)
/** Operation failed due to lack of memory */
#define ZONE_OUT_OF_MEMORY (-3)
/** Bad parameter value */
#define ZONE_BAD_PARAMETER (-4)
/** Error reading zone file */
#define ZONE_IO_ERROR (-5)
/** Control directive or support for record type is not implement */
#define ZONE_NOT_IMPLEMENTED (-6)
/** @} */

ZONE_EXPORT zone_return_t
zone_open_string(
  zone_parser_t *parser,
  const zone_options_t *options,
  const char *str,
  size_t len)
zone_nonnull((1,2,3));

ZONE_EXPORT zone_return_t
zone_open(
  zone_parser_t *parser,
  const zone_options_t *options,
  const char *file)
zone_nonnull_all();

ZONE_EXPORT void
zone_close(
  zone_parser_t *parser);

ZONE_EXPORT zone_return_t
zone_parse(
  zone_parser_t *parser,
  void *user_data)
zone_nonnull((1));

ZONE_EXPORT void zone_free(
  zone_options_t *options, void *ptr)
zone_nonnull((1));

ZONE_EXPORT void *zone_malloc(
  zone_options_t *options, size_t size)
zone_nonnull((1))
zone_allocator(zone_free, 2)
zone_attribute((alloc_size(2)));

ZONE_EXPORT void *zone_realloc(
  zone_options_t *options, void *ptr, size_t size)
zone_nonnull((1))
zone_allocator(zone_free, 2)
zone_attribute((alloc_size(3)));

ZONE_EXPORT char *zone_strdup(
  zone_options_t *options, const char *str)
zone_nonnull_all()
zone_allocator(zone_free, 2);

#if 0
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
    case ZONE_SVCB:
      field->length = ntohs(*(uint16_t *)&field->data.octets[2]);
      return field;
    case ZONE_STRING:
      field->length = 1 + field->data.octets[0];
      return field;
    default:
      abort();
  }
}
#endif

#if defined(__cplusplus)
}
#endif

#endif // ZONE_H
