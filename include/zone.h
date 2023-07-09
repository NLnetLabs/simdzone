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

/**
 * @file
 * @brief simdzone main header
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "zone/attributes.h"
#include "zone/export.h"

#if defined (__cplusplus)
extern "C" {
#endif

/**
 * @defgroup class_codes Class codes
 *
 * @{
 */
/** Internet @rfc{1035} */
#define ZONE_IN (1u)
/** CSNET @rfc{1035} @obsolete */
#define ZONE_CS (2u)
/** CHAOS @rfc{1035} */
#define ZONE_CH (3u)
/** Hesiod @rfc{1035} */
#define ZONE_HS (4u)
/** @} */

/**
 * @defgroup type_codes Type codes
 *
 * @{
 */
/** Host address @rfc{1035} */
#define ZONE_A (1u)
/** Authoritative name server @rfc{1035} */
#define ZONE_NS (2u)
/** Mail destination @rfc{1035} @obsolete */
#define ZONE_MD (3u)
/** Mail forwarder @rfc{1035} @obsolete */
#define ZONE_MF (4u)
/** Canonical name for an alias @rfc{1035} */
#define ZONE_CNAME (5u)
/** Marks the start of authority @rfc{1035} */
#define ZONE_SOA (6u)
/** Mailbox domain name @rfc{1035} @experimental */
#define ZONE_MB (7u)
/** Mail group member @rfc{1035} @experimental */
#define ZONE_MG (8u)
/** Mail rename domain name @rfc{1035} @experimental */
#define ZONE_MR (9u)
/** Anything @rfc{883} @obsolete */
#define ZONE_NULL (10u)
/** Well known service description @rfc{1035} */
#define ZONE_WKS (11u)
/** Domain name pointer @rfc{1035} */
#define ZONE_PTR (12u)
/** Host information @rfc{1035} */
#define ZONE_HINFO (13u)
/** Mailbox or mail list information @rfc{1035} */
#define ZONE_MINFO (14u)
/** Mail exchange @rfc{1035} */
#define ZONE_MX (15u)
/** Text strings @rfc{1035} */
#define ZONE_TXT (16u)
/** Responsible person @rfc{1035} */
#define ZONE_RP (17u)
/** AFS Data Base location @rfc{1183} @rfc{5864} */
#define ZONE_AFSDB (18u)
/** X.25 PSDN address @rfc{1183} */
#define ZONE_X25 (19u)
/** ISDN address @rfc{1183} */
#define ZONE_ISDN (20u)
/** Route Through @rfc{1183} */
#define ZONE_RT (21u)
/** NSAP address, NSAP style A record @rfc{1706} */
#define ZONE_NSAP (22u)
/** Domain name pointer, NSAP style @rfc{1348} @rfc{1637} */
#define ZONE_NSAP_PTR (23u)
/** Signature @rfc{2535} */
#define ZONE_SIG (24u)
/** Public key @rfc{2535} @rfc{2930} */
#define ZONE_KEY (25u)
/** X.400 mail mapping information @rfc{2163} */
#define ZONE_PX (26u)
/** Geographical Position @rfc{1712} */
#define ZONE_GPOS (27u)
/** IPv6 Address @rfc{3596} */
#define ZONE_AAAA (28u)
/** Location Information @rfc{1876} */
#define ZONE_LOC (29u)
/** Next domain @rfc{3755} @rfc{2535} @obsolete */
#define ZONE_NXT (30u)
/** Server Selection @rfc{2782} */
#define ZONE_SRV (33u)
/** Naming Authority Pointer @rfc{2915} @rfc{2168} @rfc{3403} */
#define ZONE_NAPTR (35u)
/** Key Exchanger @rfc{2230} */
#define ZONE_KX (36u)
/** CERT [RFC4398] */
#define ZONE_CERT (37u)
/** IPv6 Address @rfc{3226} @rfc{2874} @rfc{6563} @obsolete */
#define ZONE_A6 (38u)
/** DNAME @rfc{6672} */
#define ZONE_DNAME (39u)
/** Address Prefix List @rfc{3123} */
#define ZONE_APL (42u)
/** Delegation Signer @rfc{4034} @rfc{3658} */
#define ZONE_DS (43u)
/** SSH Key Fingerprint @rfc{4255} */
#define ZONE_SSHFP (44u)
/** IPsec public key @rfc{4025} */
#define ZONE_IPSECKEY (45u)
/** Resource Record Signature @rfc{4034} @rfc{3755} */
#define ZONE_RRSIG (46u)
/** Next Secure @rfc{4034} @rfc{3755} */
#define ZONE_NSEC (47u)
/** DNS Public Key @rfc{4034} @rfc{3755} */
#define ZONE_DNSKEY (48u)
/** DHCID [RFC4701] */
#define ZONE_DHCID (49u)
/** NSEC3 [RFC5155] */
#define ZONE_NSEC3 (50u)
/** NSEC3PARAM [RFC5155] */
#define ZONE_NSEC3PARAM (51u)
/** TLSA @rfc{6698} */
#define ZONE_TLSA (52u)
/** S/MIME cert association @rfc{8162} */
#define ZONE_SMIMEA (53u)
/** Host Identity Protocol @rfc{8005} */
#define ZONE_HIP (55u)
/** Child DS @rfc{7344} */
#define ZONE_CDS (59u)
/** DNSKEY(s) the Child wants reflected in DS @rfc{7344} */
#define ZONE_CDNSKEY (60u)
/** OpenPGP Key @rfc{7929} */
#define ZONE_OPENPGPKEY (61u)
/** Child-To-Parent Synchronization @rfc{7477} */
#define ZONE_CSYNC (62u)
/** Zone message digest @rfc{8976} */
#define ZONE_ZONEMD (63u)
/** Service binding @draft{dnsop,svcb-https} */
#define ZONE_SVCB (64u)
/** Service binding @draft{dnsop,svcb-https} */
#define ZONE_HTTPS (65u)
/** Sender Policy Framework @rfc{7208} */
#define ZONE_SPF (99u)
/** Node Identifier @rfc{6742} */
#define ZONE_NID (104u)
/** 32-bit Locator for ILNPv4-capable nodes @rfc{6742} */
#define ZONE_L32 (105u)
/** 64-bit Locator for ILNPv6-capable nodes @rfc{6742} */
#define ZONE_L64 (106u)
/** Name of an ILNP subnetwork @rfc{6742} */
#define ZONE_LP (107u)
/** EUI-48 address @rfc{7043} */
#define ZONE_EUI48 (108u)
/** EUI-64 address @rfc{7043} */
#define ZONE_EUI64 (109u)
/** Uniform Resource Identifier @rfc{7553} */
#define ZONE_URI (256u)
/** Certification Authority Restriction @rfc{6844} */
#define ZONE_CAA (257u)
/** DNSSEC Lookaside Validation @rfc{4431} */
#define ZONE_DLV (32769u)
/** @} */

typedef int32_t zone_code_t;
typedef int32_t zone_return_t;

typedef struct zone_string zone_string_t;
struct zone_string {
  size_t length;
  const char *data;
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

// @private
//
// bsearch is quite slow compared to a hash table, but a hash table is either
// quite big or there is a significant chance or collisions. a minimal perfect
// hash table can be used instead, but there is a good chance of mispredicted
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
//  2. multiply the character by a given number to get a reasonably good
//     distribution.
//  3. increment the character by the length of the identifier to ensure
//     unique keys for identifiers that begin and end with the same
//     characters. e.g. A and AAAA.
typedef struct zone_fast_table zone_fast_table_t;
struct zone_fast_table {
  uint8_t keys[16];
  const zone_symbol_t *symbols[16];
};

/**
 * @brief Type of value defined by field
 *
 * Fields are defined by their binary representation, NOT their textual
 * representation. e.g. time-to-live and timestamp fields are encoded as
 * 32-bit integers on the wire. @ref type_qualifiers are used to complement
 * the type information. e.g. @ref ZONE_TTL and @ref ZONE_TIME can be used to
 * provide extra information regarding the aforementioned types.
 */
typedef enum {
  ZONE_INT8,
  ZONE_INT16,
  ZONE_INT32,
  ZONE_IP4,
  ZONE_IP6,
  ZONE_NAME,
  ZONE_STRING,
  // (B)inary (L)arge (Ob)ject. Inspired by relational database terminology.
  // Must be last.
  ZONE_BLOB,
  // hex fields
  // ZONE_EUI48 (ZONE_HEX6?)
  // ZONE_EUI64 (ZONE_HEX8?)
  // miscellaneous fields
  ZONE_SVC_PARAM, /**< SVCB service parameter */
  ZONE_TYPE_BITMAP /**< NSEC type bitmap */
} zone_type_t;

/**
 * @defgroup type_qualifiers Type qualifiers
 *
 * Type qualifiers provide additional information for RDATA fields. Types
 * indicate the binary representation of an RDATA field, qualifier(s) can be
 * used to communicate semantics. e.g. a time-to-live is presented on the
 * wire as a 32-bit integer, ZONE_TTL can be used to signal the field
 * represents a time-to-live value.
 *
 * @note Some types allow for more than one qualifier to be specified, hence
 *       each qualifier is assigned a separate bit.
 *
 * @{
 */
/**
 * @brief Type code (#ZONE_INT16)
 *
 * Type codes may appear in text by name or generic type notation @rfc{3597}.
 */
#define ZONE_TYPE (1u << 0)
/**
 * @brief Class code (#ZONE_INT16)
 *
 * Class codes may appear in text by name or generic class notation @rfc{3597}.
 */
#define ZONE_CLASS (1u << 1)
/**
 * @brief Time-to-live (TTL) (#ZONE_INT32)
 *
 * Time-to-live values may appear in text as numeric value (seconds) or in
 * "1h2m3s" notation (@e extension).
 */
#define ZONE_TTL (1u << 2)
/**
 * @brief Timestamp (#ZONE_INT32)
 *
 * Timestamps must be presented in text in "YYYYMMDDHHmmSS" notation.
 */
#define ZONE_TIME (1u << 3)
/** @brief Text representation is base16 (#ZONE_STRING or #ZONE_BLOB) */
#define ZONE_BASE16 (1u << 4)
/** @brief Text representation is base32 (#ZONE_BLOB) */
#define ZONE_BASE32 (1u << 5)
/** @brief Text representation is base64 (#ZONE_BLOB) */
#define ZONE_BASE64 (1u << 6)
/** @brief Name is compressed (#ZONE_NAME) */
#define ZONE_COMPRESSED (1u << 7)
/** @brief Name represents a mailbox (#ZONE_NAME) */
#define ZONE_MAILBOX (1u << 8)
/** @brief Name is converted to lower case for DNSSEC validation (#ZONE_NAME) */
#define ZONE_LOWER_CASE (1u << 9)
/** @brief Optional (#ZONE_NAME) */
#define ZONE_OPTIONAL (1u << 10)
/**
 * @brief May occur multiple times (#ZONE_STRING or #ZONE_SVC_PARAM)
 *
 * Field may occur multiple times. e.g. #ZONE_STRING in #ZONE_TXT or
 * #ZONE_SVC_PARAM in #ZONE_SVCB. Sequences must be the last field in the
 * record.
 */
#define ZONE_SEQUENCE (1u << 11)
/** @} */

typedef struct zone_rdata_info zone_rdata_info_t;
struct zone_rdata_info {
  zone_string_t name;
  uint32_t type;
  uint32_t qualifiers;
  zone_table_t symbols;
};

typedef struct zone_rdata_info zone_field_info_t;

/**
 * @defgroup options Type options
 * @brief Options for record types
 *
 * @{
 */
// type options
// ZONE_IN goes here too!
#define ZONE_ANY (1<<2)
#define ZONE_EXPERIMENTAL (1<<3)
#define ZONE_OBSOLETE (1<<4)
/** @} */

typedef struct zone_type_info zone_type_info_t;
struct zone_type_info {
  zone_string_t name;
  uint16_t code;
  uint32_t options;
  struct {
    size_t length;
    const zone_rdata_info_t *fields;
  } rdata;
};

#define ZONE_BLOCK_SIZE (64)
#define ZONE_WINDOW_SIZE (256 * ZONE_BLOCK_SIZE) // 16KB


// tape capacity must be large enough to hold every token from a single
// worst-case read (e.g. 64 consecutive line feeds). in practice a single
// block will never contain 64 tokens, therefore, to optimize throughput,
// allocate twice the size so consecutive index operations can be done
#define ZONE_TAPE_SIZE (100 * (ZONE_BLOCK_SIZE + ZONE_BLOCK_SIZE))

typedef struct zone_name_block zone_name_block_t;
struct zone_name_block {
  size_t length; /**< Length of domain name stored in block */
  uint8_t octets[ 255 + ZONE_BLOCK_SIZE ];
};

typedef struct zone_rdata_block zone_rdata_block_t;
struct zone_rdata_block {
  size_t length; /**< Length of RDATA stored in block */
  uint8_t octets[ 65535 + 4096 /* nsec padding */ ];
};

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

// @private
typedef struct zone_file zone_file_t;
struct zone_file {
  zone_file_t *includer;
  zone_name_block_t origin, owner;
  uint16_t last_type;
  uint32_t last_ttl, default_ttl;
  uint16_t last_class;
  // non-terminating line feeds, i.e. escaped line feeds, line feeds in quoted
  // sections or within parentheses, are counted, but deferred for consistency
  // in error reports
  size_t span; /**< number of lines spanned by record */
  size_t line; /**< starting line of record */
  char *name;
  char *path;
  FILE *handle;
  bool grouped;
  bool start_of_line;
  enum { ZONE_HAVE_DATA, ZONE_READ_ALL_DATA, ZONE_NO_MORE_DATA } end_of_file;
  struct {
    size_t index, length, size;
    char *data;
  } buffer;
  // indexer state is kept per-file
  struct {
    uint64_t in_comment;
    uint64_t in_quoted;
    uint64_t is_escaped;
    uint64_t follows_contiguous;
  } state;
  // vector of tokens generated by the indexer. guaranteed to be large
  // enough to hold every token for a single read + terminators
  struct { const char **head, **tail, *tape[ZONE_TAPE_SIZE + 2]; } fields;
  struct { uint16_t *head, *tail, tape[ZONE_TAPE_SIZE + 1]; } lines;
};

typedef struct zone_parser zone_parser_t;
struct zone_parser;

/**
 * @defgroup log_categories Log categories.
 *
 * @note No direct relation between log categories and error codes exists.
 *       Log categories communicate the importance of the log message, error
 *       codes communicate what went wrong to the caller.
 * @{
 */
/** Error condition. */
#define ZONE_ERROR (1u<<1)
/** Warning condition. */
#define ZONE_WARNING (1u<<2)
/** Informational message. */
#define ZONE_INFO (1u<<3)
/** @} */

typedef void(*zone_log_t)(
  zone_parser_t *,
  const char *, // file
  size_t, // line
  const char *, // function
  uint32_t, // category
  const char *, // message
  void *); // user data

/**
 * @brief Write error message to active log handler.
 *
 * @note Direct use is discouraged. Use of #ZONE_LOG instead.
 *
 * @param[in]  parser    Zone parser
 * @param[in]  file      Name of source file
 * @param[in]  line      Line number in source file
 * @param[in]  function  Name of function
 * @param[in]  category  Log category
 * @param[in]  format    Format string compatible with printf
 * @param[in]  ...       Variadic arguments corresponding to #format
 */
ZONE_EXPORT void zone_log(
  zone_parser_t *parser,
  const char *file,
  size_t line,
  const char *function,
  uint32_t category,
  const char *format,
  ...)
zone_nonnull((1,2,4,6))
zone_format_printf(6,7);

/**
 * @brief Write log message to active log handler.
 *
 * The zone parser operates on a per-record base and therefore cannot detect
 * errors that span records. e.g. SOA records being specified more than once.
 * The user may print a message using the active log handler, keeping the
 * error message format consistent.
 *
 * @param[in]  parser    Zone parser
 * @param[in]  category  Log category
 * @param[in]  format    Format string compatible with printf
 * @param[in]  ...       Variadic arguments corresponding to @ref format
 */
#define ZONE_LOG(parser, category, ...) \
  zone_log(parser, __FILE__, __LINE__, __func__, category, __VA_ARGS__)

typedef struct zone_name zone_name_t;
struct zone_name {
  uint8_t length;
  uint8_t *octets;
};

// invoked for each record (host order). header (owner, type, class and ttl)
// fields are passed individually for convenience. rdata fields can be visited
// individually by means of the iterator
typedef zone_return_t(*zone_add_t)(
  zone_parser_t *,
  const zone_name_t *, // owner (length + octets)
  uint16_t, // type
  uint16_t, // class
  uint32_t, // ttl
  uint16_t, // rdlength
  const uint8_t *, // rdata
  void *); // user data

typedef struct {
  /** Lax mode of operation. */
  /** Authoritative servers may choose to be more lenient when operating as
      as a secondary as data may have been transferred over AXFR/IXFR that
      would have triggered an error otherwise. */
  bool secondary;
  /** Disable $INCLUDE directive. */
  /** Useful in setups where untrusted input may be offered. */
  bool no_includes;
  /** Enable 1h2m3s notations for TTLS. */
  bool pretty_ttls;
  const char *origin;
  uint32_t default_ttl;
  uint16_t default_class;
  struct {
    /** Message categories to write out. */
    /** All categories are printed if no categories are selected and no
        custom callback was specified. */
    uint32_t categories;
    /** Callback used to write out log messages. */
    zone_log_t write;
  } log;
  struct {
    zone_add_t add;
    // FIXME: more callbacks to be added at a later stage to support efficient
    //        (de)serialization of AXFR/IXFR in text representation.
    //zone_delete_t remove;
  } accept;
} zone_options_t;

/**
 * @brief Buffer space reserved for parser
 *
 * Depending on the use case, parsing resource records and committing the data
 * are disjunct operations. Specifically, authoritative name servers may want
 * to parse and commit in parallel to cut load times. Allocate multiple buffers
 * to allow for asynchronous operation.
 *
 * Synchronization between submission and completion is the responsibility of
 * the application. The return code of the accept operation indicates which
 * rdata buffer to use next. Rotation of name buffers is controlled by the
 * parser.
 */
typedef struct zone_cache zone_cache_t;
struct zone_cache {
  size_t size; /**< Number of name and rdata storage blocks available */
  zone_name_block_t *owner;
  zone_rdata_block_t *rdata;
};

struct zone_parser {
  zone_options_t options;
  void *user_data;
  volatile void *environment; // FIXME: not sure about this yet
  struct {
    size_t size;
    struct {
      size_t serial;
      zone_name_block_t *blocks;
    } owner;
    struct {
      zone_rdata_block_t *blocks;
    } rdata;
  } cache;
  zone_name_block_t *owner;
  zone_rdata_block_t *rdata;
  zone_file_t *file, first;
};

/**
 * @defgroup return_codes Return codes
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
/** Control directive or support for record type is not implemented */
#define ZONE_NOT_IMPLEMENTED (-6)
/** Specified file does not exist */
#define ZONE_NOT_A_FILE (-6)
/** Access to specified file is not allowed */
#define ZONE_NOT_PERMITTED (-7)
/** @} */

/**
 * @brief Parse zone file
 */
ZONE_EXPORT zone_return_t
zone_parse(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_cache_t *cache,
  const char *path,
  void *user_data)
zone_nonnull((1,2,3,4));

/**
 * @brief Parse zone from string
 */
ZONE_EXPORT zone_return_t
zone_parse_string(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_cache_t *cache,
  const char *string,
  size_t length,
  void *user_data)
zone_nonnull((1,2,3,4));

#if defined(__cplusplus)
}
#endif

#endif // ZONE_H
