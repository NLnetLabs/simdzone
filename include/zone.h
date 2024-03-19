/*
 * zone.h -- (DNS) presentation format parser
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
/** Any (QCLASS) @rfc{1035} */
#define ZONE_ANY (255u)
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
/** DHCID @rfc{4701} */
#define ZONE_DHCID (49u)
/** NSEC3 @rfc{5155} */
#define ZONE_NSEC3 (50u)
/** NSEC3PARAM @rfc{5155} */
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
/** Service binding @rfc{9460} */
#define ZONE_SVCB (64u)
/** Service binding @rfc{9460} */
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
/** DNS Authoritative Source (DNS-AS) */
#define ZONE_AVC (258u)
/** DNSSEC Lookaside Validation @rfc{4431} */
#define ZONE_DLV (32769u)
/** @} */

#define ZONE_BLOCK_SIZE (64)
#define ZONE_WINDOW_SIZE (256 * ZONE_BLOCK_SIZE) // 16KB

// tape capacity must be large enough to hold every token from a single
// worst-case read (e.g. 64 consecutive line feeds). in practice a single
// block will never contain 64 tokens, therefore, to optimize throughput,
// allocate twice the size so consecutive index operations can be done
#define ZONE_TAPE_SIZE ((100 * ZONE_BLOCK_SIZE) + ZONE_BLOCK_SIZE)

#define ZONE_RDATA_SIZE (65535)

#define ZONE_NAME_SIZE (255)
#define ZONE_PADDING_SIZE (ZONE_BLOCK_SIZE)

typedef struct zone_name_buffer zone_name_buffer_t;
struct zone_name_buffer {
  size_t length; /**< Length of domain name stored in buffer */
  uint8_t octets[ ZONE_NAME_SIZE + ZONE_PADDING_SIZE ];
};

// FIXME: explain need for NSEC padding
typedef struct zone_rdata_buffer zone_rdata_buffer_t;
struct zone_rdata_buffer {
  uint8_t octets[ ZONE_RDATA_SIZE + 4096 /* NSEC padding */ ];
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
  zone_name_buffer_t origin, owner;
  uint16_t last_type;
  uint32_t last_ttl, default_ttl;
  uint16_t last_class;
  // non-terminating line feeds, i.e. escaped line feeds, line feeds in quoted
  // sections or within parentheses, are counted, but deferred for consistency
  // in error reports
  size_t span; /**< number of lines spanned by record */
  size_t line; /**< starting line of record */
  char *name; /**< filename in control directive */
  char *path; /**< absolute path */
  FILE *handle;
  bool grouped;
  bool start_of_line;
  uint8_t end_of_file;
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
  // vector(s) of tokens generated by the indexer. guaranteed to be large
  // enough to hold every token for a single read + terminators
  struct { const char **head, **tail, *tape[ZONE_TAPE_SIZE + 2]; } fields;
  struct { const char **head, **tail, *tape[ZONE_TAPE_SIZE + 1]; } delimiters;
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
  uint32_t, // category
  const char *, // message
  void *); // user data

typedef struct zone_name zone_name_t;
struct zone_name {
  uint8_t length;
  const uint8_t *octets;
};

// invoked for each resource record (host order). header (owner, type, class and ttl)
// fields are passed individually for convenience. rdata fields can be visited
// individually by means of the iterator
typedef int32_t(*zone_accept_t)(
  zone_parser_t *,
  const zone_name_t *, // owner (length + octets)
  uint16_t, // type
  uint16_t, // class
  uint32_t, // ttl
  uint16_t, // rdlength
  const uint8_t *, // rdata
  void *); // user data

typedef struct {
  /** Non-strict mode of operation. */
  /** Authoritative servers may choose to be more lenient when operating as
      a secondary as data may have been transferred over AXFR/IXFR that
      would have triggered an error otherwise. */
  bool non_strict;
  /** Disable $INCLUDE directive. */
  /** Useful in setups where untrusted input may be offered. */
  bool no_includes;
  /** Maximum $INCLUDE depth. 0 for default. */
  uint32_t include_limit;
  /** Enable 1h2m3s notations for TTLS. */
  bool pretty_ttls;
  /** Origin in wire format. */
  zone_name_t origin;
  uint32_t default_ttl;
  uint16_t default_class;
  struct {
    /** Priorities NOT to write out. */
    uint32_t mask;
    /** Callback invoked to write out log messages. */
    zone_log_t callback;
  } log;
  struct {
    /** Callback invoked for each RR. */
    zone_accept_t callback;
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
typedef struct zone_buffers zone_buffers_t;
struct zone_buffers {
  size_t size; /**< Number of name and rdata buffers available */
  zone_name_buffer_t *owner;
  zone_rdata_buffer_t *rdata;
};

struct zone_parser {
  zone_options_t options;
  void *user_data;
  struct {
    size_t size;
    struct {
      size_t active;
      zone_name_buffer_t *blocks;
    } owner;
    struct {
      size_t active;
      zone_rdata_buffer_t *blocks;
    } rdata;
  } buffers;
  zone_name_buffer_t *owner;
  zone_rdata_buffer_t *rdata;
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
#define ZONE_SYNTAX_ERROR (-256)  // (-1 << 8)
/** Semantic error */
#define ZONE_SEMANTIC_ERROR (-512)  // (-2 << 8)
/** Operation failed due to lack of memory */
#define ZONE_OUT_OF_MEMORY (-768)  // (-3 << 8)
/** Bad parameter value */
#define ZONE_BAD_PARAMETER (-1024)  // (-4 << 8)
/** Error reading zone file */
#define ZONE_READ_ERROR (-1280)  // (-5 << 8)
/** Control directive or support for record type is not implemented */
#define ZONE_NOT_IMPLEMENTED (-1536)  // (-6 << 8)
/** Specified file does not exist */
#define ZONE_NOT_A_FILE (-1792)  // (-7 << 8)
/** Access to specified file is not allowed */
#define ZONE_NOT_PERMITTED (-2048)  // (-8 << 8)
/** @} */

/**
 * @brief Parse zone file
 */
ZONE_EXPORT int32_t
zone_parse(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *path,
  void *user_data)
zone_nonnull((1,2,3,4));

/**
 * @brief Parse zone from string
 */
ZONE_EXPORT int32_t
zone_parse_string(
  zone_parser_t *parser,
  const zone_options_t *options,
  zone_buffers_t *buffers,
  const char *string,
  size_t length,
  void *user_data)
zone_nonnull((1,2,3,4));

/**
 * @brief Write error message to active log handler.
 *
 * The zone parser operates on a per-record base and therefore cannot detect
 * errors that span records. e.g. SOA records being specified more than once.
 * The user may print a message using the active log handler, keeping the
 * error message format consistent.
 *
 * @param[in]  parser    Zone parser
 * @param[in]  priority  Log priority
 * @param[in]  format    Format string compatible with printf
 * @param[in]  ...       Variadic arguments corresponding to #format
 */
ZONE_EXPORT void zone_log(
  zone_parser_t *parser,
  uint32_t priority,
  const char *format,
  ...)
zone_nonnull((1,3))
zone_format_printf(3,4);

/**
 * @brief Write error message to active log handler.
 *
 * @param[in]  parser     Zone parser
 * @param[in]  priority   Log priority
 * @param[in]  format     Format string compatible with printf
 * @param[in]  arguments  Argument list
 */
ZONE_EXPORT void zone_vlog(
  zone_parser_t *parser,
  uint32_t priority,
  const char *format,
  va_list arguments)
zone_nonnull((1,3));

ZONE_EXPORT inline void
zone_nonnull((1,2))
zone_format_printf(2,3)
zone_error(zone_parser_t *parser, const char *format, ...)
{
  if (!(ZONE_ERROR & ~parser->options.log.mask))
    return;
  va_list arguments;
  va_start(arguments, format);
  zone_vlog(parser, ZONE_ERROR, format, arguments);
  va_end(arguments);
}

ZONE_EXPORT inline void
zone_nonnull((1,2))
zone_format_printf(2,3)
zone_warning(zone_parser_t *parser, const char *format, ...)
{
  if (!(ZONE_WARNING & ~parser->options.log.mask))
    return;
  va_list arguments;
  va_start(arguments, format);
  zone_vlog(parser, ZONE_WARNING, format, arguments);
  va_end(arguments);
}

ZONE_EXPORT inline void
zone_nonnull((1,2))
zone_format_printf(2,3)
zone_info(zone_parser_t *parser, const char *format, ...)
{
  if (!(ZONE_INFO & ~parser->options.log.mask))
    return;
  va_list arguments;
  va_start(arguments, format);
  zone_vlog(parser, ZONE_INFO, format, arguments);
  va_end(arguments);
}


#if defined(__cplusplus)
}
#endif

#endif // ZONE_H
