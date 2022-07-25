/*
 * zone.h -- zone parser.
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "scanner.h"
#include "util.h"

static const char string[] = "<string>";

extern inline zone_type_t zone_type(const zone_code_t code);
extern inline zone_item_t zone_item(const zone_code_t code);

zone_return_t zone_open_string(
  zone_parser_t *par, const zone_options_t *opts, const char *str, size_t len)
{
  zone_file_t *file;

  if (!str)
    return ZONE_BAD_PARAMETER;

  // custom allocator must be fully specified or not at all
  int alloc = (opts->allocator.malloc != 0) +
              (opts->allocator.realloc != 0) +
              (opts->allocator.free != 0) +
              (opts->allocator.arena != NULL);
  if (alloc != 0 && alloc != 4)
    return ZONE_BAD_PARAMETER;
  //
  if (!opts->accept.rr)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.rdata)
    return ZONE_BAD_PARAMETER;
  if (!opts->accept.delimiter)
    return ZONE_BAD_PARAMETER;

  if (!(file = calloc(1, sizeof(*file))))
    return ZONE_OUT_OF_MEMORY;
  file->name = string;
  file->path = string;
  file->handle = NULL; // valid for fixed buffer
  file->buffer.used = len;
  file->buffer.size = len;
  file->buffer.data.read = str;
  file->position.line = 1;
  file->position.column = 1;
  memset(par, 0, sizeof(*par));
  par->scanner.state = ZONE_INITIAL;
  par->parser.state = ZONE_INITIAL;
  par->file = file;
  par->options = *opts;
  return 0;
}

void zone_close(zone_parser_t *par)
{
  if (par) {
    if (par->file) {
      if (par->file->handle)
        fclose(par->file->handle);
      free(par->file);
    }
  }
  // FIXME: implement
  // x. close the whole thing.
  // x. cleanup buffers
  // x. etc, etc, etc
  return;
}

#define MAP(name, id) { name, sizeof(name) - 1, id }

static int mapcmp(const void *p1, const void *p2)
{
  const zone_map_t *m1 = p1, *m2 = p2;
  assert(m1 && m1->name && m1->length);
  assert(m2 && m2->name && m2->length);
  return zone_strcasecmp(m1->name, m1->length, m2->name, m2->length);
}

// Taken from RFC 2535, section 7.
static const zone_map_t algorithms[] = {
  MAP("RSAMD5", 1), // RFC 2537
  MAP("DH", 2), // RFC 2539
  MAP("DSA", 3), // RFC 2536
  MAP("ECC", 4),
  MAP("RSASHA1", 5), // RFC 3110
  MAP("DSA-NSEC3-SHA1", 6), // RFC 5155
  MAP("RSASHA1-NSEC3-SHA1", 7), // RFC 5155
  MAP("RSASHA256", 8), // RFC 5702
  MAP("RSASHA512", 10), // RFC 5702
  MAP("ECC-GOST", 12), // RFC 5933
  MAP("ECDSAP256SHA256", 13), // RFC 6605
  MAP("ECDSAP384SHA384", 14), // RFC 6605
  MAP("ED25519", 15), // RFC 8080
  MAP("ED448", 16), // RFC 8080
  MAP("INDIRECT", 252),
  MAP("PRIVATEDNS", 253),
  MAP("PRIVATEOID", 254),
};

// Taken from RFC 4398, section 2.1.
static const zone_map_t certificates[] = {
  MAP("ACPKIX", 7), // Attribute Certificate
  MAP("IACPKIX", 8), // The URL of an Attribute Certificate
  MAP("IPGP", 6), // The fingerprint and URL of an OpenPGP packet
  MAP("IPKIX", 4), // The URL of an X.509 data object
  MAP("ISPKI", 5), // The URL of an SPKI certificate
  MAP("OID", 254), // OID private
  MAP("PGP", 3), // OpenPGP packet
  MAP("PKIX", 1), // X.509 as per PKIX
  MAP("SPKI", 2), // SPKI cert
  MAP("URI", 253), // URI private
// 0 Reserved
// 255 Reserved
// 256-65279 Available for IANA assignment
// 65280-65534 Experimental
// 65535 Reserved
};

#undef MAP

int32_t zone_is_algorithm(const char *str, size_t len, uint32_t flags)
{
  char buf[32];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  const zone_map_t *map, key = { str, len, 0 };
  static const size_t size = sizeof(algorithms[0]);
  static const size_t nmemb = sizeof(algorithms)/size;

  if ((map = bsearch(&key, algorithms, nmemb, size, mapcmp)))
    return (int32_t)map->id;
  return 0;
}

int32_t zone_is_certificate(const char *str, size_t len, uint32_t flags)
{
  char buf[32];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  const zone_map_t *map, key = { str, len, 0 };
  static const size_t size = sizeof(certificates[0]);
  static const size_t nmemb = sizeof(certificates)/size;

  if ((map = bsearch(&key, certificates, nmemb, size, mapcmp)))
    return (int32_t)map->id;
  return 0;
}

int32_t zone_is_class(const char *str, size_t len, uint32_t flags)
{
  char buf[32];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  if (len < 2)
    return 0;
  if (strncasecmp(str, "IN", 2) == 0)
    return 1;
  if (strncasecmp(str, "CH", 2) == 0)
    return 2;
  if (strncasecmp(str, "CS", 2) == 0)
    return 3;
  if (strncasecmp(str, "HS", 2) == 0)
    return 4;

  // support unknown DNS class (rfc 3597)
  if (len <= 5 || strncasecmp(str, "CLASS", 5) != 0)
    return 0;

  int32_t class = 0;
  for (size_t i = 5; i < len; i++) {
    if (str[i] < '0' || str[i] > '9')
      return 0;
    class *= 10;
    class += (uint32_t)(str[i] - '0');
    if (class >= UINT16_MAX)
      return 0;
  }

  return class;
}

#include "types.h"

int32_t zone_is_type(const char *str, size_t len, uint32_t flags)
{
  char buf[64];

  if (flags & ZONE_ESCAPED) {
    ssize_t cnt;

    cnt = zone_unescape(str, len, buf, sizeof(buf), flags & ZONE_STRICT);
    if (cnt < 0)
      return -1;
    str = buf;
    len = (size_t)cnt > sizeof(buf) ? sizeof(buf) : (size_t)cnt;
  }

  const zone_map_t *map, key = { str, len, 0 };
  static const size_t size = sizeof(types[0]);
  static const size_t nmemb = sizeof(types)/size;

  if ((map = bsearch(&key, types, nmemb, size, mapcmp)))
    return (int32_t)map->id;
  if (!(flags & ZONE_GENERIC))
    return 0;

  // support unknown DNS record types (rfc 3597)
  if (len <= 4 || strncasecmp(str, "TYPE", 4) != 0)
    return 0;

  int32_t type = 0;
  for (size_t i = 4; i < len; i++) {
    if (str[i] < '0' || str[i] > '9')
      return 0;
    type *= 10;
    type += (uint32_t)(str[i] - '0');
    if (type > UINT16_MAX)
      return 0;
  }

  return type;
}
