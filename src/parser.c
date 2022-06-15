/*
 * parser.c -- parser for (DNS) zone files
 *
 * Copyright (c) 2001-2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "scanner.h"
#include "memory.h"

static zone_return_t
parse_ttl(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr);

typedef zone_return_t(*rdata_parse_t)(
  zone_parser_t *, const zone_token_t *, zone_field_t *, void *);

struct rdata_descriptor {
  zone_format_t format;
  const char *name;
  uint32_t qualifiers;
  rdata_parse_t parse;
};

struct type_descriptor {
  uint16_t type;
  const char *name;
  uint32_t options;
  struct rdata_descriptor *rdata;
};

#define TYPES(...) \
  static const struct type_descriptor types[] = { __VA_ARGS__ };

#define TYPE(n, t, o, r) \
  { .type = t, .name = #n, .options = o, .rdata = r }

#define RDATA(...) \
  (struct rdata_descriptor[]){ __VA_ARGS__, { 0 }}

#define RDATA__(f, n, q, ...) \
  { .format = f, .name = #n, .qualifiers = q, __VA_ARGS__ }

#define INT8(n, q, ...) RDATA__(ZONE_INT8, n, q, __VA_ARGS__)
#define INT16(n, q, ...) RDATA__(ZONE_INT16, n, q, __VA_ARGS__)
#define INT32(n, q, ...) RDATA__(ZONE_INT32, n, q, __VA_ARGS__)
#define IP4(n, q, ...) RDATA__(ZONE_IP4, n, q, __VA_ARGS__)
#define IP6(n, q, ...) RDATA__(ZONE_IP6, n, q, __VA_ARGS__)
#define NAME(n, q, ...) RDATA__(ZONE_NAME, n, q, __VA_ARGS__)

#define PARSE(f) .parse = f

#define ANY (1<<0)
#define EXPERIMENTAL (1<<1)
#define OBSOLETE (1<<2)

#define MAILBOX (1<<0)
#define COMPRESSED (1<<1)

#include "types.h"

#undef NAME
#undef IP6
#undef IP4
#undef INT32
#undef INT16
#undef INT8
#undef RDATA__
#undef RDATA
#undef TYPE
#undef TYPES

static const struct type_descriptor unknown_type = { 0 };

static inline void *zone_malloc(zone_parser_t *par, size_t size)
{
  if (!par->options.allocator.malloc)
    return malloc(size);
  return par->options.allocator.malloc(par->options.allocator.arena, size);
}

static inline void *zone_realloc(zone_parser_t *par, void *ptr, size_t size)
{
  if (!par->options.allocator.realloc)
    return realloc(ptr, size);
  return par->options.allocator.realloc(par->options.allocator.arena, ptr, size);
}

static inline void zone_free(zone_parser_t *par, void *ptr)
{
  if (!par->options.allocator.free)
    free(ptr);
  else
    par->options.allocator.free(par->options.allocator.arena, ptr);
}

static inline uint64_t multiply(uint64_t lhs, uint64_t rhs, uint64_t max)
{
  return (max < lhs || (lhs && max / lhs < rhs)) ? max + 1 : lhs * rhs;
}

static inline uint64_t add(uint64_t lhs, uint64_t rhs, uint64_t max)
{
  return (max < lhs ||  max - lhs < rhs) ? max + 1 : lhs + rhs;
}

static inline uint32_t is_unit(char c)
{
  static const uint32_t s = 1u, m = 60u*s, h = 60u*m, d = 24u*h, w = 7u*d;

  switch (c) {
    case 's':
    case 'S':
      return s;
    case 'm':
    case 'M':
      return m;
    case 'h':
    case 'H':
      return h;
    case 'd':
    case 'D':
      return d;
    case 'w':
    case 'W':
      return w;
  }

  return 0;
}

zone_return_t
zone_parse_ttl(zone_parser_t *par, const zone_token_t *tok, uint32_t *ttl)
{
  uint64_t num = 0, sum = 0, fact = 0;
  enum { INITIAL, NUMBER, UNIT } state = INITIAL;

  const char *s = tok->string.data;
  const size_t n = tok->string.length;
  for (size_t i = 0; i < n; ) {
    uint8_t c;
    uint64_t u;

    // unescape
    if (s[i] != '\\') {
      c = s[i];
      i += 1;
    } else if ((i < n - 1) && (s[i+1] >= '0' && s[i+1] <= '2') &&
               (i < n - 2) && (s[i+2] >= '0' && s[i+2] <= '5') &&
               (i < n - 3) && (s[i+3] >= '0' && s[i+3] <= '5'))
    {
      c = (s[i+1]-'0') * 100 + (s[i+2]-'0') * 10 + (s[i+3]-'0');
      i += 4;
    } else if (i < n - 1) {
      c = s[i+1];
      i += 2;
    } else {
      assert(i == n - 1);
      c = s[i];
      i += 1;
    }

    switch (state) {
      case INITIAL:
        // ttls must start with a number
        if (c < '0' || c > '9')
          return 0;
        state = NUMBER;
        num = c - '0';
        break;
      case NUMBER:
        if (c >= '0' && c <= '9') {
          num = add(multiply(num, 10, INT32_MAX), c - '0', INT32_MAX);
        } else if ((u = is_unit(c))) {
          // units must not be repeated e.g. 1m1m
          if (fact == u)
            SYNTAX_ERROR(par, "Invalid ttl at {l}, reuse of unit %c", c);
          // greater units must precede smaller units. e.g. 1m1s, not 1s1m
          if (fact && fact < u)
            SYNTAX_ERROR(par, "Invalid ttl at {l}, unit %c follows smaller unit", c);
          num = multiply(num, (fact = u), INT32_MAX);
          state = UNIT;
        } else {
          SYNTAX_ERROR(par, "Invalid ttl at {l}, invalid unit %c", c);
        }
        break;
      case UNIT:
        // units must be followed by a number. e.g. 1h30m, not 1hh
        if (c < '0' || c > '9')
          SYNTAX_ERROR(par, "Invalid ttl at {l}, non-digit follows unit");
        // units must not be followed by a number if smallest unit,
        // i.e. seconds, was previously specified
        if (fact == 1)
          SYNTAX_ERROR(par, "Invalid ttl at {l}, seconds already specified");
        sum = add(sum, num, INT32_MAX);
        num = c - '0';
        state = NUMBER;
        break;
    }
  }

  sum = add(sum, num, (uint64_t)INT32_MAX);
  // FIXME: comment RFC2308 msb
  if (sum > (uint64_t)INT32_MAX)
    SEMANTIC_ERROR(par, "Invalid ttl at {l}, most significant bit set");
  *ttl = sum;
  return 0;
}

zone_return_t
zone_parse_name(zone_parser_t *par, const zone_token_t *tok, uint8_t name[255], size_t *len)
{
  size_t lab = 0, oct = 1;
  const char *s = tok->string.data;
  const size_t n = tok->string.length;

  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  // a freestanding "@" denotes the current origin
  if (tok->string.length == 1 && tok->string.data[0] == '@') {
    memcpy(name, par->file->origin.name.octets, par->file->origin.name.length);
    *len = par->file->origin.name.length;
    return 0;
  }

  for (size_t i=0; i < n; ) {
    if (oct >= 255)
      SYNTAX_ERROR(par, "Invalid domain at {l}, name length exceeds maximum");

    if (s[i] == '.' || i == n - 1) {
      if (oct - 1 == lab && lab > 0)
        SYNTAX_ERROR(par, "Invalid domain at {l}, empty label");
      else if ((oct - lab) - 1 > 63)
        SYNTAX_ERROR(par, "Invalid domain at {l}, label length exceeds maximum");
      name[lab] = (oct - lab) - 1;
      if (s[i] != '.')
        break;
      lab = oct++;
      name[lab] = 0;
      i += 1;
    } else if (s[i] == '\\') {
      // escape characters (rfc1035 5.1)
      if ((i < n - 1) && (s[i+1] >= '0' && s[i+1] <= '2') &&
          (i < n - 2) && (s[i+2] >= '0' && s[i+2] <= '5') &&
          (i < n - 3) && (s[i+3] >= '0' && s[i+3] <= '5'))
      {
        name[oct++] = (s[i+1]-'0') * 100 + (s[i+2]-'0') * 10 + (s[i+3]-'0');
        i += 4;
      } else if (i < n - 1) {
        name[oct++] = s[i+1];
        i += 2;
      } else {
        // FIXME: can be considered a syntax error, let's judge based on
        //        on a parser setting...
        i += 1;
      }
    } else {
      name[oct++] = s[i++];
    }
  }

  if (name[lab] != 0) {
    if (oct >= 255 - par->file->origin.name.length)
      SYNTAX_ERROR(par, "Invalid domain name at {l}, name length exceeds maximum");
    memcpy(&name[oct], par->file->origin.name.octets, par->file->origin.name.length);
    oct += par->file->origin.name.length;
  }

  *len = oct;
  return 0;
}

static zone_return_t
parse_ttl(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  uint32_t ttl;
  zone_return_t ret;

  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  (void)ptr;
  if ((ret = zone_parse_ttl(par, tok, &ttl)) < 0)
    return ret;
  assert(ttl <= INT32_MAX);
  fld->location = tok->location;
  fld->format = ZONE_INT16;
  fld->int32 = htonl(ttl);
  return ZONE_RDATA;
}

static zone_return_t
parse_int(
  zone_parser_t *par, const zone_token_t *tok, uint64_t max, uint64_t *num)
{
  char buf[32];
  ssize_t len;
  const char *str;
  uint64_t sum = 0u;

  assert(max < UINT64_MAX);
  if (tok->string.length == 0 || tok->string.length > sizeof(buf) * 4)
    SYNTAX_ERROR(par, "Invalid integer at {l}", tok);

  str = tok->string.data;
  len = (ssize_t)tok->string.length;
  if (tok->string.escaped) {
    if ((len = zone_unescape(str, (size_t)len, buf, sizeof(buf), 1)) < 0)
      SYNTAX_ERROR(par, "Invalid integer at {l}", tok);
  }

  if (len > (ssize_t)sizeof(buf))
    SYNTAX_ERROR(par, "Invalid integer at {l}", tok);

  for (ssize_t i = 0; i < len; i++) {
    if (str[i] < '0' || str[i] > '9')
      SYNTAX_ERROR(par, "Invalid integer at {l}, integer contains non-digit", tok);
    sum = add(multiply(sum, 10, max), str[i] - '0', max);
    if (sum > max)
      SYNTAX_ERROR(par, "Invalid integer at {l}, value exceeds maximum", tok);
  }

  *num = sum;
  return 0;
}

static zone_return_t
parse_int8(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  zone_return_t ret;
  uint64_t num;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if ((ret = parse_int(par, tok, UINT8_MAX, &num)) < 0)
    return ret;
  assert(num <= UINT8_MAX);
  fld->location = tok->location;
  fld->format = ZONE_INT8;
  fld->int8 = (uint8_t)num;
  return ZONE_RDATA;
}

static zone_return_t
parse_int16(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  zone_return_t ret;
  uint64_t num;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if ((ret = parse_int(par, tok, UINT16_MAX, &num)) < 0)
    return ret;
  assert(num <= UINT16_MAX);
  fld->location = tok->location;
  fld->format = ZONE_INT16;
  fld->int16 = htons((uint16_t)num);
  return ZONE_RDATA;
}

static zone_return_t parse_int32(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  zone_return_t ret;
  uint64_t num;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);
  if ((ret = parse_int(par, tok, UINT32_MAX, &num)) < 0)
    return ret;
  assert(num <= UINT32_MAX);
  fld->location = tok->location;
  fld->format = ZONE_INT32;
  fld->int32 = htonl((uint32_t)num);
  return ZONE_RDATA;
}

static zone_return_t parse_ip4(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in_addr *ip4 = NULL;
  char buf[INET_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    goto bad_ip;
  buf[len] = '\0';
  if (!(ip4 = zone_malloc(par, sizeof(*ip4))))
    return ZONE_OUT_OF_MEMORY;
  if (inet_pton(AF_INET, buf, ip4) != 1)
    goto bad_ip;
  fld->location = tok->location;
  fld->format = ZONE_IP4;
  fld->ip4 = ip4;
  return ZONE_RDATA;
bad_ip:
  if (ip4)
    zone_free(par, ip4);
  SYNTAX_ERROR(par, "Invalid IPv4 address at {l}", &tok);
}

static zone_return_t parse_ip6(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  struct in6_addr *ip6 = NULL;
  char buf[INET6_ADDRSTRLEN + 1];
  ssize_t len = -1;

  (void)ptr;
  assert((tok->code & 0xf00) == ZONE_STRING);
  if (tok->string.escaped)
    len = zone_unescape(tok->string.data, tok->string.length, buf, sizeof(buf), 0);
  else if (tok->string.length < sizeof(buf))
    memcpy(buf, tok->string.data, (len = tok->string.length));

  if (len < 0 || len >= (ssize_t)sizeof(buf))
    goto bad_ip;
  buf[len] = '\0';
  if (!(ip6 = zone_malloc(par, sizeof(*ip6))))
    return ZONE_OUT_OF_MEMORY;
  if (inet_pton(AF_INET6, buf, &ip6) != 1)
    goto bad_ip;
  fld->location = tok->location;
  fld->format = ZONE_IP6;
  fld->ip6 = ip6;
  return ZONE_RDATA;
bad_ip:
  if (ip6)
    zone_free(par, ip6);
  SYNTAX_ERROR(par, "Invalid IPv6 address at {l}", &tok);
}

static zone_return_t parse_name(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  size_t len;
  uint8_t name[255];
  zone_return_t ret;

  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  if ((ret = zone_parse_name(par, tok, name, &len)) < 0)
    return ret;
  assert(len <= 255);

  fld->location = tok->location;
  fld->format = ZONE_NAME;
  fld->name.length = (uint8_t)len;
  fld->name.octets = name;

  if (par->options.accept.name) {
    const void *ref;

    if (!(ref = par->options.accept.name(par, fld, ptr)))
      return ZONE_OUT_OF_MEMORY;
    fld->format = ZONE_DOMAIN;
    fld->domain = ref;
  } else {
    if (!(fld->name.octets = zone_malloc(par, (size_t)len)))
      return ZONE_OUT_OF_MEMORY;
    memcpy(fld->name.octets, name, (size_t)len);
  }

  return ZONE_RDATA;
}

#define OWNER (0)
#define TTL (1)
#define CLASS (2)
#define TYPE (3)

static zone_return_t
parse_owner(zone_parser_t *par, const zone_token_t *tok, void *ptr)
{
  (void)ptr;
  assert((tok->code & ZONE_STRING) == ZONE_STRING);

  // a freestanding "@" denotes the current origin
  if (tok->string.length == 1 && tok->string.data[0] == '@') {
    assert(!par->options.accept.name || par->file->origin.domain);
    // reuse persistent reference if available
    if (par->options.accept.name)
      par->record.fields[OWNER] = (zone_field_t){
        .location = tok->location,
        .format = ZONE_DOMAIN,
        .domain = par->file->origin.domain };
    else
      par->record.fields[OWNER] = (zone_field_t){
        .location = tok->location,
        .format = ZONE_NAME,
        .name = {
          .length = par->file->origin.name.length,
          .octets = par->file->origin.name.octets }};
  } else {
    // invalidate persistent reference
    par->file->owner.domain = NULL;
    if (zone_parse_name(
          par, tok, par->file->owner.name.octets, &par->file->owner.name.length))
      return ZONE_SYNTAX_ERROR;

    par->record.fields[OWNER] = (zone_field_t){
      .location = tok->location,
      .format = ZONE_NAME,
      .name = {
        .length = par->file->owner.name.length,
        .octets = par->file->owner.name.octets }};
  }

  return ZONE_OWNER;
}

static inline zone_return_t
accept_rr(zone_parser_t *par, void *ptr)
{
  // allocate memory to hold the owner last-minute (if no persistent reference
  // is available) to simplify memory management
  zone_field_t owner = par->record.fields[OWNER];
  assert(owner.format == ZONE_DOMAIN || owner.format == ZONE_NAME);
  if (owner.format != ZONE_DOMAIN) {
    assert(owner.name.length == par->file->owner.name.length);
    assert(owner.name.octets == par->file->owner.name.octets);

    if (par->options.accept.name) {
      const void *ref;

      if (!(ref = par->options.accept.name(par, &owner, ptr)))
        return ZONE_OUT_OF_MEMORY;
      owner.format = ZONE_DOMAIN;
      owner.domain = ref;
    } else {
      if (!(owner.name.octets = zone_malloc(par, owner.name.length)))
        return ZONE_OUT_OF_MEMORY;
      memcpy(owner.name.octets, par->file->owner.name.octets, owner.name.length);
    }
  }

  assert(par->options.accept.rr);

  zone_return_t ret = par->options.accept.rr(
    par,
   &owner,
   &par->record.fields[TTL],
   &par->record.fields[CLASS],
   &par->record.fields[TYPE],
    ptr);

  return ret < 0 ? ret : 0;
}

zone_return_t zone_parse(zone_parser_t *par, void *user_data)
{
  zone_token_t tok;
  zone_return_t code;

  // default parse function per format
  rdata_parse_t funcs[] = {
    0, // FIXME: should probably store the unknown rdata callback here?!?!
    0, // domain, reference returned by accept_name, never parsed
    parse_int8,
    parse_int16,
    parse_int32,
    parse_ip4,
    parse_ip6,
    parse_name
  };


  do {
    code = zone_scan(par, &tok);
    // propagate errors
    if (code < 0)
      break;
    assert(code == tok.code);
    // ignore comments
    if (code == ZONE_COMMENT)
      continue;

    if (code & ZONE_OWNER) {
      assert((code & ZONE_STRING) == ZONE_STRING);
      code = parse_owner(par, &tok, user_data);
    } else if (code & ZONE_TTL) {
      assert((code & ZONE_INT32) == ZONE_INT32);
      par->record.fields[TTL].location = tok.location;
      par->record.fields[TTL].format = ZONE_INT32;
      par->record.fields[TTL].int16 = tok.int32;
    } else if (code & ZONE_CLASS) {
      assert((code & ZONE_INT16) == ZONE_INT16);
      par->record.fields[CLASS].location = tok.location;
      par->record.fields[CLASS].format = ZONE_INT16;
      par->record.fields[CLASS].int16 = tok.int16;
    } else if (code & ZONE_TYPE) {
      zone_return_t ret;

      assert((code & ZONE_INT16) == ZONE_INT16);
      par->record.fields[TYPE].location = tok.location;
      par->record.fields[TYPE].format = ZONE_INT16;
      par->record.fields[TYPE].int16 = tok.int16;
      if (tok.int16 < (sizeof(types)/sizeof(types[0])))
        par->record.descriptor.type = &types[tok.int16];
      else // support unknown record types as per rfc3597
        par->record.descriptor.type = &unknown_type;

      if ((ret = accept_rr(par, user_data)) < 0)
        code = ret;
    } else if (code == '\0' || code == '\n') {
      zone_return_t ret;
      zone_field_t fld = {
        .location = tok.location,
        .format = ZONE_INT8,
        .int8 = (uint8_t)code };

      // FIXME: should be a no-op for blank line
      if (!par->record.descriptor.type)
        SEMANTIC_ERROR(par, "Expected type at {l}", &tok);
      else if (!par->record.descriptor.rdata)
        SEMANTIC_ERROR(par, "Expected rdata at {l}", &tok);

      if ((ret = par->options.accept.terminator(par, &fld, user_data)) < 0)
        code = ret;
      par->record.descriptor.type = NULL;
      par->record.descriptor.rdata = NULL;
      //if (tok.code == '\0' && par->file->handle)
      //  close_file(par);
      //
      // FIXME: we must reset the location here so that the location is correct
      //        even if the owner is left blank in the next record!
      //
    } else {
      zone_field_t fld;
      zone_return_t ret;
      rdata_parse_t func;

      assert((code & ZONE_RDATA) == ZONE_RDATA ||
             (code & ZONE_SVCB_RDATA) == ZONE_SVCB_RDATA);
      assert((code & ZONE_STRING) == ZONE_STRING ||
             (code & ZONE_SVC_PARAM) == ZONE_SVC_PARAM);
      assert(par->record.descriptor.type);
      const struct type_descriptor *type = par->record.descriptor.type;
      assert(par->record.descriptor.rdata || type->rdata);
      const struct rdata_descriptor *rdata;

      if (!par->record.descriptor.rdata)
        rdata = par->record.descriptor.rdata = &type->rdata[0];
      else if (rdata->format == 0) // eventually we should check here for optional fields etc
        SYNTAX_ERROR(par, "Invalid record got too much rdatas");
      else
        rdata = par->record.descriptor.rdata, par->record.descriptor.rdata = rdata + 1;

      assert((rdata->format & 0xf00) >> 8 < sizeof(funcs)/sizeof(funcs[0]));
      if (rdata->parse)
        func = rdata->parse;
      else
        func = funcs[(rdata->format & 0xf00) >> 8];

      if ((ret = func(par, &tok, &fld, user_data)) < 0)
        code = ret;
      else if ((ret = par->options.accept.rdata(par, &fld, user_data)) < 0)
        code = ret;
    }
  } while (code > 0);

  // FIXME: cleanup on error, etc

  return code < 0 ? code : 0;
}
