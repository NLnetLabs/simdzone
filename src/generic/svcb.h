/*
 * svcb.h -- svcb parser
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef SVCB_H
#define SVCB_H

typedef struct svc_param_info svc_param_info_t;
struct svc_param_info;

// FIXME: move, to be used by all parse functions
typedef struct rdata rdata_t;
struct rdata {
  uint8_t *octets;
  uint8_t *limit;
};

typedef int32_t (*svc_param_parse_t)(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *svc_param_info,
  rdata_t *rdata,
  const token_t *);

struct svc_param_info {
  zone_symbol_t name;
  bool value;
  svc_param_parse_t parse, parse_strict;
};

// RFC9460 section 7.1:
//   The "alpn" and "no-default-alpn" SvcParamKeys together indicate the set
//   of Application-Layer Protocol Negotiation (ALPN) protocol identifiers
//   [ALPN] and associated transport protocols supported by this service
//   endpoint (the "SVCB ALPN set").
//
// RFC9460 section 7.1.1:
//   ALPNs are identified by their registered "Identification Sequence"
//   (alpn-id), which is a sequence of 1-255 octets. For "alpn", the
//   presentation value SHALL be a comma-separated list (Appendix A.1) of
//   one or more alpn-ids. Zone-file implementations MAY disallow the ","
//   and "\\" characters in ALPN IDs instead of implementing the value-list
//   escaping procedure, relying on the opaque key format (e.g., key=\002h2)
//   in the event that these characters are needed.
//
// Application-Layer Protocol Negotiation (ALPN) protocol identifiers are
// maintained by IANA:
// https://www.iana.org/assignments/tls-extensiontype-values#alpn-protocol-ids
//
// RFC9460 appendix A.1:
//   ... A value-list parser that splits on "," and prohibits items
//   containing "\"" is sufficient to comply with all requirements in
//   this document. ...
zone_nonnull_all
static int32_t parse_alpn(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  // FIXME: easily optimized by applying vectorization
  uint8_t *separator = rdata->octets;
  uint8_t *octet = rdata->octets + 1;
  uint8_t *limit = rdata->octets + 1 + token->length;
  if (limit > rdata->limit)
    SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));

  memcpy(octet, token->data, token->length);

  (void)field;
  (void)key;
  (void)param;

  for (; octet < limit; octet++) {
    // FIXME: SIMD and possibly SWAR can easily be used to improve
    if (*octet == '\\')
      SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));
    if (*octet != ',')
      continue;
    assert(separator < octet);
    const size_t length = ((uintptr_t)octet - (uintptr_t)separator) - 1;
    if (length == 0)
      SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));
    if (length > 255)
      SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));
    *separator = (uint8_t)length;
    separator = octet;
  }

  const size_t length = ((uintptr_t)octet - (uintptr_t)separator) - 1;
  if (length == 0)
    SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));
  if (length > 255)
    SYNTAX_ERROR(parser, "Invalid alpn in %s", TNAME(type));
  *separator = (uint8_t)length;

  rdata->octets = limit;
  return 0;
}

zone_nonnull_all
static int32_t parse_port(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *data = token->data;

  (void)field;
  (void)key;
  (void)param;

  if (!token->length || token->length > 5)
    SYNTAX_ERROR(parser, "Invalid port in %s", TNAME(type));

  uint64_t number = 0;
  for (;; data++) {
    const uint64_t digit = (uint8_t)*data - '0';
    if (digit > 9)
      break;
    number = number * 10 + digit;
  }

  uint16_t port = (uint16_t)number;
  port = htobe16(port);
  memcpy(rdata->octets, &port, 2);
  rdata->octets += 2;

  if (rdata->octets > rdata->limit)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  if (data != token->data + token->length || number > 65535)
    SYNTAX_ERROR(parser, "Invalid port in %s", TNAME(type));
  return 0;
}

zone_nonnull_all
static int32_t parse_ipv4hint(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *t = token->data, *te = token->data + token->length;
  size_t n = 0;

  (void)field;
  (void)key;
  (void)param;

  if (scan_ip4(t, rdata->octets, &n) == -1)
    SYNTAX_ERROR(parser, "Invalid ipv4hint in %s", TNAME(type));
  rdata->octets += 4;
  t += n;

  while (*t == ',') {
    if (rdata->octets > rdata->limit)
      SYNTAX_ERROR(parser, "Invalid ipv4hint in %s", TNAME(type));
    if (scan_ip4(t + 1, rdata->octets, &n) == -1)
      SYNTAX_ERROR(parser, "Invalid ipv4hint in %s", TNAME(type));
    rdata->octets += 4;
    t += n + 1;
  }

  if (t != te || rdata->octets > rdata->limit)
    SYNTAX_ERROR(parser, "Invalid ipv4hint in %s", TNAME(type));
  return 0;
}

zone_nonnull_all
static int32_t parse_ech(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  size_t size = (uintptr_t)rdata->limit - (uintptr_t)rdata->octets;
  size_t length;

  (void)field;
  (void)key;
  (void)param;

  if (token->length / 4 > size / 3)
    SYNTAX_ERROR(parser, "maximum size exceeded");

  struct base64_state state = { 0 };
  if (!base64_stream_decode(
    &state, token->data, token->length, rdata->octets, &length))
    SYNTAX_ERROR(parser, "Invalid ech in %s", TNAME(type));

  rdata->octets += length;
  if (state.bytes)
    SYNTAX_ERROR(parser, "Invalid ech in %s", TNAME(type));

  return 0;
}

zone_nonnull_all
static int32_t parse_ipv6hint(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *t = token->data, *te = token->data + token->length;
  size_t n = 0;

  (void)field;
  (void)key;
  (void)param;

  if (scan_ip6(t, rdata->octets, &n) == -1)
    SYNTAX_ERROR(parser, "Invalid ipv6hint in %s", TNAME(type));
  rdata->octets += 16;
  t += n;

  while (*t == ',') {
    if (rdata->octets >= rdata->limit)
      SYNTAX_ERROR(parser, "Invalid ipv6hint in %s", TNAME(type));
    if (scan_ip6(t + 1, rdata->octets, &n) == -1)
      SYNTAX_ERROR(parser, "Invalid ipv6hint in %s", TNAME(type));
    rdata->octets += 16;
    t += n + 1;
  }

  if (t != te || rdata->octets > rdata->limit)
    SYNTAX_ERROR(parser, "Invalid ipv6hint in %s", TNAME(type));
  return 0;
}

// RFC9461 section 5:
//   "dohpath" is a single-valued SvcParamKey whose value (in both
//   presentation format and wire format) MUST be a URI Template in
//   relative form ([RFC6570], Section 1.1) encoded in UTF-8 [RFC3629].
zone_nonnull_all
static int32_t parse_dohpath_strict(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *t = token->data, *te = t + token->length;

  (void)field;
  (void)key;
  (void)param;

  // FIXME: easily optimized using SIMD (and possibly SWAR)
  while ((t < te) & (rdata->octets < rdata->limit)) {
    *rdata->octets = (uint8_t)*t;
    if (*t == '\\') {
      uint32_t o;
      if (!(o = unescape(t, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid dohpath in %s", TNAME(type));
      rdata->octets += 1; t += o;
    } else {
      rdata->octets += 1; t += 1;
    }
  }

  // RFC9461 section 5:
  //   The URI Template MUST contain a "dns" variable, and MUST be chosen such
  //   that the result after DoH URI Template expansion (RFC8484 section 6)
  //   is always a valid and function ":path" value (RFC9113 section 8.3.1)
  // FIXME: implement

  if (t != te || rdata->octets >= rdata->limit)
    SYNTAX_ERROR(parser, "Invalid dohpath in %s", TNAME(type));
  return 0;
}

zone_nonnull_all
static int32_t parse_dohpath(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *t = token->data, *te = t + token->length;

  (void)field;
  (void)key;
  (void)param;

  // FIXME: easily optimized using SIMD (and possibly SWAR)
  while ((t < te) & (rdata->octets < rdata->limit)) {
    *rdata->octets = (uint8_t)*t;
    if (*t == '\\') {
      uint32_t o;
      if (!(o = unescape(t, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid dohpath in %s", TNAME(type));
      rdata->octets += 1; t += o;
    } else {
      rdata->octets += 1; t += 1;
    }
  }

  if (t != te || rdata->octets >= rdata->limit)
    SYNTAX_ERROR(parser, "Invalid dohpath in %s", TNAME(type));
  return 0;
}

zone_nonnull_all
static zone_never_inline int32_t parse_unknown(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  const char *t = token->data, *te = t + token->length;

  (void)key;
  (void)param;

  while ((t < te) & (rdata->octets < rdata->limit)) {
    *rdata->octets = (uint8_t)*t;
    if (*t == '\\') {
      uint32_t o;
      if (!(o = unescape(t, rdata->octets)))
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      rdata->octets += 1; t += o;
    } else {
      rdata->octets += 1; t += 1;
    }
  }

  if (t != te || rdata->octets >= rdata->limit)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  return 0;
}

/**
 * @defgroup svc_params Service Parameter Keys
 *
 * [IANA registered service parameter keys](https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml)
 *
 * @{
 */
/** Parameters clients must not ignore @rfc{9460} */
#define SVC_PARAM_KEY_MANDATORY (0u)
/** Application Layer Protocol Negotiation (ALPN) protocol identifiers @rfc{9460} */
#define SVC_PARAM_KEY_ALPN (1u)
/** No support for default protocol (alpn must be specified) @rfc{9460} */
#define SVC_PARAM_KEY_NO_DEFAULT_ALPN (2u)
/** TCP or UDP port for alternative endpoint @rfc{9460} */
#define SVC_PARAM_KEY_PORT (3u)
/** IPv4 address hints @rfc{9460} */
#define SVC_PARAM_KEY_IPV4HINT (4u)
/** Encrypted ClientHello (ECH) configuration @draft{ietf, tls-svcb-ech} */
#define SVC_PARAM_KEY_ECH (5u)
/** IPv6 address hints @rfc{9460} */
#define SVC_PARAM_KEY_IPV6HINT (6u)
/** URI template in relative form @rfc{9461} */
#define SVC_PARAM_KEY_DOHPATH (7u)
/** Target is an Oblivious HTTP service @draft{ohai,svcb-config} */
#define SVC_PARAM_KEY_OHTTP (8u)
/** Reserved ("invalid key") @rfc{9460} */
#define SVC_PARAM_KEY_INVALID_KEY (65535u)
/** @} */

zone_nonnull_all
static int32_t parse_mandatory_strict(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *svc_param,
  rdata_t *rdata,
  const token_t *token);

zone_nonnull_all
static int32_t parse_mandatory(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *svc_param,
  rdata_t *rdata,
  const token_t *token);

#define SVC_PARAM(name, key, value, parse, parse_sorted) \
  { { { name, sizeof(name) - 1 }, key }, value, parse, parse_sorted }

static const svc_param_info_t svc_params[] = {
  SVC_PARAM("mandatory", 0u, true, parse_mandatory, parse_mandatory_strict),
  SVC_PARAM("alpn", 1u, true, parse_alpn, parse_alpn),
  // RFC9460 section 7.1.1:
  //   For "no-default-alpn", the presentation and wire format values MUST be
  //   empty. When "no-default-alpn" is specified in an RR, "alpn" must also be
  //   specified in order for the RR to be "self-consistent" (Section 2.4.3).
  SVC_PARAM("no-default-alpn", 2u, false, 0, 0),
  SVC_PARAM("port", 3u, true, parse_port, parse_port),
  SVC_PARAM("ipv4hint", 4u, true, parse_ipv4hint, parse_ipv4hint),
  SVC_PARAM("ech", 5u, true, parse_ech, parse_ech),
  SVC_PARAM("ipv6hint", 6u, true, parse_ipv6hint, parse_ipv6hint),
  // RFC9461 section 5:
  //   If the "alpn" SvcParam indicates support for HTTP, "dohpath" MUST be
  //   present.
  SVC_PARAM("dohpath", 7u, true, parse_dohpath, parse_dohpath_strict),
  SVC_PARAM("ohttp", 8u, false, 0, 0),
};

static const svc_param_info_t unknown_svc_param =
  SVC_PARAM("unknown", 0u, true, parse_unknown, parse_unknown);

#undef SVC_PARAM

zone_nonnull_all
static zone_really_inline size_t scan_unknown_svc_param_key(
  const char *data, uint16_t *key, const svc_param_info_t **param)
{
  size_t length = 0;
  uint64_t number = 0;
  for (;; length++) {
    const uint64_t digit = (uint8_t)data[length] - '0';
    if (digit > 9)
      break;
    number = number * 10 + digit;
  }

  if (!length || length > 4)
    return 0;
  if (number < (sizeof(svc_params) / sizeof(svc_params[0])))
    return (void)(*param = &svc_params[(*key = (uint16_t)number)]), length;
  if (number < 65535)
    return (void)(*key = (uint16_t)number), (void)(*param = &unknown_svc_param), length + 3;
  return 0;
}

zone_nonnull_all
static zone_really_inline size_t scan_svc_param(
  const char *data, uint16_t *key, const svc_param_info_t **param)
{
  // draft-ietf-dnsop-svcb-https-12 section 2.1:
  // alpha-lc    = %x61-7A   ;  a-z
  // SvcParamKey = 1*63(alpha-lc / DIGIT / "-")
  //
  // FIXME: naive implementation
  if (memcmp(data, "mandatory", 9) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_MANDATORY)]), 9;
  else if (memcmp(data, "alpn", 4) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_ALPN)]), 4;
  else if (memcmp(data, "no-default-alpn", 15) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_NO_DEFAULT_ALPN)]), 15;
  else if (memcmp(data, "port", 4) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_PORT)]), 4;
  else if (memcmp(data, "ipv4hint", 8) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_IPV4HINT)]), 8;
  else if (memcmp(data, "ech", 3) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_ECH)]), 3;
  else if (memcmp(data, "ipv6hint", 8) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_IPV6HINT)]), 8;
  else if (memcmp(data, "dohpath", 7) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_DOHPATH)]), 7;
  else if (memcmp(data, "ohttp", 5) == 0)
    return (void)(*param = &svc_params[(*key = SVC_PARAM_KEY_OHTTP)]), 5;
  else if (memcmp(data, "key", 0) == 0)
    return scan_unknown_svc_param_key(data + 3, key, param);
  else
    return 0;
}

zone_nonnull_all
static zone_really_inline size_t scan_svc_param_key(
  const char *data, uint16_t *key)
{
  // FIXME: improve implementation
  const svc_param_info_t *param;
  return scan_svc_param(data, key, &param);
}

zone_nonnull_all
static zone_really_inline int32_t parse_mandatory_strict(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  (void)field;

  // RFC9460 section 8:
  //   The presentation value SHALL be a comma-seperatred list of one or more
  //   valid SvcParamKeys, ...
  int32_t highest_key = -1;
  const char *data = token->data;
  uint8_t *whence = rdata->octets;
  size_t skip;

  if (!(skip = scan_svc_param_key(data, &key)))
    SYNTAX_ERROR(parser, "Invalid %s in %s", TNAME(param), TNAME(type));

  highest_key = key;
  key = htobe16(key);
  memcpy(rdata->octets, &key, sizeof(key));
  rdata->octets += sizeof(key);
  data += skip;

  while (*data == ',' && rdata->octets < rdata->limit) {
    if (!(skip = scan_svc_param_key(data + 1, &key)))
      SYNTAX_ERROR(parser, "Invalid mandatory of %s", TNAME(type));
    data += skip + 1;
    if (key > highest_key) {
      highest_key = key;
      key = htobe16(key);
      memcpy(rdata->octets, &key, 2);
      rdata->octets += 2;
    } else {
      // RFC9460 section 8:
      //   In wire format, the keys are represented by their numeric values in
      //   network byte order, concatenated in ascending order.
      uint8_t *octets = whence;
      uint16_t smaller_key = 0;
      while (octets < rdata->octets) {
        memcpy(&smaller_key, octets, sizeof(smaller_key));
        smaller_key = be16toh(smaller_key);
        if (key < smaller_key)
          break;
        octets += 2;
      }
      assert(octets < rdata->octets);
      // RFC9460 section 8:
      //   Keys MAY appear in any order, but MUST NOT appear more than once.
      if (key == smaller_key)
        SYNTAX_ERROR(parser, "Duplicate key in mandatory of %s", TNAME(type));
      assert(key < smaller_key);
      uint16_t length = (uint16_t)(rdata->octets - octets);
      memmove(octets + 2, octets, length);
      key = htobe16(key);
      memcpy(octets, &key, 2);
      rdata->octets += 2;
    }
  }

  if (rdata->octets >= rdata->limit)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  if (data != token->data + token->length)
    SYNTAX_ERROR(parser, "...");
  return 0;
}

zone_nonnull_all
static zone_really_inline int32_t parse_mandatory(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  uint16_t key,
  const svc_param_info_t *param,
  rdata_t *rdata,
  const token_t *token)
{
  size_t skip;
  const char *data = token->data;

  (void)field;

  if (!(skip = scan_svc_param_key(data, &key)))
    SYNTAX_ERROR(parser, "Invalid key in %s of %s", TNAME(param), TNAME(type));
  memcpy(rdata->octets, &key, 2);
  rdata->octets += 2;
  data += skip;

  while (*data == ',' && rdata->octets < rdata->limit) {
    if (!(skip = scan_svc_param_key(data + 1, &key)))
      SYNTAX_ERROR(parser, "Invalid key in %s of %s", TNAME(param), TNAME(type));
    data += skip + 1;
    memcpy(rdata->octets, &key, 2);
    rdata->octets += 2;
  }

  if (rdata->octets >= rdata->limit - 2)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  if (data != token->data + token->length)
    SYNTAX_ERROR(parser, "Invalid %s", TNAME(type));
  return 0;
}

// https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
zone_nonnull_all
static zone_really_inline int32_t parse_svc_params_strict(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  // rdata_t rdata,
  token_t *token)
{
  const uint16_t zero = 0;
  int32_t code, highest_key = -1;
  uint8_t *whence = parser->rdata->octets + parser->rdata->length;
  rdata_t rdata = { parser->rdata->octets + parser->rdata->length,
                    parser->rdata->octets + ZONE_RDATA_SIZE };

  while (token->code == CONTIGUOUS) {
    size_t skip;
    uint16_t key;
    const svc_param_info_t *param;

    if (!(skip = scan_svc_param(token->data, &key, &param)))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    assert(param);

    if (key > highest_key) {
      highest_key = key;

      switch ((token->data[skip] == '=') + (param->value << 1)) {
        case 1: // void parameter with value
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
        case 0: // void parameter without value
        case 2: // parameter without optional value
          if (skip != token->length)
            SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
          key = htobe16(key);
          memcpy(rdata.octets, &key, sizeof(key));
          memcpy(rdata.octets+2, &zero, sizeof(zero));
          rdata.octets += 4;
          break;
        case 3: // parameter with value
          skip += 1;
          // quoted parameter, separate token
          if (token->data[skip] == '"')
            lex(parser, token);
          else
            (void)(token->data += skip), token->length -= skip;
          {
            uint8_t *octets = rdata.octets;
            rdata.octets += 4;
            code = param->parse_strict(
              parser, type, field, key, param, &rdata, token);
            if (code < 0)
              return code;
            uint16_t length = (uint16_t)(rdata.octets - octets) - 4;
            key = htobe16(key);
            length = htobe16(length);
            memcpy(octets, &key, sizeof(key));
            memcpy(octets+2, &length, sizeof(length));
          }
          break;
      }
    } else {
      uint8_t *octets = whence;
      uint16_t smaller_key = 65535;

      while (octets < rdata.octets) {
        memcpy(&smaller_key, octets, sizeof(smaller_key));
        smaller_key = be16toh(smaller_key);
        if (key <= smaller_key)
          break;
        uint16_t length;
        memcpy(&length, octets + 2, sizeof(length));
        length = be16toh(length);
        octets += length + 4;
      }

      assert(octets < rdata.octets);
      if (key == smaller_key)
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

      switch ((token->data[skip] == '=') + (param->value << 1)) {
        case 1: // void parameter with value
          SYNTAX_ERROR(parser, "foobar1");
        case 0: // void parameter without value
        case 2: // parameter without value
          key = htobe16(key);
          memmove(octets + 4, octets, (uintptr_t)rdata.octets - (uintptr_t)octets);
          memcpy(octets, &key, sizeof(key));
          memcpy(octets+2, &zero, sizeof(zero));
          rdata.octets += 4;
          break;
        case 3: // parameter with value
          skip += 1;
          // quoted parameter, separate token
          if (token->data[skip] == '"')
            lex(parser, token);
          else
            (void)(token->data += skip), token->length -= skip;
          {
            uint16_t length;
            rdata_t param_rdata;
            // RFC9460 section 2.2:
            //   SvcParamKeys SHALL appear in increasing numeric order.
            //
            // move existing data to end of the buffer and reset limit to
            // avoid allocating memory
            assert(rdata.octets - octets < ZONE_RDATA_SIZE);
            length = (uint16_t)(rdata.octets - octets);
            param_rdata.octets = octets + 4u;
            param_rdata.limit = parser->rdata->octets + (ZONE_RDATA_SIZE - length);
            // move data PADDING_SIZE past limit to ensure SIMD operatations
            // do not overwrite existing data
            memmove(param_rdata.limit + ZONE_PADDING_SIZE, octets, length);
            code = param->parse_strict(
              parser, type, field, key, param, &param_rdata, token);
            if (code)
              return code;
            assert(param_rdata.octets < param_rdata.limit);
            memmove(param_rdata.octets, param_rdata.limit + ZONE_PADDING_SIZE, length);
            rdata.octets = param_rdata.octets + length;
            length = (uint16_t)(param_rdata.octets - octets) - 4u;
            key = htobe16(key);
            length = htobe16(length);
            memcpy(octets, &key, sizeof(key));
            memcpy(octets+2, &length, sizeof(length));
          }
          break;
      }
    }

    lex(parser, token);
  }

  // FIXME: check all keys specified in mandatory are actually specified!!!!

  // FIXME: remove once all parsers use rdata_t
  parser->rdata->length = (uintptr_t)rdata.octets - (uintptr_t)parser->rdata->octets;

  return have_delimiter(parser, type, token);
}

zone_nonnull_all
static zone_really_inline int32_t parse_svc_params(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  // rdata_t *rdata,
  token_t *token)
{
  // propagate data as-is if secondary
  if (!parser->options.secondary)
    return parse_svc_params_strict(parser, type, field, token);

  int32_t code;
  const uint16_t zero = 0;
  rdata_t rdata = {
    parser->rdata->octets + parser->rdata->length,
    parser->rdata->octets + 65535 };

  while (token->code == CONTIGUOUS) {
    size_t skip;
    uint16_t key;
    const svc_param_info_t *param;

    if (!(skip = scan_svc_param(token->data, &key, &param)))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    assert(param);

    switch ((token->data[skip] == '=') + (param->value << 1)) {
      case 1: // void parameter with value
        SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
      case 0: // void parameter without value
      case 2: // parameter without value
        if (skip != token->length)
          SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
        key = htobe16(key);
        memcpy(rdata.octets, &key, sizeof(key));
        memcpy(rdata.octets+2, &zero, sizeof(zero));
        rdata.octets += 4;
        break;
      case 3: // parameter with value
        skip += 1;
        // quoted value, separate token
        if (token->data[skip] == '"')
          lex(parser, token);
        else
          (void)(token->data += skip), token->length -= skip;
        {
          uint8_t *octets = rdata.octets;
          rdata.octets += 4;
          code = param->parse(
            parser, type, field, key, param, &rdata, token);
          if (code)
            return code;
          uint16_t length = (uint16_t)(rdata.octets - octets) - 4;
          key = htobe16(key);
          length = htobe16(length);
          memcpy(octets, &key, sizeof(key));
          memcpy(octets+2, &length, sizeof(length));
        }
        break;
    }

    lex(parser, token);
  }

  // FIXME: remove once all parsers use rdata_t
  parser->rdata->length = (uintptr_t)rdata.octets - (uintptr_t)parser->rdata->octets;

  return have_delimiter(parser, type, token);
}

#endif // SVCB_H
