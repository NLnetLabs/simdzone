/*
 * type.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TYPE_H
#define TYPE_H

#include <string.h>
#if _WIN32
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#else
#include <strings.h>
#endif

static const uint8_t type_code_page[256] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x00 - 0x07
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x08 - 0x0f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x10 - 0x17
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x18 - 0x1f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x20 - 0x27
  // hyphen
  0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00,  // 0x28 - 0x2f
  // digits
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  // 0x30 - 0x37
  0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x38 - 0x3f
  // letters (upper case)
  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  // 0x40 - 0x47
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,  // 0x48 - 0x4f
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  // 0x50 - 0x57
  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x58 - 0x5f
  // letters (lower case)
  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  // 0x60 - 0x67
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,  // 0x68 - 0x6f
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  // 0x70 - 0x77
  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x78 - 0x7f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x80 - 0x87
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x88 - 0x8f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x90 - 0x97
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x98 - 0x9f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xa0 - 0xa7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xa8 - 0xaf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xb0 - 0xb7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xb8 - 0xbf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xc0 - 0xc7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xc8 - 0xcf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xd0 - 0xd7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xd8 - 0xdf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xe0 - 0xe7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xe8 - 0xef
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xf0 - 0xf7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0xf8 - 0xff
};

zone_nonnull_all
static zone_really_inline int32_t maybe_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol,
  uint16_t key)
{
  (void)parser;
  (void)type;
  (void)field;

  const zone_symbol_t *s = &types[key].info.name;

  if (strncasecmp(token->data, s->key.data, s->key.length) != 0 ||
      contiguous[ (uint8_t)token->data[ s->key.length ] ] == CONTIGUOUS)
    return 0;

  *symbol = s;
  *code = (uint16_t)s->value;
  return ZONE_TYPE;
}

zone_nonnull_all
static zone_really_inline int32_t maybe_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol,
  uint16_t key)
{
  (void)parser;
  (void)type;
  (void)field;

  const zone_symbol_t *s = &classes[key].name;
  if (strncasecmp(token->data, s->key.data, s->key.length) != 0 ||
      contiguous[ (uint8_t)token->data[ s->key.length ] ] == CONTIGUOUS)
    return 0;

  *symbol = s;
  *code = (uint16_t)s->value;
  return ZONE_CLASS;
}

zone_nonnull_all
static zone_really_inline int32_t find_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  const char *p = token->data;

#define MAYBE_TYPE(key) \
  return maybe_type(parser, type, field, token, code, symbol, key)
#define MAYBE_CLASS(key) \
  return maybe_class(parser, type, field, token, code, symbol, key)

  switch (type_code_page[ (uint8_t)p[0] ]) {
    case 'A':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case  0 : MAYBE_TYPE(ZONE_A);
        case 'A': MAYBE_TYPE(ZONE_AAAA);
        case 'F': MAYBE_TYPE(ZONE_AFSDB);
        case 'P': MAYBE_TYPE(ZONE_APL);
        case '6': MAYBE_TYPE(ZONE_A6);
        case 'V': MAYBE_TYPE(ZONE_AVC);
      }
      break;
    case 'C':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'N': MAYBE_TYPE(ZONE_CNAME);
        case 'D':
          switch (type_code_page[ (uint8_t)p[2] ]) {
            case 'S': MAYBE_TYPE(ZONE_CDS);
            case 'N': MAYBE_TYPE(ZONE_CDNSKEY);
          }
          break;
        case 'H': MAYBE_CLASS(ZONE_CH);
        case 'A': MAYBE_TYPE(ZONE_CAA);
        case 'E': MAYBE_TYPE(ZONE_CERT);
        case 'S':
          switch (type_code_page[ (uint8_t)p[2] ]) {
            case  0 : MAYBE_CLASS(ZONE_CS);
            case 'Y': MAYBE_TYPE(ZONE_CSYNC);
          }
      }
      break;
    case 'D':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'N':
          switch (type_code_page[ (uint8_t)p[2] ]) {
            case 'A': MAYBE_TYPE(ZONE_DNAME);
            case 'S': MAYBE_TYPE(ZONE_DNSKEY);
          }
          break;
        case 'S': MAYBE_TYPE(ZONE_DS);
        case 'H': MAYBE_TYPE(ZONE_DHCID);
        case 'L': MAYBE_TYPE(259);
      }
      break;
    case 'E':
      switch (type_code_page[ (uint8_t)p[3] ]) {
        case '4': MAYBE_TYPE(ZONE_EUI48);
        case '6': MAYBE_TYPE(ZONE_EUI64);
      }
      break;
    case 'G': MAYBE_TYPE(ZONE_GPOS);
    case 'H':
      switch (type_code_page[ (uint8_t)p[2] ]) {
        case 'T': MAYBE_TYPE(ZONE_HTTPS);
        case 'N': MAYBE_TYPE(ZONE_HINFO);
        case 'P': MAYBE_TYPE(ZONE_HIP);
        case  0 : MAYBE_CLASS(ZONE_HS);
      }
      break;
    case 'I':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'N': MAYBE_CLASS(ZONE_IN);
        case 'P': MAYBE_TYPE(ZONE_IPSECKEY);
        case 'S': MAYBE_TYPE(ZONE_ISDN);
      }
      break;
    case 'K':
      switch (type_code_page[ (uint8_t)p[1] ] ) {
        case 'E': MAYBE_TYPE(ZONE_KEY);
        case 'X': MAYBE_TYPE(ZONE_KX);
      }
      break;
    case 'L':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case '3': MAYBE_TYPE(ZONE_L32);
        case '6': MAYBE_TYPE(ZONE_L64);
        case 'O': MAYBE_TYPE(ZONE_LOC);
        case 'P': MAYBE_TYPE(ZONE_LP);
      }
      break;
    case 'M':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'X': MAYBE_TYPE(ZONE_MX);
        case 'B': MAYBE_TYPE(ZONE_MB);
        case 'D': MAYBE_TYPE(ZONE_MD);
        case 'F': MAYBE_TYPE(ZONE_MF);
        case 'G': MAYBE_TYPE(ZONE_MG);
        case 'I': MAYBE_TYPE(ZONE_MINFO);
        case 'R': MAYBE_TYPE(ZONE_MR);
      }
      break;
    case 'N':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'S':
          switch (type_code_page[ (uint8_t)p[2] ]) {
            case  0 : MAYBE_TYPE(ZONE_NS);
            case 'E':
              switch (type_code_page[ (uint8_t)p[4] ]) {
                case  0 : MAYBE_TYPE(ZONE_NSEC);
                case '3':
                  switch (type_code_page[ (uint8_t)p[5] ]) {
                    case  0 : MAYBE_TYPE(ZONE_NSEC3);
                    case 'P': MAYBE_TYPE(ZONE_NSEC3PARAM);
                  }
              }
              break;
            case 'A':
              switch (type_code_page[ (uint8_t)p[4] ]) {
                case  0 : MAYBE_TYPE(ZONE_NSAP);
                case '-': MAYBE_TYPE(ZONE_NSAP_PTR);
              }
          }
          break;
        case 'A': MAYBE_TYPE(ZONE_NAPTR);
        case 'I': MAYBE_TYPE(ZONE_NID);
        case 'X': MAYBE_TYPE(ZONE_NXT);
      }
      break;
    case 'O': MAYBE_TYPE(ZONE_OPENPGPKEY);
    case 'P':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'T': MAYBE_TYPE(ZONE_PTR);
        case 'X': MAYBE_TYPE(ZONE_PX);
      }
      break;
    case 'R':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'R': MAYBE_TYPE(ZONE_RRSIG);
        case 'P': MAYBE_TYPE(ZONE_RP);
        case 'T': MAYBE_TYPE(ZONE_RT);
      }
      break;
    case 'S':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'O': MAYBE_TYPE(ZONE_SOA);
        case 'R': MAYBE_TYPE(ZONE_SRV);
        case 'I': MAYBE_TYPE(ZONE_SIG);
        case 'M': MAYBE_TYPE(ZONE_SMIMEA);
        case 'P': MAYBE_TYPE(ZONE_SPF);
        case 'S': MAYBE_TYPE(ZONE_SSHFP);
        case 'V': MAYBE_TYPE(ZONE_SVCB);
      }
      break;
    case 'T':
      switch (type_code_page[ (uint8_t)p[1] ]) {
        case 'X': MAYBE_TYPE(ZONE_TXT);
        case 'L': MAYBE_TYPE(ZONE_TLSA);
      }
      break;
    case 'U': MAYBE_TYPE(ZONE_URI);
    case 'W': MAYBE_TYPE(ZONE_WKS);
    case 'X': MAYBE_TYPE(ZONE_X25);
    case 'Z': MAYBE_TYPE(ZONE_ZONEMD);
  }

#undef MAYBE_TYPE
#undef MAYBE_CLASS
  return 0;
}

zone_nonnull_all
static zone_really_inline int32_t scan_generic_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  const char *ps = token->data + 4, *p = ps;
  uint64_t n = 0;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > 65535 || p - ps > 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *code = (uint16_t)n;
  if (*code <= 258)
    *symbol = &types[*code].info.name;
  else if (*code == ZONE_DLV)
    *symbol = &types[259].info.name;
  else
    *symbol = &types[0].info.name;
  return ZONE_TYPE;
}

zone_nonnull_all
static zone_really_inline int32_t scan_generic_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  const char *ps = token->data + 5, *p = ps;
  uint64_t n = 0;
  for (;; p++) {
    const uint64_t d = (uint8_t)*p - '0';
    if (d > 9)
      break;
    n = n * 10 + d;
  }

  if (!n || n > 65535 || p - ps >= 5 || is_contiguous((uint8_t)*p))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));

  *code = (uint16_t)n;
  if (*code <= 4)
    *symbol = &classes[*code].name;
  else
    *symbol = &classes[0].name;
  return ZONE_CLASS;
}

zone_nonnull_all
static zone_really_inline int32_t scan_type_or_class(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;
  if ((r = find_type_or_class(parser, type, field, token, code, symbol)))
    return r;

  if (strncasecmp(token->data, "TYPE", 4) == 0)
    return scan_generic_type(parser, type, field, token, code, symbol);
  else if (strncasecmp(token->data, "CLASS", 5) == 0)
    return scan_generic_class(parser, type, field, token, code, symbol);

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
}

zone_nonnull_all
static zone_really_inline int32_t scan_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token,
  uint16_t *code,
  const zone_symbol_t **symbol)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;
  if ((r = find_type_or_class(parser, type, field, token, code, symbol)) == ZONE_TYPE)
    return r;

  if (strncasecmp(token->data, "TYPE", 4) != 0)
    return scan_generic_type(parser, type, field, token, code, symbol);

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
}

zone_nonnull_all
static zone_really_inline int32_t parse_type(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;
  uint16_t c = 0;
  const zone_symbol_t *s;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  scan_type(parser, type, field, token, &c, &s);
  c = htons(c);
  memcpy(&parser->rdata->octets[parser->rdata->length], &c, sizeof(c));
  parser->rdata->length += sizeof(c);
  return ZONE_TYPE;
}

#endif // TYPE_H
