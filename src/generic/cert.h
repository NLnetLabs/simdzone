/*
 * cert.h
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef CERT_H
#define CERT_H

// https://www.iana.org/assignments/cert-rr-types/cert-rr-types.xhtml

typedef struct certificate_type certificate_type_t;
struct certificate_type {
  struct {
    char name[8];
    size_t length;
  } key;
  uint16_t value;
};

#define BAD_CERTIFICATE_TYPE(value) \
  { { "", 0 }, 0 }
#define CERTIFICATE_TYPE(name, value) \
  { { name, sizeof(name) - 1 }, value }

static const certificate_type_t certificate_types[] = {
  BAD_CERTIFICATE_TYPE(0),
  CERTIFICATE_TYPE("PKIX", 1),
  CERTIFICATE_TYPE("SPKI", 2),
  CERTIFICATE_TYPE("PGP", 3),
  CERTIFICATE_TYPE("IPKIX", 4),
  CERTIFICATE_TYPE("ISPKI", 5),
  CERTIFICATE_TYPE("IPGP", 6),
  CERTIFICATE_TYPE("ACPKIX", 7),
  CERTIFICATE_TYPE("IACPKIX", 8),
  CERTIFICATE_TYPE("URI", 253),
  CERTIFICATE_TYPE("OID", 254),
};

static const certificate_type_t *certificate_type_map[16] = {
  &certificate_types[5],  // ISPKI (0)
  &certificate_types[0],
  &certificate_types[0],
  &certificate_types[0],
  &certificate_types[0],
  &certificate_types[0],
  &certificate_types[10], // OID (6)
  &certificate_types[0],
  &certificate_types[3],  // PGP (8)
  &certificate_types[4],  // IPKIX (9)
  &certificate_types[2],  // SPKI (10)
  &certificate_types[1],  // PKIX (11)
  &certificate_types[8],  // IACPKIX (12)
  &certificate_types[9],  // URI (13)
  &certificate_types[6],  // IPGP (14)
  &certificate_types[7]   // ACPKIX (15)
};

// magic value generated using certificate-hash.c
static uint8_t certificate_hash(uint64_t value)
{
  uint32_t value32 = (uint32_t)((value >> 32) ^ value);
  return (uint8_t)((value32 * 98112ull) >> 32) & 0xf;
}

nonnull_all
static really_inline int32_t parse_certificate_type(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  static const int8_t zero_masks[48] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0
  };

  uint32_t number = (uint8_t)token->data[0] - '0';

  if (number > 9) {
    uint64_t input;
    memcpy(&input, token->data, 8);
    static const uint64_t letter_mask = 0x4040404040404040llu;
    const size_t length = token->length;
    // convert to upper case
    input &= input & ~((input & letter_mask) >> 1);
    // zero out non-relevant bytes
    uint64_t zero_mask;
    memcpy(&zero_mask, &zero_masks[32 - (token->length & 0xf)], 8);
    input &= zero_mask;
    const uint8_t index = certificate_hash(input);
    assert(index < 16);
    const certificate_type_t *certificate_type = certificate_type_map[index];
    uint64_t name;
    memcpy(&name, certificate_type->key.name, 8);
    uint16_t value = certificate_type->value;
    if (unlikely((input != name) & (length != certificate_type->key.length) & (value != 0)))
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
    value = htobe16(value);
    memcpy(rdata->octets, &value, 2);
    rdata->octets += 2;
    return 0;
  }

  bool leading_zero = (number == 0) & (token->length > 1);
  size_t length = 1;

  for (; length < token->length; length++) {
    const uint8_t digit = (uint8_t)token->data[length] - '0';
    if (digit > 9)
      break;
    number = number * 10 + digit;
  }

  if (number > 65535 || length > 5 || length != token->length || leading_zero)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  uint16_t value = (uint16_t)number;
  value = htobe16(value);
  memcpy(rdata->octets, &value, 2);
  rdata->octets += 2;
  return 0;
}

#endif // CERT_H
