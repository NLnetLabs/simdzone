/*
 * caa.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef CAA_H
#define CAA_H

// FIXME: eligable for vectorization
zone_nonnull_all
static zone_really_inline int32_t parse_caa_tag(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  const token_t *token)
{
  int32_t r;

  // RFC8659 section 4.1
  // https://datatracker.ietf.org/doc/html/rfc8659
  //
  // Tags MAY contain ASCII characters "a" through "z", "A" through "Z", and
  // the numbers 0 through 9. Tags MUST NOT contain any other characters.
  // Matching of tags is case insensitive.
  //
  // Tags submitted for registration by IANA MUST NOT contain any characters
  // other than the (lowercase) ASCII characters "a" through "z" and the
  // numbers 0 through 9.
  //
  // Tags registered by IANA
  // https://www.iana.org/assignments/pkix-parameters/pkix-parameters.xhtml
  //
  // issue
  // issuewild
  // iodef
  // auth
  // path
  // policy
  // contactemail
  // contactphone
  // issuevmc

  // Tags are meant to be written as <contiguous>.
  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  uint8_t *w = &parser->rdata->octets[parser->rdata->length + 1];
  const uint8_t *ws = w, *we = w + 255;
  const char *t = token->data;

  while (w < we) {
    const uint8_t c = (uint8_t)*t;
    if ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
    {
      w[0] = c;
      w += 1; t += 1;
    } else if (contiguous[c] != CONTIGUOUS) {
      break;
    } else {
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
    }
  }

  // FIXME: if an uppercase character is found, ensure it is not one of the
  //        tags registered by IANA.

  if (w >= we)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), TNAME(type));
  parser->rdata->octets[parser->rdata->length] = (uint8_t)(w - ws);
  parser->rdata->length += (size_t)(w - ws) + 1;
  return ZONE_STRING;
}

#endif // CAA_H
