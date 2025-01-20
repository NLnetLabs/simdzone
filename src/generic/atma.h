/*
 * atma.h -- ATMA parser (see: https://web.archive.org/web/20190112072924/http://www.broadband-forum.org/ftp/pub/approved-specs/af-dans-0152.000.pdf )
 *
 * Copyright (c) 2025, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ATMA_H
#define ATMA_H

static const uint8_t bad_atma_chars[256] = {
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x00 - 0x07
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x08 - 0x0f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x10 - 0x17
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x18 - 0x10f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x20 - 0x27
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, // 0x28 - 0x2f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x30 - 0x37
  0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x38 - 0x3f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x40 - 0x47
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x48 - 0x4f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x50 - 0x57
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x58 - 0x5f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x60 - 0x67
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x68 - 0x6f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x70 - 0x77
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x78 - 0x7f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x80 - 0x87
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x88 - 0x8f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x90 - 0x97
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x98 - 0x9f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xa0 - 0xa7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xa8 - 0xaf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xb0 - 0xb7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xb8 - 0xbf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xc0 - 0xc7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xc8 - 0xcf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xd0 - 0xd7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xd8 - 0xdf
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xe0 - 0xe7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xe0 - 0xe7
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xf8 - 0xff
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0xf8 - 0xff
};

static const uint8_t atma_increment[256] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x01 - 0x07
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08 - 0x0f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x10 - 0x17
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x18 - 0x10f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 - 0x27
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x28 - 0x2f
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x30 - 0x37
  0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x38 - 0x3f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x40 - 0x47
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x48 - 0x4f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x50 - 0x57
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58 - 0x5f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60 - 0x67
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x68 - 0x6f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x70 - 0x77
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x78 - 0x7f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80 - 0x87
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88 - 0x8f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90 - 0x97
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98 - 0x9f
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xa0 - 0xa7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xa8 - 0xaf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0 - 0xb7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb8 - 0xbf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xc0 - 0xc7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xc8 - 0xcf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd0 - 0xd7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd8 - 0xdf
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe0 - 0xe7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe0 - 0xe7
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf8 - 0x00
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf8 - 0x00
};


nonnull_all
static really_inline int32_t parse_atma_e164(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint32_t bad_chars = 0;
  for (size_t count=1; count < token->length; count++) {
    const uint8_t octet = (uint8_t)token->data[count];
    *rdata->octets = octet;
    rdata->octets += atma_increment[octet];
    bad_chars |= bad_atma_chars[octet];
  }
  if (bad_chars)
    SEMANTIC_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));

  return 0;
}

nonnull((1,2,4,5))
static really_inline int atma_stream_decode(
  struct base16_state *state,
  const char *src,
  size_t srclen,
  uint8_t *out,
  size_t *outlen)
{
  int ret = 0;
  const uint8_t *s = (const uint8_t *) src;
  uint8_t *o = (uint8_t *) out;
  uint32_t q;

  // Use local temporaries to avoid cache thrashing:
  size_t olen = 0;
  size_t slen = srclen;
  struct base16_state st;
  st.eof = state->eof;
  st.bytes = state->bytes;
  st.carry = state->carry;

  if (st.eof) {
    *outlen = 0;
    return ret;
  }

  // Duff's device again:
  switch (st.bytes)
  {
#if defined(__SUNPRO_C)
#pragma error_messages(off, E_STATEMENT_NOT_REACHED)
#endif
    for (;;)
#if defined(__SUNPRO_C)
#pragma error_messages(default, E_STATEMENT_NOT_REACHED)
#endif
    {
    case 0:
      base16_dec_loop_generic_32(&s, &slen, &o, &olen);
      if (slen-- == 0) {
        ret = 1;
        break;
      }
      if ((q = base16_table_dec_32bit_d0[*s++]) == 256) {
        st.eof = BASE16_EOF;
        break;
      } else if (q == 257) {
	continue;
      }
      st.carry = (uint8_t)q;
      st.bytes = 1;

      // fallthrough

    case 1:
      if (slen-- == 0) {
        ret = 1;
        break;
      }
      if ((q = base16_table_dec_32bit_d1[*s++]) == 256) {
        st.eof = BASE16_EOF;
        break;
      } else if (q == 257) {
	continue;
      }
      *o++ = st.carry | (uint8_t)q;
      st.carry = 0;
      st.bytes = 0;
      olen++;
    }
  }

  state->eof = st.eof;
  state->bytes = st.bytes;
  state->carry = st.carry;
  *outlen = olen;
  return ret;
}

nonnull((1,3,4))
static really_inline int atma_decode(
  const char *src, size_t srclen, uint8_t *out, size_t *outlen)
{
  struct base16_state state = { .eof = 0, .bytes = 0, .carry = 0 };
  return atma_stream_decode(&state, src, srclen, out, outlen) & !state.bytes;
}

nonnull_all
static really_inline int32_t parse_atma(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  if (token->length && (char)*token->data == '+') {
    *rdata->octets++ = 1;
    if ((uintptr_t)rdata->limit - (uintptr_t)rdata->octets < token->length)
      SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
    return parse_atma_e164(parser, type, field, rdata, token);
  }
  size_t length = token->length / 2;
  if ((uintptr_t)rdata->limit - (uintptr_t)rdata->octets < length)
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  *rdata->octets++ = 0;
  if (!atma_decode(token->data, token->length, rdata->octets, &length))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  rdata->octets += length;
  return 0;
}

#endif // ATMA_H
