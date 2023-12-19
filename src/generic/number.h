/*
 * number.h -- integer parsing routines
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef NUMBER_H
#define NUMBER_H

nonnull((1,3))
static really_inline int32_t scan_int8(
  const char *data, size_t length, uint8_t *number)
{
  uint32_t sum = (uint8_t)data[0] - '0';

  if (sum > 9 || length > 3)
    return 0;

  uint32_t non_zero = (sum != 0) | (length == 1);

  for (size_t count=1; count < length; count++) {
    const uint8_t digit = (uint8_t)data[count] - '0';
    sum = sum * 10 + digit;
    if (digit > 9)
      return 0;
  }

  *number = (uint8_t)sum;
  return sum <= 255u && non_zero;
}

nonnull((1,3))
static really_inline int32_t scan_int16(
  const char *data, size_t length, uint16_t *number)
{
  uint32_t sum = (uint8_t)data[0] - '0';

  if (sum > 9 || length > 5)
    return 0;

  uint32_t non_zero = (sum != 0) | (length == 1);

  for (size_t count=1; count < length; count++) {
    const uint8_t digit = (uint8_t)data[count] - '0';
    sum = sum * 10 + digit;
    if (digit > 9)
      return 0;
  }

  *number = (uint16_t)sum;
  return sum <= 65535u && non_zero;
}

nonnull((1,3))
static really_inline int32_t scan_int32(
  const char *data, size_t length, uint32_t *number)
{
  uint64_t sum = (uint8_t)data[0] - '0';

  if (sum > 9 || length > 10)
    return 0;

  uint32_t non_zero = (sum != 0) | (length == 1);

  for (size_t count=1; count < length; count++) {
    const uint8_t digit = (uint8_t)data[count] - '0';
    sum = sum * 10 + digit;
    if (digit > 9)
      return 0;
  }

  *number = (uint32_t)sum;
  return sum <= 4294967295u && non_zero;
}

nonnull_all
static really_inline int32_t parse_int8(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint8_t number;
  if (!scan_int8(token->data, token->length, &number))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  memcpy(rdata->octets, &number, 1);
  *rdata->octets++ = number;
  return 0;
}

nonnull_all
static really_inline int32_t parse_int16(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint16_t number;
  if (!scan_int16(token->data, token->length, &number))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  number = htobe16(number);
  memcpy(rdata->octets, &number, 2);
  rdata->octets += 2;
  return 0;
}

nonnull_all
static really_inline int32_t parse_int32(
  parser_t *parser,
  const type_info_t *type,
  const rdata_info_t *field,
  rdata_t *rdata,
  const token_t *token)
{
  uint32_t number;
  if (!scan_int32(token->data, token->length, &number))
    SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
  number = htobe32(number);
  memcpy(rdata->octets, &number, 4);
  rdata->octets += 4;
  return 0;
}

#endif // NUMBER_H
