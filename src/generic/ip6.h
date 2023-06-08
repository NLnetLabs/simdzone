/*
 * ip6.h -- fallback parser for IPv6 addresses
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef IP6_H
#define IP6_H

#ifndef NS_INT16SZ
#define NS_INT16SZ  2
#endif

#ifndef NS_IN6ADDRSZ
#define NS_IN6ADDRSZ 16
#endif

#ifndef NS_INADDRSZ
#define NS_INADDRSZ 4
#endif

/* int
 * inet_pton4(src, dst)
 *  like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *  1 if `src' is a valid dotted quad, else 0.
 * notice:
 *  does not touch `dst' unless it's returning 1.
 * author:
 *  Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, uint8_t *dst)
{
  static const char digits[] = "0123456789";
  int saw_digit, octets, ch;
  uint8_t tmp[NS_INADDRSZ], *tp;

  saw_digit = 0;
  octets = 0;
  *(tp = tmp) = 0;
  while (contiguous[ (ch = *src++) ] == CONTIGUOUS) {
    const char *pch;

    if ((pch = strchr(digits, ch)) != NULL) {
      uint32_t new = *tp * 10 + (uint32_t)(pch - digits);

      if (new > 255)
        return (0);
      *tp = (uint8_t)new;
      if (! saw_digit) {
        if (++octets > 4)
          return (0);
        saw_digit = 1;
      }
    } else if (ch == '.' && saw_digit) {
      if (octets == 4)
        return (0);
      *++tp = 0;
      saw_digit = 0;
    } else
      return (0);
  }
  if (octets < 4)
    return (0);

  memcpy(dst, tmp, NS_INADDRSZ);
  return (1);
}

/* int
 * inet_pton6(src, dst)
 *  convert presentation level address to network order binary form.
 * return:
 *  1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *  (1) does not touch `dst' unless it's returning 1.
 *  (2) :: in a full address is silently ignored.
 * credit:
 *  inspired by Mark Andrews.
 * author:
 *  Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, uint8_t *dst)
{
  static const char xdigits_l[] = "0123456789abcdef",
        xdigits_u[] = "0123456789ABCDEF";
  uint8_t tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int ch, saw_xdigit;
  uint32_t val;

  memset((tp = tmp), '\0', NS_IN6ADDRSZ);
  endp = tp + NS_IN6ADDRSZ;
  colonp = NULL;
  /* Leading :: requires some special handling. */
  if (*src == ':')
    if (*++src != ':')
      return (0);
  curtok = src;
  saw_xdigit = 0;
  val = 0;
  while (contiguous[ (ch = *src++) ] == CONTIGUOUS) {
    const char *pch;

    if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
      pch = strchr((xdigits = xdigits_u), ch);
    if (pch != NULL) {
      val <<= 4;
      val |= (pch - xdigits);
      if (val > 0xffff)
        return (0);
      saw_xdigit = 1;
      continue;
    }
    if (ch == ':') {
      curtok = src;
      if (!saw_xdigit) {
        if (colonp)
          return (0);
        colonp = tp;
        continue;
      }
      if (tp + NS_INT16SZ > endp)
        return (0);
      *tp++ = (uint8_t) (val >> 8) & 0xff;
      *tp++ = (uint8_t) val & 0xff;
      saw_xdigit = 0;
      val = 0;
      continue;
    }
    if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
        inet_pton4(curtok, tp) > 0) {
      tp += NS_INADDRSZ;
      saw_xdigit = 0;
      break;  /* '\0' was seen by inet_pton4(). */
    }
    return (0);
  }
  if (saw_xdigit) {
    if (tp + NS_INT16SZ > endp)
      return (0);
    *tp++ = (uint8_t) (val >> 8) & 0xff;
    *tp++ = (uint8_t) val & 0xff;
  }
  if (colonp != NULL) {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we'll do the shift by hand.
     */
    const int n = (int)(tp - colonp);
    int i;

    for (i = 1; i <= n; i++) {
      endp[- i] = colonp[n - i];
      colonp[n - i] = 0;
    }
    tp = endp;
  }
  if (tp != endp)
    return (0);
  memcpy(dst, tmp, NS_IN6ADDRSZ);
  return (1);
}

zone_nonnull_all
static zone_really_inline int32_t parse_ip6(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  token_t *token)
{
  int32_t r;

  if ((r = have_contiguous(parser, type, field, token)) < 0)
    return r;

  if (inet_pton6(token->data, &parser->rdata->octets[parser->rdata->length]) == 1) {
    parser->rdata->length += 16;
    return ZONE_IP6;
  }

  SYNTAX_ERROR(parser, "Invalid %s in %s", NAME(field), NAME(type));
}

#endif // IP6_H
