/*
 * string.h -- comment
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_STRING_H
#define ZONE_STRING_H

#include "zone.h"

typedef struct zone_string zone_string_t;
struct zone_string {
  const char *data;
  size_t length;
  int32_t escaped;
};

#define ZONE_QUOTED (1<<8)
#define ZONE_DECIMAL (1<<9)

typedef zone_return_t zone_char_t; // alias for readability

inline zone_char_t zone_string_peek(
  const zone_string_t *str, size_t *cur, uint32_t flags)
{
  if (*cur == str->length)
    return '\0';

  assert(*cur < str->length);
  if (!str->escaped || str->data[*cur] != '\\')
    return str->data[*cur];

  zone_char_t chr = 0, flg = 0;

  if (*cur == str->length - 1)
    goto bad_escape;
  flg = ZONE_QUOTED;
  chr = str->data[*cur + 1];
  if (chr < '0' || chr > '9')
    return chr | ZONE_QUOTED;
  if (chr > '2')
    goto bad_escape;

  zone_char_t unesc = chr - '0';
  for (size_t cnt = 2; cnt < 4; cnt++) {
    zone_char_t esc;
    if (*cur == str->length - cnt)
      goto bad_escape;
    esc = str->data[*cur + cnt];
    if (esc < '0' || esc > '5')
      goto bad_escape;
    unesc *= 10;
    unesc += esc - '0';
  }

  return unesc | ZONE_DECIMAL;
bad_escape:
  if (flags & ZONE_STRICT)
    return -1;
  return chr | flg;
}

inline zone_char_t zone_string_next(
  const zone_string_t *str, size_t *cur, uint32_t flags)
{
  zone_char_t chr = zone_string_peek(str, cur, flags);

  if (chr <= 0)
    return chr;

  if (chr & ZONE_DECIMAL)
    *cur += 4;
  else if (chr & ZONE_QUOTED)
    *cur += 2;
  else
    *cur += 1;
  return chr;
}

#endif // ZONE_STRING_H
