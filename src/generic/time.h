/*
 * time.h -- some useful comment
 *
 * Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TIME_H
#define TIME_H

/* Number of days per month (except for February in leap years). */
static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static int is_leap_year(int year)
{
  return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int leap_days(int y1, int y2)
{
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
static time_t mktime_from_utc(const struct tm *tm)
{
  int year = 1900 + tm->tm_year;
  time_t days = 365 * (year - 1970) + leap_days(1970, year);
  time_t hours;
  time_t minutes;
  time_t seconds;
  int i;

  for (i = 0; i < tm->tm_mon; ++i) {
      days += mdays[i];
  }
  if (tm->tm_mon > 1 && is_leap_year(year)) {
      ++days;
  }
  days += tm->tm_mday - 1;

  hours = days * 24 + tm->tm_hour;
  minutes = hours * 60 + tm->tm_min;
  seconds = minutes * 60 + tm->tm_sec;

  return seconds;
}

// FIXME: likely eligible for vectorization, see issue #22
zone_nonnull_all()
static inline void parse_time(
  zone_parser_t *parser,
  const zone_type_info_t *type,
  const zone_field_info_t *field,
  zone_token_t *token)
{
  char buf[] = "YYYYmmddHHMMSS";

  if (token->length >= sizeof(buf))
    SYNTAX_ERROR(parser, "Invalid %s in %s",
                 field->name.data, type->name.data);
  memcpy(buf, token->data, token->length);
  buf[token->length] = '\0';

  const char *end = NULL;
  struct tm tm;
  if (!(end = strptime(buf, "%Y%m%d%H%M%S", &tm)) || *end != 0)
    SYNTAX_ERROR(parser, "Invalid %s in %s",
                 field->name.data, type->name.data);
  *((uint32_t *)&parser->rdata[parser->rdlength]) = htonl(mktime_from_utc(&tm));
  parser->rdlength += sizeof(uint32_t);
}

#endif // TIME_H
