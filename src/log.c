#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include "log.h"

void zone_error(const zone_parser_t *par, const char *fmt, ...)
{
  assert(par);
  assert(fmt);
  (void)par;
  // pending a proper implementation
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}
