#ifndef TABLE_H
#define TABLE_H

#include <string.h>

#if _WIN32
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#else
#include <strings.h>
#endif

static int compare(const void *p1, const void *p2)
{
  int r;
  const token_t *t = p1;
  const zone_string_t *s = p2;
  assert(s->length <= ZONE_BLOCK_SIZE);
  if ((r = strncasecmp(t->data, s->data, s->length)) != 0)
    return r;
  // make sure symbol is followed by non-contiguous to avoid matching wrong
  // symbol based on prefix. e.g. NSEC3 vs. NSEC3PARAM
  return contiguous[ (uint8_t)t->data[s->length] ] == CONTIGUOUS;
}

static const zone_symbol_t *lookup_symbol(
  const zone_table_t *table, const token_t *token)
{
  return bsearch(token, table->symbols, table->length, sizeof(zone_symbol_t), compare);
}

#endif // TABLE_H
