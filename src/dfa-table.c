/*
 * dfa-tables.c -- deterministic finite automaton table generator
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "dfa.h"

static const struct {
  zone_state_t current;
  zone_grapheme_t key;
  zone_state_t next;
  uint8_t bit;
} transitions[] = {
  // whitespace
  { ZONE_WHITESPACE,  ZONE_CHARACTER,  ZONE_CONTIGUOUS,               1 },
  { ZONE_WHITESPACE,  ZONE_SPACE,      ZONE_WHITESPACE,               0 },
  { ZONE_WHITESPACE,  ZONE_NEWLINE,    ZONE_WHITESPACE,               1 },
  { ZONE_WHITESPACE,  ZONE_QUOTE,      ZONE_QUOTED,                   1 },
  { ZONE_WHITESPACE,  ZONE_SEMICOLON,  ZONE_COMMENT,                  0 },
  { ZONE_WHITESPACE,  ZONE_BACKSLASH,  ZONE_CONTIGUOUS|ZONE_ESCAPED,  1 },
  { ZONE_WHITESPACE,  ZONE_BRACKET,    ZONE_WHITESPACE,               1 },
  // contiguous
  { ZONE_CONTIGUOUS,  ZONE_CHARACTER,  ZONE_CONTIGUOUS,               0 },
  { ZONE_CONTIGUOUS,  ZONE_SPACE,      ZONE_WHITESPACE,               1 },
  { ZONE_CONTIGUOUS,  ZONE_NEWLINE,    ZONE_WHITESPACE,               1 },
  { ZONE_CONTIGUOUS,  ZONE_QUOTE,      ZONE_QUOTED,                   1 },
  { ZONE_CONTIGUOUS,  ZONE_SEMICOLON,  ZONE_COMMENT,                  0 },
  { ZONE_CONTIGUOUS,  ZONE_BACKSLASH,  ZONE_CONTIGUOUS|ZONE_ESCAPED,  0 },
  { ZONE_CONTIGUOUS,  ZONE_BRACKET,    ZONE_WHITESPACE,               1 },
  // contiguous|escaped
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_CHARACTER,  ZONE_CONTIGUOUS,  0 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_SPACE,      ZONE_CONTIGUOUS,  0 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_NEWLINE,    ZONE_CONTIGUOUS,  1 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_QUOTE,      ZONE_CONTIGUOUS,  0 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_SEMICOLON,  ZONE_CONTIGUOUS,  0 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_BACKSLASH,  ZONE_CONTIGUOUS,  0 },
  { ZONE_CONTIGUOUS|ZONE_ESCAPED,  ZONE_BRACKET,    ZONE_CONTIGUOUS,  0 },
  // quoted
  { ZONE_QUOTED,      ZONE_CHARACTER,   ZONE_QUOTED,                  0 },
  { ZONE_QUOTED,      ZONE_SPACE,       ZONE_QUOTED,                  0 },
  { ZONE_QUOTED,      ZONE_NEWLINE,     ZONE_QUOTED,                  1 },
  { ZONE_QUOTED,      ZONE_QUOTE,       ZONE_WHITESPACE,              1 },
  { ZONE_QUOTED,      ZONE_SEMICOLON,   ZONE_QUOTED,                  0 },
  { ZONE_QUOTED,      ZONE_BACKSLASH,   ZONE_QUOTED|ZONE_ESCAPED,     0 },
  { ZONE_QUOTED,      ZONE_CHARACTER,   ZONE_QUOTED,                  0 },
  // quoted|escaped
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_CHARACTER,  ZONE_QUOTED,      0 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_SPACE,      ZONE_QUOTED,      0 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_NEWLINE,    ZONE_QUOTED,      1 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_QUOTE,      ZONE_QUOTED,      0 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_SEMICOLON,  ZONE_QUOTED,      0 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_BACKSLASH,  ZONE_QUOTED,      0 },
  { ZONE_QUOTED|ZONE_ESCAPED,      ZONE_BRACKET,    ZONE_QUOTED,      0 },
  // comment
  { ZONE_COMMENT,     ZONE_CHARACTER,  ZONE_COMMENT,                  0 },
  { ZONE_COMMENT,     ZONE_SPACE,      ZONE_COMMENT,                  0 },
  { ZONE_COMMENT,     ZONE_NEWLINE,    ZONE_WHITESPACE,               1 },
  { ZONE_COMMENT,     ZONE_QUOTE,      ZONE_COMMENT,                  0 },
  { ZONE_COMMENT,     ZONE_SEMICOLON,  ZONE_COMMENT,                  0 },
  { ZONE_COMMENT,     ZONE_BACKSLASH,  ZONE_COMMENT,                  0 },
  { ZONE_COMMENT,     ZONE_BRACKET,    ZONE_COMMENT,                  0 },
};

static int usage(const char *cmd)
{
  fprintf(stderr, "Usage: %s <output>\n", cmd);
  return 1;
}

#define KEYS (7)
#define KEY_BITS (3)
#define STATES (6)
#define STATE_BITS (3)
#define MASK_BITS (4) // matches the number of inputs packed together
#define TRANSITIONS (sizeof(transitions)/sizeof(transitions[0]))

static void permute(
  uint32_t key,
  uint32_t state, // original input state
  uint32_t depth,
  uint32_t current, // state for current transition
  uint64_t mask,
  uint64_t *table)
{
  assert(state <= STATES);
  assert(depth < MASK_BITS);
  assert(current <= STATES);
  for (uint32_t i=0; i < KEYS; i++) {
    key &= (1 << (depth * KEY_BITS)) - 1;
    key |= (i & KEYS) << (depth * KEY_BITS);
    for (uint32_t j=0; j < TRANSITIONS; j++) {
      if (transitions[j].key == i && transitions[j].current == current) {
        const uint64_t next = transitions[j].next;
        mask &= (1 << depth) - 1;
        mask |= (transitions[j].bit & 0x01) << depth;
        assert(key < (1 << (MASK_BITS * KEY_BITS)));
        if (depth == MASK_BITS - 1) {
          uint64_t *row = &table[key];
          *row |= next << (state * STATE_BITS) + (STATES * MASK_BITS);
          *row |= mask << (state * MASK_BITS);
        } else {
          permute(key, state, depth+1, next, mask, table);
        }
        break;
      }
    }
  }
}

int main(int argc, char *argv[])
{
  FILE *file = NULL;
  uint64_t *table = NULL;
  const size_t size = (1 << (MASK_BITS * KEY_BITS));

  if (argc != 2)
    return usage(argv[0]);

  // transitions are packed by 4 (maximum)
  //  - key size (3 bits) * 4 = 12 bits (4096 variations)
  //  - each group (<=4) has an ouput (1 bit) for each state (6) (24 bits)
  //  - each group (<=4) results in a state (6, or 3 bits) (18 bits)
  //    (reserve 64 bits for value)
  if (!(table = calloc(size, sizeof(uint64_t)))) {
    fprintf(stderr, "Cannot allocate memory for table");
    goto err_alloc;
  }

  for (uint32_t i=0; i < STATES; i++)
    permute(0, i, 0, i, 0, table);

  if (!(file = fopen(argv[1], "wb")))
    return 1;

  fprintf(file,
    "#include <stdint.h>\n"
    "\n"
    "static const uint64_t transitions[%zu] = {", size);

  for (size_t key=0, lf=0; key < size; key++, lf = (lf == 2 ? 0 : lf + 1)) {
    if (key)
      fputs(",", file);
    if (lf == 0)
      fputs("\n  ", file);
    else
      fputs(" ", file);
    fprintf(file, "0x%0.16"PRIx64, table[key]);
  }

  fprintf(file,
    "\n};\n");

  fclose(file);
  return 0;
err_fopen:
  free(table);
err_alloc:
  return 1;
}
