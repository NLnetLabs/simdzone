/*
 * dfa.h -- deterministic finite automaton for lexical analysis of zone files
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef ZONE_DFA_H
#define ZONE_DFA_H

#include <stdint.h>

typedef enum {
  ZONE_CHARACTER = (0x00u),  // <*********> -- contiguous
  ZONE_SPACE = (0x04u),      // " "  : 0x20 |- space
                             // "\t" : 0x09 |
                             // "\r" : 0x0d |
  ZONE_NEWLINE = (0x05u),    // "\n" : 0x0a -- newline (ends record and comment)
  ZONE_QUOTE = (0x02u),      // "\"" : 0x22 -- starts and ends quoted
  ZONE_SEMICOLON = (0x01u),  // ";"  : 0x3b -- starts comment
  ZONE_BACKSLASH = (0x03u),  // "\\" : 0x5c -- next character is escaped
  ZONE_BRACKET = (0x06u)     // "("  : 0x28 |- starts/ends grouped
                             // ")"  : 0x29 |
} zone_grapheme_t;

#define ZONE_WHITESPACE (0x00u)
#define ZONE_COMMENT (0x01u)
#define ZONE_ESCAPED (0x01u) // use with contiguous (0x03u) or quoted (0x05u)
#define ZONE_CONTIGUOUS (0x02u)
#define ZONE_QUOTED (0x04u)

typedef uint_fast8_t zone_state_t;

extern const uint64_t *zone_transitions;

#endif // ZONE_DFA_H
