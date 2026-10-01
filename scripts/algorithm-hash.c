/*
 * algorithm-hash.c -- Calculate perfect hash for DNSSEC algorithms
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

typedef struct tuple tuple_t;
struct tuple {
  char name[24];
  uint8_t code;
  int array_index; // index in algorithms[] (0 = BAD placeholder)
};

// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
// Sparse algorithms[32]: index matches value where possible; 9 and 11 reserved;
// ED448/SM2SM3 at 16/17; ECC-GOST12 at 23; INDIRECT/PRIVATEDNS/PRIVATEOID after.
static const tuple_t algorithms[] = {
  { "RSAMD5", 1, 1 },
  { "DH", 2, 2 },
  { "DSA", 3, 3 },
  { "ECC", 4, 4 },
  { "RSASHA1", 5, 5 },
  { "DSA-NSEC-SHA1", 6, 6 },
  { "RSASHA1-NSEC3-SHA1", 7, 7 },
  { "RSASHA256", 8, 8 },
  { "RSASHA512", 10, 10 },
  { "ECC-GOST", 12, 12 },
  { "ECDSAP256SHA256", 13, 13 },
  { "ECDSAP384SHA384", 14, 14 },
  { "ED25519", 15, 15 },
  { "ED448", 16, 16 },
  { "SM2SM3", 17, 17 },
  { "ECC-GOST12", 23, 23 },
  { "INDIRECT", 252, 24 },
  { "PRIVATEDNS", 253, 25 },
  { "PRIVATEOID", 254, 26 }
};

// Hash table size must be a power of two; 32 fits the current set.
#define HASH_BITS 5
#define HASH_SIZE (1u << HASH_BITS)
#define HASH_MASK (HASH_SIZE - 1)

static uint64_t
name_key(const char *name, size_t length)
{
  char upper[8];
  uint64_t value;
  size_t i;

  memset(upper, 0, sizeof(upper));
  for (i = 0; i < length && i < 8; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c >= 'a' && c <= 'z')
      c = (unsigned char)(c - 32);
    upper[i] = (char)c;
  }
  memcpy(&value, upper, 8);
  // Include length so ECC-GOST and ECC-GOST12 do not collide.
  value ^= ((uint64_t)length << 56);
  return value;
}

static uint8_t hash(uint64_t magic, uint64_t value)
{
  uint32_t value32 = (uint32_t)((value >> 32) ^ value);
  return (uint8_t)((value32 * magic) >> 32) & HASH_MASK;
}

static void
print_mask(const char *name, size_t length)
{
  size_t i;
  printf("    { ");
  for (i = 0; i < 24; i++) {
    if (i && (i % 8) == 0)
      printf("\n      ");
    if (i < length) {
      unsigned char c = (unsigned char)name[i];
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        printf("0xdf");
      else
        printf("0xff");
    } else {
      printf("0");
    }
    if (i != 23)
      printf(", ");
  }
  printf(" }");
}

int main(int argc, char *argv[])
{
  const size_t n = sizeof(algorithms)/sizeof(algorithms[0]);
  uint64_t magic;
  (void)argc;
  (void)argv;

  for (magic = 1; magic < UINT64_MAX; magic++) {
    size_t i;
    uint8_t seen[HASH_SIZE];
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < n; i++) {
      size_t length = strlen(algorithms[i].name);
      uint8_t key = hash(magic, name_key(algorithms[i].name, length));
      if (seen[key])
        break;
      seen[key] = 1;
    }

    if (i == n) {
      int slot_to_idx[HASH_SIZE];
      size_t s;

      printf("// magic: %" PRIu64 "\n", magic);
      for (i = 0; i < n; i++) {
        size_t length = strlen(algorithms[i].name);
        uint8_t key = hash(magic, name_key(algorithms[i].name, length));
        printf("// %s -> slot %u (code %u, index %d)\n",
          algorithms[i].name, key, algorithms[i].code,
          algorithms[i].array_index);
      }

      printf("\n--- algorithms array ---\n");
      printf("static const algorithm_t algorithms[32] = {\n");
      {
        int filled[32] = {0};
        for (i = 0; i < n; i++)
          filled[algorithms[i].array_index] = (int)i + 1;
        for (s = 0; s < 32; s++) {
          if (filled[s]) {
            int idx = filled[s] - 1;
            printf("  ALGORITHM(\"%s\", %u),\n",
              algorithms[idx].name, algorithms[idx].code);
          } else {
            printf("  BAD_ALGORITHM(%zu),\n", s);
          }
        }
      }
      printf("};\n");

      for (s = 0; s < HASH_SIZE; s++)
        slot_to_idx[s] = -1;
      for (i = 0; i < n; i++) {
        size_t length = strlen(algorithms[i].name);
        uint8_t key = hash(magic, name_key(algorithms[i].name, length));
        slot_to_idx[key] = (int)i;
      }

      printf("\n--- hash map ---\n");
      printf("} algorithm_hash_map[%u] = {\n", HASH_SIZE);
      for (s = 0; s < HASH_SIZE; s++) {
        if (slot_to_idx[s] < 0) {
          printf("  { &algorithms[0],  // unknown (%zu)\n", s);
          printf("    { 0 } }");
        } else {
          int idx = slot_to_idx[s];
          printf("  { &algorithms[%d], // %s (%zu)\n",
            algorithms[idx].array_index, algorithms[idx].name, s);
          print_mask(algorithms[idx].name, strlen(algorithms[idx].name));
        }
        if (s + 1 < HASH_SIZE)
          printf(",\n");
        else
          printf("\n");
      }
      printf("};\n");
      return 0;
    }
  }

  printf("no magic value\n");
  return 1;
}
