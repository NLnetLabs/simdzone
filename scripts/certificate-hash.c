/*
 * certificate-hash.c -- Calculate perfect hash for certificate algorithms
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
  char name[8];
  uint8_t code;
};

// https://www.iana.org/assignments/cert-rr-types/cert-rr-types.xhtml
static const tuple_t algorithms[] = {
  { "PKIX", 1 },
  { "SPKI", 2 },
  { "PGP", 3 },
  { "IPKIX", 4 },
  { "ISPKI", 5 },
  { "IPGP", 6 },
  { "ACPKIX", 7 },
  { "IACPKIX", 8 },
  { "OID", 254 },
  { "URI", 253 }
};

const uint64_t original_magic = 98112llu;

static uint8_t hash(uint64_t magic, uint64_t value)
{
  uint32_t value32 = ((value >> 32) ^ value);
  return (value32 * magic) >> 32;
}

int main(int argc, char *argv[])
{
  const size_t n = sizeof(algorithms)/sizeof(algorithms[0]);
  for (uint64_t magic = original_magic; magic < UINT64_MAX; magic++) {
    size_t i;
    uint16_t keys[256] = { 0 };
    for (i=0; i < n; i++) {
      uint64_t value;
      memcpy(&value, algorithms[i].name, 8);

      uint8_t key = hash(magic, value);
      if (keys[key & 0xf])
        break;
      keys[key & 0xf] = 1;
    }

    if (i == n) {
      printf("i: %zu, magic: %" PRIu64 "\n", i, magic);
      for (i=0; i < n; i++) {
        uint64_t value;
        memcpy(&value, algorithms[i].name, 8);
        uint8_t key = hash(magic, value);
        printf("%s: %" PRIu8 " (%" PRIu16 ")\n", algorithms[i].name, key & 0xf, algorithms[i].code);
      }
      return 0;
    }
  }

  printf("no magic value\n");
  return 1;
}
