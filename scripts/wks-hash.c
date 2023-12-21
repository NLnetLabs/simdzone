#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

typedef struct tuple tuple_t;
struct tuple {
  char name[16];
  uint16_t code;
};

static const tuple_t services[] = {
  { "tcpmux", 1 },
  { "echo", 7 },
  { "ftp-data", 20 },
  { "ftp", 21 },
  { "ssh", 22 },
  { "telnet", 23 },
  { "lmtp", 24 },
  { "smtp", 25 },
  { "nicname", 43 },
  { "domain", 53 },
  { "whoispp", 63 },
  { "http", 80 },
  { "kerberos", 88 },
  { "npp", 92 },
  { "pop3", 110 },
  { "nntp", 119 },
  { "ntp", 123 },
  { "imap", 143 },
  { "snmp", 161 },
  { "snmptrap", 162 },
  { "bgmp", 264 },
  { "ptp-event", 319 },
  { "ptp-general", 320 },
  { "nnsp", 433 },
  { "https", 443 },
  { "submission", 587 },
  // FIXME: submissions cannot be distinguished from submission by hash value
  //        because the shared prefix is too long. it makes sense to calculate
  //        the hash over the suffix rather then the prefix or include the
  //        length
  { "submissions", 465 },
  { "nntps", 563 },
  { "ldaps", 636 },
  { "domain-s", 853 },
  { "ftps-data", 989 },
  { "ftps", 990 },
  { "imaps", 993 },
  { "pop3s", 995 }
};

const uint64_t original_magic = 138261570llu; // established after first run

static uint8_t hash(uint64_t magic, uint64_t value, size_t length)
{
  // ensure upper case modifies numbers and dashes unconditionally too,
  // but does not intruduce clashes
  value &= 0xdfdfdfdfdfdfdfdfllu;
  uint32_t value32 = ((value >> 32) ^ value);
  return (((value32 * magic) >> 32) + length) & 0x3f;
}

int main(int argc, char *argv[])
{
  const size_t n = sizeof(services)/sizeof(services[0]);
  for (uint64_t magic = original_magic; magic < UINT64_MAX; magic++) {
    size_t i;
    uint16_t keys[256] = { 0 };
    for (i=0; i < n; i++) {
      uint64_t value;
      memcpy(&value, services[i].name, 8);

      uint8_t key = hash(magic, value, strlen(services[i].name));
      if (keys[key])
        break;
      keys[key] = 1;
    }

    if (i == n) {
      struct { const char *name; uint16_t port; } table[64] = { 0 };
      printf("services: %zu, magic: %" PRIu64 "\n", i, magic);
      for (i=0; i < n; i++) {
        uint64_t value;
        memcpy(&value, services[i].name, 8);
        uint8_t key = hash(magic, value, strlen(services[i].name));
        table[key].name = services[i].name;
        table[key].port = services[i].code;
      }
      for (uint8_t key=0; key < sizeof(table)/sizeof(table[0]); key++) {
        if (table[key].port)
          printf("  SERVICE(\"%s\", %u),\n", table[key].name, table[key].port);
        else
          printf("  UNKNOWN_SERVICE(),\n");
      }
      return 0;
    }
  }

  printf("no magic value\n");
  return 1;
}
