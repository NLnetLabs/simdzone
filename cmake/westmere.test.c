#include <stdint.h>
#include <immintrin.h>

int main(int argc, char *argv[])
{
  (void)argv;
  uint64_t popcnt = _mm_popcnt_u64((uint64_t)argc);
  return popcnt == 11;
}
