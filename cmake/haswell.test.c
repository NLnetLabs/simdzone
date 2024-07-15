#include <stdint.h>
#include <immintrin.h>

int main(int argc, char *argv[])
{
  (void)argv;
  int argc32x8[8] = { argc, 0, 0, 0, 0, 0, 0, 0 };
  __m256i argc256 = _mm256_loadu_si256((__m256i *)argc32x8);
  return _mm256_testz_si256(argc256, _mm256_set1_epi8(11));
}
