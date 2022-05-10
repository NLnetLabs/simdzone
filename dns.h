#ifndef DNS_H
#define DNS_H

#include <stdint.h>

int32_t strtotype(const char *str, size_t len, uint16_t *ptr);
int32_t strtoclass(const char *str, size_t len, uint16_t *ptr);
int32_t strtottl(const char *str, size_t len, uint32_t *ptr);

#endif // DNS_H
