/*
 * endian.h -- byte order abstractions
 *
 * Copyright (c) 2023, NLnet Labs.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef ENDIAN_H
#define ENDIAN_H

#if _WIN32
#include <stdlib.h>

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN

#if BYTE_ORDER == LITTLE_ENDIAN
#define htobe16(x) _byteswap_ushort(x)
#define htobe32(x) _byteswap_ulong(x)
#define htobe64(x) _byteswap_uint64(x)
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)

#define be16toh(x) _byteswap_ushort(x)
#define be32toh(x) _byteswap_ulong(x)
#define be64toh(x) _byteswap_uint64(x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#else
#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define htole16(x) _byteswap_ushort(x)
#define htole32(x) _byteswap_ulong(x)
#define htole64(x) _byteswap_uint64(x)

#define be16toh(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#define le16toh(x) _byteswap_ushort(x)
#define le32toh(x) _byteswap_ulong(x)
#define le64toh(x) _byteswap_uint64(x)
#endif

#elif __APPLE__
#include <libkern/OSByteOrder.h>

#ifndef BYTE_ORDER
# define BYTE_ORDER __BYTE_ORDER__
#endif
#ifndef LITTLE_ENDIAN
# define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef BIG_ENDIAN
# define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)

#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else
#include "config.h"

#if defined(linux) || defined(__OpenBSD__)
#  ifdef HAVE_ENDIAN_H
#    include <endian.h>    /* attempt to define endianness */
#  else
#    include <machine/endian.h> /* on older OpenBSD */
#  endif
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/endian.h> /* attempt to define endianness */
#endif

#endif

#endif // ENDIAN_H
