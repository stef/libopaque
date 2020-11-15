#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <sodium.h>
#include <string.h>

//#define TRACE 1
//#define NORANDOM 1

#ifdef TRACE
#include <stdio.h>
void dump(const uint8_t *p, const size_t len, const char* msg);
#endif

#ifdef NORANDOM
void a_randombytes(void* const buf, const size_t len);
void a_randomscalar(unsigned char* buf);
#define crypto_core_ristretto255_scalar_random a_randomscalar
#define randombytes a_randombytes
#endif

#endif //COMMON_H
