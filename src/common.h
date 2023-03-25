#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <sodium.h>
#include <string.h>

//#define TRACE 1
//#define NORANDOM 1

#ifdef CFRG_TEST_VEC
#undef TRACE
#undef NORANDOM
#endif

#if (defined TRACE || defined CFRG_TEST_VEC)
#include <stdio.h>
#include <stdarg.h>
void dump(const uint8_t *p, const size_t len, const char* msg, ...);
#endif

#ifdef NORANDOM
void a_randombytes(void* const buf, const size_t len);
void a_randomscalar(uint8_t* buf);
#define crypto_core_ristretto255_scalar_random a_randomscalar
#define randombytes a_randombytes
#endif

#ifdef __EMSCRIPTEN__
// Per
// https://emscripten.org/docs/compiling/Building-Projects.html#detecting-emscripten-in-preprocessor,
// "The preprocessor define __EMSCRIPTEN__ is always defined when compiling
// programs with Emscripten". For why we are replacing sodium_m(un)?lock, see
// common.c for more details.
#include <sodium.h>
int opaque_mlock(void *const addr, const size_t len);
int opaque_munlock(void *const addr, const size_t len);
#define sodium_mlock opaque_mlock
#define sodium_munlock opaque_munlock
#endif

#endif //COMMON_H
