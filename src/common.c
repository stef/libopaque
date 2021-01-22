#include "common.h"

#if (defined TRACE || defined VOPRF_TEST_VEC)
void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  fprintf(stderr,"%s ",msg);
  for(i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  fprintf(stderr,"\n");
}
#endif // TRACE

#ifdef NORANDOM
void a_randombytes(void* const buf, const size_t len) {
  size_t i;
  for(i=0;i<len;i++) ((uint8_t*)buf)[i]=i&0xff;
}

void a_randomscalar(uint8_t* buf) {
  uint8_t tmp[64];
  a_randombytes(tmp, 64);
  crypto_core_ristretto255_scalar_reduce(buf, tmp);
}
#endif // NORANDOM

#ifdef __EMSCRIPTEN__

/*
 * The following is from
 * https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/sodium/utils.c .
 *
 * int
 * sodium_mlock(void *const addr, const size_t len)
 * {
 * #if defined(MADV_DONTDUMP) && defined(HAVE_MADVISE)
 *     (void) madvise(addr, len, MADV_DONTDUMP);
 * #endif
 * #ifdef HAVE_MLOCK
 *     return mlock(addr, len);
 * #elif defined(WINAPI_DESKTOP)
 *     return -(VirtualLock(addr, len) == 0);
 * #else
 *     errno = ENOSYS;
 *     return -1;
 * #endif
 * }
 *
 * When executing code compiled with Empscripten to create JavaScript bindings,
 * only the last part starting with "errno = ENOSYS" executes. ENOSYS means
 * "Function not implemented". libopaque checks the return value of sodium_mlock.
 * We do not want to fail, so let us just return 0.
 */
int opaque_mlock(void *const addr, const size_t len) {
  return 0;
}

/*
 * The following is from
 * https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/sodium/utils.c .
 *
 * int
 * sodium_munlock(void *const addr, const size_t len)
 * {
 *     sodium_memzero(addr, len);
 * #if defined(MADV_DODUMP) && defined(HAVE_MADVISE)
 *     (void) madvise(addr, len, MADV_DODUMP);
 * #endif
 * #ifdef HAVE_MLOCK
 *     return munlock(addr, len);
 * #elif defined(WINAPI_DESKTOP)
 *     return -(VirtualUnlock(addr, len) == 0);
 * #else
 *     errno = ENOSYS;
 *     return -1;
 * #endif
 * }
 *
 * When executing code compiled with Empscripten to create JavaScript bindings,
 * only the sodium_memzero line and the lines starting at "errno = ENOSYS"
 * execute. ENOSYS means "Function not implemented". libopaque checks the return
 * value of sodium_mlock. We do not want to fail, so let us return 0.
 */
int opaque_munlock(void *const addr, const size_t len) {
  sodium_memzero(addr, len);
  return 0;
}

#endif // __EMSCRIPTEN__
