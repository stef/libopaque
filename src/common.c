#include "common.h"

#ifdef TRACE
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

void a_randomscalar(unsigned char* buf) {
  uint8_t tmp[64];
  a_randombytes(tmp, 64);
  crypto_core_ristretto255_scalar_reduce(buf, tmp);
}
#endif // NORANDOM

