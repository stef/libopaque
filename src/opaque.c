/*
    @copyright 2018-20, opaque@ctrlc.hu
    This file is part of libopaque.

    libopaque is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libopaque is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libopaque. If not, see <http://www.gnu.org/licenses/>.

    This file implements the Opaque protocol as specified by the IETF CFRG
*/

#include "opaque.h"
#include <arpa/inet.h>

#if (defined VOPRF_TEST_VEC_1 || defined VOPRF_TEST_VEC_2)
#define VOPRF_TEST_VEC 1
#undef TRACE
#undef NORANDOM
#endif

#include "common.h"

#ifndef HAVE_SODIUM_HKDF
#include "aux/crypto_kdf_hkdf_sha256.h"
#endif

/**
 * sk is a shared secret. In opaque.h, we do not report its byte size. We
 * centralize its size here so that if the algorithm to calculate sk changes, we
 * can just change it in one place.
 */
#define OPAQUE_SHARED_SECRETBYTES 32

#define OPAQUE_HANDSHAKE_SECRETBYTES 32

/**
 * See oprf_Finalize. TODO Change "OPAQUE01" once the RFC publishes.
 */
static const uint8_t OPAQUE_FINALIZE_INFO[] = "OPAQUE01";

#define OPAQUE_FINALIZE_INFO_LEN 8

typedef struct {
  uint8_t skU[crypto_scalarmult_SCALARBYTES];
  uint8_t pkU[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_Credentials;

// user specific record stored at server upon registration
typedef struct {
  uint8_t kU[crypto_core_ristretto255_SCALARBYTES];
  uint8_t skS[crypto_scalarmult_SCALARBYTES];
  uint8_t pkU[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
  uint32_t envU_len;
  uint8_t envU[];
} __attribute((packed)) Opaque_UserRecord;

typedef struct {
  uint8_t M[crypto_core_ristretto255_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t blind[crypto_core_ristretto255_SCALARBYTES];
  uint8_t x_u[crypto_scalarmult_SCALARBYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
  uint8_t M[crypto_core_ristretto255_BYTES];
  uint16_t pwdU_len;
  uint8_t pwdU[];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t Z[crypto_core_ristretto255_BYTES];
  uint8_t X_s[crypto_scalarmult_BYTES];
  uint8_t nonceS[OPAQUE_NONCE_BYTES];
  uint8_t auth[crypto_auth_hmacsha256_BYTES];
  uint32_t envU_len;
  uint8_t envU[];
} __attribute((packed)) Opaque_ServerSession;

typedef struct {
  uint8_t blind[crypto_core_ristretto255_SCALARBYTES];
  uint16_t pwdU_len;
  uint8_t pwdU[];
} Opaque_RegisterUserSec;

typedef struct {
  uint8_t Z[crypto_core_ristretto255_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_RegisterSrvPub;

typedef struct {
  uint8_t skS[crypto_scalarmult_SCALARBYTES];
  uint8_t kU[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) Opaque_RegisterSrvSec;

typedef struct {
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t km2[crypto_auth_hmacsha256_KEYBYTES];
  uint8_t km3[crypto_auth_hmacsha256_KEYBYTES];
  uint8_t ke2[OPAQUE_HANDSHAKE_SECRETBYTES];
  uint8_t ke3[OPAQUE_HANDSHAKE_SECRETBYTES];
} __attribute((packed)) Opaque_Keys;

/**
 * struct Opaque_ServerAuthCTX for storing context information for
 * explicit authentication.
 *
 * In case the Opaque session requires explicit authentication of the
 * user, the client needs to retain this information from the
 * opaque_CreateCredentialResponse() to use during the authentication of the user
 * via the opaque_UserAuth() function.
 */
typedef struct {
  uint8_t km3[crypto_auth_hmacsha256_KEYBYTES];
  crypto_hash_sha256_state xcript_state;
} Opaque_ServerAuthCTX;

typedef enum {
  skU = 1,
  pkU = 2,
  pkS = 3,
  idU = 4,
  idS = 5
} __attribute((packed)) CredentialType;

typedef struct {
  CredentialType type: 8;
  uint16_t size;
  uint8_t data[1];
} __attribute((packed)) CredentialExtension;

/**
 * This function generates an OPRF private key.
 *
 * This is the KeyGen OPRF function defined in the RFC:
 * > OPAQUE only requires an OPRF private key. We write (kU, _) = KeyGen() to denote
 * > use of this function for generating secret key kU (and discarding the
 * > corresponding public key).
 *
 * @param [out] kU - the per-user OPRF private key
 */
static void oprf_KeyGen(uint8_t kU[crypto_core_ristretto255_SCALARBYTES]) {
  crypto_core_ristretto255_scalar_random(kU);
}

/**
 * This function computes the OPRF output using input x, N, and domain separation
 * tag info.
 *
 * This is the Finalize OPRF function defined in the RFC.
 *
 * @param [in] x - a value used to compute OPRF (for OPAQUE, this is pwdU, the
 * user's password)
 * @param [in] x_len - the length of param x in bytes
 * @param [in] N - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Unblind
 * @param [in] info - a domain separation tag
 * @param [in] info_len - the length of param info in bytes
 * @param [out] y - an OPRF output
 * @return The function returns 0 if everything is correct.
 */
static int oprf_Finalize(const uint8_t *x, const uint16_t x_len,
                         const uint8_t N[crypto_core_ristretto255_BYTES],
                         const uint8_t *info, const uint16_t info_len,
                         uint8_t rwdU[crypto_secretbox_KEYBYTES]) {
  // according to paper: hash(pwd||H0^k)
  // acccording to voprf IETF CFRG specification: hash(htons(len(pwd))||pwd||
  //                                              htons(len(H0_k))||H0_k|||
  //                                              htons(len(info))||info||
  //                                              htons(len("VOPRF06-Finalize-OPAQUE00"))||"VOPRF06-Finalize-OPAQUE00")
  crypto_hash_sha512_state state;
  if(-1==sodium_mlock(&state,sizeof state)) {
    return -1;
  }
  crypto_hash_sha512_init(&state);
  // pwd
  uint16_t size=htons(x_len);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, x, x_len);
  // H0_k
  size=htons(crypto_core_ristretto255_BYTES);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, N, crypto_core_ristretto255_BYTES);
  // info
  if(info!=NULL && info_len>0) {
    size=htons(info_len);
    crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
    crypto_hash_sha512_update(&state, info, info_len);
  }
  const uint8_t DST[]="VOPRF06-Finalize-OPAQUE00";
  const uint8_t DST_size=strlen((const char*) DST);
  size=htons(DST_size);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, DST, DST_size);

  uint8_t y[crypto_hash_sha512_BYTES];
  if(-1==sodium_mlock(&y,sizeof y)) {
    sodium_munlock(&state, sizeof state);
    return -1;
  }
  crypto_hash_sha512_final(&state, y);
  sodium_munlock(&state, sizeof state);

#ifdef TRACE
  dump((uint8_t*) y, sizeof y, "y ");
#endif

  // salt - according to the ietf draft this could be all zeroes
  uint8_t salt[crypto_pwhash_SALTBYTES]={0};
  if (crypto_pwhash(rwdU, crypto_secretbox_KEYBYTES, (const char*) y, sizeof y, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(y, sizeof(y));
    return -1;
  }
  sodium_munlock(y, sizeof(y));
  crypto_kdf_hkdf_sha256_extract(rwdU, (uint8_t*) "RwdU", 4, rwdU, crypto_secretbox_KEYBYTES);

#ifdef TRACE
  dump((uint8_t*) rwdU, crypto_secretbox_KEYBYTES, "rwdU ");
#endif

  return 0;
}

static int prf(const uint8_t *pwdU, const uint16_t pwdU_len,
                const uint8_t kU[crypto_core_ristretto255_SCALARBYTES],
                uint8_t rwdU[crypto_secretbox_KEYBYTES]) {
  // F_k(pwd) = H(pwd, (H0(pwd))^k) for key k ∈ Z_q
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  sodium_mlock(h0,sizeof h0);
  // hash pwd with H0
  crypto_hash_sha512(h0, pwdU, pwdU_len);
#ifdef TRACE
  dump(h0, sizeof h0, "h0");
#endif
  uint8_t H0[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0,sizeof H0);
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);
#ifdef TRACE
  dump(H0, sizeof H0, "H0");
#endif

  // H0 ^ k
  uint8_t N[crypto_core_ristretto255_BYTES];
  sodium_mlock(N,sizeof N);
  if (crypto_scalarmult_ristretto255(N, kU, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    sodium_munlock(N,sizeof N);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef TRACE
  dump(N, sizeof N, "N");
#endif

  // 2. rwdU = Finalize(pwdU, N, "OPAQUE01")
  if(0!=oprf_Finalize(pwdU, pwdU_len, N, OPAQUE_FINALIZE_INFO, OPAQUE_FINALIZE_INFO_LEN, rwdU)) {
    sodium_munlock(N,sizeof N);
    return -1;
  }
  sodium_munlock(N,sizeof N);

  return 0;
}

/* expand_loop
 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
 */
static void expand_loop(const uint8_t *b_0, const uint8_t *b_i, const uint8_t i, const uint8_t *dst_prime, const uint8_t dst_prime_len, uint8_t *b_ii) {
  uint8_t xored[crypto_hash_sha512_BYTES];
  unsigned j;
  for(j=0;j<sizeof xored;j++) xored[j]=b_0[j]^b_i[j];
  // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, xored, sizeof xored);
  crypto_hash_sha512_update(&state,(uint8_t*) &i, 1);
  crypto_hash_sha512_update(&state, dst_prime, dst_prime_len);
  crypto_hash_sha512_final(&state, b_ii);
}

/*
 * expand_message_xmd(msg, DST, len_in_bytes)
 * as defined by https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/master/draft-irtf-cfrg-hash-to-curve.md#expand_message_xmd-hashtofield-expand-xmd
 *
 * Parameters:
 * - H, a hash function (see requirements above).
 * - b_in_bytes, b / 8 for b the output size of H in bits.
 *   For example, for b = 256, b_in_bytes = 32.
 * - r_in_bytes, the input block size of H, measured in bytes (see
 *   discussion above). For example, for SHA-256, r_in_bytes = 64.
 *
 * Input:
 * - msg, a byte string.
 * - DST, a byte string of at most 255 bytes.
 *   See below for information on using longer DSTs.
 * - len_in_bytes, the length of the requested output in bytes.
 *
 * Output:
 * - uniform_bytes, a byte string.
 *
 * Steps:
 * 1.  ell = ceil(len_in_bytes / b_in_bytes)
 * 2.  ABORT if ell > 255
 * 3.  DST_prime = DST || I2OSP(len(DST), 1)
 * 4.  Z_pad = I2OSP(0, r_in_bytes)
 * 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
 * 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
 * 7.  b_0 = H(msg_prime)
 * 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
 * 9.  for i in (2, ..., ell):
 * 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
 * 11. uniform_bytes = b_1 || ... || b_ell
 * 12. return substr(uniform_bytes, 0, len_in_bytes)
 */
static int expand_message_xmd(const uint8_t *msg, const uint8_t msg_len, const uint8_t *dst, const uint8_t dst_len, const uint8_t len_in_bytes, uint8_t *uniform_bytes) {
  // 1.  ell = ceil(len_in_bytes / b_in_bytes)
  const uint8_t ell = (len_in_bytes + crypto_hash_sha512_BYTES-1) / crypto_hash_sha512_BYTES;
  // 2.  ABORT if ell > 255
  if(ell>255) return -1;
  // 3.  DST_prime = DST || I2OSP(len(DST), 1)
  uint8_t dst_prime[dst_len+1];
  memcpy(dst_prime, dst, dst_len);
  dst_prime[dst_len] = dst_len;
#ifdef TRACE
  dump(dst_prime, sizeof dst_prime, "dst_prime");
#endif
  // 4.  Z_pad = I2OSP(0, r_in_bytes)
  //const uint8_t r_in_bytes = 128; // for sha512
  uint8_t z_pad[128 /*r_in_bytes*/] = {0}; // supress gcc error: variable-sized object may not be initialized
#ifdef TRACE
  dump(z_pad, sizeof z_pad, "z_pad");
#endif
  // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
  const uint16_t l_i_b = htons(len_in_bytes);
  const uint8_t *l_i_b_str = (uint8_t*) &l_i_b;
  // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
  uint8_t msg_prime[sizeof z_pad + msg_len + sizeof l_i_b + 1 + sizeof dst_prime],
    *ptr = msg_prime;
  memcpy(ptr, z_pad, sizeof z_pad);
  ptr += sizeof z_pad;
  memcpy(ptr, msg, msg_len);
  ptr += msg_len;
  memcpy(ptr, l_i_b_str, sizeof l_i_b);
  ptr += sizeof l_i_b;
  *ptr = 0;
  ptr++;
  memcpy(ptr, dst_prime, sizeof dst_prime);
#ifdef TRACE
  dump(msg_prime, sizeof msg_prime, "msg_prime");
#endif
  // 7.  b_0 = H(msg_prime)
  uint8_t b_0[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(b_0, msg_prime, sizeof msg_prime);
  // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  uint8_t b_i[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, b_0, sizeof b_0);
  crypto_hash_sha512_update(&state,(uint8_t*) &"\x01", 1);
  crypto_hash_sha512_update(&state, dst_prime, sizeof dst_prime);
  crypto_hash_sha512_final(&state, b_i);
  // 9.  for i in (2, ..., ell):
  unsigned left = len_in_bytes;
  uint8_t *out = uniform_bytes;
  unsigned clen = (left>sizeof b_i)?sizeof b_i:left;
  memcpy(out, b_i, clen);
  out+=clen;
  left-=clen;
  int i;
  uint8_t b_ii[crypto_hash_sha512_BYTES];
  for(i=2;i<=ell;i+=2) {
    // 11. uniform_bytes = b_1 || ... || b_ell
    // 12. return substr(uniform_bytes, 0, len_in_bytes)
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    expand_loop(b_0, b_i, i, dst_prime, sizeof dst_prime, b_ii);
    clen = (left>sizeof b_ii)?sizeof b_ii:left;
    memcpy(out, b_ii, clen);
    out+=clen;
    left-=clen;
    // unrolled next iteration so we don't have to swap b_i and b_ii
    expand_loop(b_0, b_ii, i+1, dst_prime, sizeof dst_prime, b_i);
    clen = (left>sizeof b_i)?sizeof b_i:left;
    memcpy(out, b_i, clen);
    out+=clen;
    left-=clen;
  }
  return 0;
}

/* hash-to-ristretto255 - as defined by  https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/master/draft-irtf-cfrg-hash-to-curve.md#hashing-to-ristretto255-appx-ristretto255
 * Steps:
 * -1. context-string = \x0 + htons(1) // contextString = I2OSP(modeBase(==0), 1) || I2OSP(suite.ID(==1), 2)
 * 0. dst="VOPRF06-HashToGroup-" + context-string (==\x00\x00\x01)
 * 1. uniform_bytes = expand_message(msg, DST, 64)
 * 2. P = ristretto255_map(uniform_bytes)
 * 3. return P
 */
static int voprf_hash_to_ristretto255(const uint8_t *msg, uint8_t msg_len, uint8_t p[crypto_core_ristretto255_BYTES]) {
  const uint8_t dst[] = "VOPRF06-HashToGroup-\x00\x00\x01";
  const uint8_t dst_len = (sizeof dst) - 1;
  uint8_t uniform_bytes[crypto_core_ristretto255_HASHBYTES]={0};
  if(0!=expand_message_xmd(msg, msg_len, dst, dst_len, crypto_core_ristretto255_HASHBYTES, uniform_bytes)) return -1;
#if (defined TRACE || defined VOPRF_TEST_VEC)
  dump(uniform_bytes, sizeof uniform_bytes, "uniform_bytes");
#endif
  crypto_core_ristretto255_from_hash(p, uniform_bytes);
#if (defined TRACE || defined VOPRF_TEST_VEC)
  dump(p, crypto_core_ristretto255_BYTES, "hashed-to-curve");
#endif
  return 0;
}

/**
 * This function converts input x into an element of the OPRF group, randomizes it
 * by some scalar r, producing M, and outputs (r, M).
 *
 * This is the Blind OPRF function defined in the RFC.
 *
 * @param [in] x - the value to blind (for OPAQUE, this is pwdU, the user's
 * password)
 * @param [in] x_len - the length of param x in bytes
 * @param [out] r - an OPRF scalar value used for randomization
 * @param [out] M - a serialized OPRF group element, a byte array of fixed length,
 * the blinded version of x, an input to oprf_Evaluate
 * @return The function returns 0 if everything is correct.
 */
static int oprf_Blind(const uint8_t *x, const uint16_t x_len,
                      uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                      uint8_t M[crypto_core_ristretto255_BYTES]) {
#ifdef VOPRF_TEST_VEC
  dump(x, x_len, "input");
#endif
  uint8_t H0[crypto_core_ristretto255_BYTES];
  if(0!=sodium_mlock(H0,sizeof H0)) {
    return -1;
  }
  // sets α := (H^0(pw))^r
  if(0!=voprf_hash_to_ristretto255(x, x_len, H0)) return -1;
#ifdef TRACE
  dump(H0,sizeof H0, "H0 ");
#endif

  // U picks r
#ifdef VOPRF_TEST_VEC_1
  unsigned char rtest[] = {
  0x5e, 0xd8, 0x95, 0x20, 0x6b, 0xfc, 0x53, 0x31, 0x6d, 0x30, 0x7b, 0x23,
  0xe4, 0x6e, 0xcc, 0x66, 0x23, 0xaf, 0xb3, 0x08, 0x6d, 0xa7, 0x41, 0x89,
  0xa4, 0x16, 0x01, 0x2b, 0xe0, 0x37, 0xe5, 0x0b
  };
  unsigned int rtest_len = 32;
  memcpy(r,rtest,rtest_len);
#elif VOPRF_TEST_VEC_2
  unsigned char rtest[] = {
    0xed, 0x83, 0x66, 0xfe, 0xb6, 0xb1, 0xd0, 0x5d, 0x1f, 0x46, 0xac, 0xb7,
    0x27, 0x06, 0x1e, 0x43, 0xaa, 0xdf, 0xaf, 0xe9, 0xc1, 0x0e, 0x5a, 0x64,
    0xe7, 0x51, 0x8d, 0x63, 0xe3, 0x26, 0x35, 0x03
  };
  unsigned int rtest_len = 32;
  memcpy(r,rtest,rtest_len);
#else
  crypto_core_ristretto255_scalar_random(r);
#endif

#ifdef TRACE
  dump(r, crypto_core_ristretto255_SCALARBYTES, "r");
#endif
  // H^0(pw)^r
  if (crypto_scalarmult_ristretto255(M, r, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef VOPRF_TEST_VEC
  dump(M, crypto_core_ristretto255_BYTES, "blinded");
#endif
#ifdef TRACE
  dump(M, crypto_core_ristretto255_BYTES, "M");
#endif
  return 0;
}

/**
 * This function evaluates input element M using private key k, yielding output
 * element Z.
 *
 * This is the Evaluate OPRF function defined in the RFC.
 *
 * @param [in] k - a private key (for OPAQUE, this is kU, the user's OPRF private
 * key)
 * @param [in] M - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Blind (for OPAQUE, this is the blinded pwdU, the user's
 * password)
 * @param [out] Z - a serialized OPRF group element, a byte array of fixed length,
 * an input to oprf_Unblind
 * @return The function returns 0 if everything is correct.
 */
static int oprf_Evaluate(const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                         const uint8_t M[crypto_core_ristretto255_BYTES],
                         uint8_t Z[crypto_core_ristretto255_BYTES]) {
  return crypto_scalarmult_ristretto255(Z, k, M);
}

/**
 * This function removes random scalar r from Z, yielding output N.
 *
 * This is the Unblind OPRF function defined in the RFC.
 *
 * @param [in] r - an OPRF scalar value used for randomization in oprf_Blind
 * @param [in] Z - a serialized OPRF group element, a byte array of fixed length,
 * an output of oprf_Evaluate
 * @param [out] N - a serialized OPRF group element with random scalar r removed,
 * a byte array of fixed length, an input to oprf_Finalize
 * @return The function returns 0 if everything is correct.
 */
static int oprf_Unblind(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                        const uint8_t Z[crypto_core_ristretto255_BYTES],
                        uint8_t N[crypto_core_ristretto255_BYTES]) {
#ifdef TRACE
  dump((uint8_t*) r, crypto_core_ristretto255_SCALARBYTES, "r ");
  dump((uint8_t*) Z, crypto_core_ristretto255_BYTES, "Z ");
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(Z) != 1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // invert r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir, sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, r) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) ir, sizeof ir, "r^-1 ");
#endif

  // H0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  if (crypto_scalarmult_ristretto255(N, ir, Z) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) N, crypto_core_ristretto255_BYTES, "N ");
#endif

  sodium_munlock(ir, sizeof ir);
  return 0;
}

static void hkdf_expand_label(uint8_t* res, const uint8_t secret[crypto_kdf_hkdf_sha256_KEYBYTES], const char *label, const char transcript[crypto_hash_sha256_BYTES], const size_t len) {
  // construct a hkdf label
  // struct {
  //   uint16 length = Length;
  //   opaque label<8..255> = "OPAQUE " + Label;
  //   opaque context<0..255> = Context;
  // } HkdfLabel;
  const size_t llen = strlen((const char*) label);
  uint8_t hkdflabel[2+7/*"OPAQUE "*/+llen+(transcript!=NULL?crypto_hash_sha256_BYTES:0)];

  *((uint16_t*) hkdflabel)=htons(crypto_auth_hmacsha256_KEYBYTES); // len

  uint8_t *ptr=hkdflabel+2;
  memcpy(ptr,"OPAQUE ",7);
  ptr+=7;

  memcpy(ptr,label,llen);
  ptr+=llen;
  if(transcript!=NULL)
    memcpy(ptr, transcript, crypto_hash_sha256_BYTES);

#ifdef TRACE
  fprintf(stderr,"expanded label: ");
  dump(hkdflabel, sizeof(hkdflabel), label);
  if(transcript!=NULL) dump((const uint8_t*) transcript,crypto_hash_sha256_BYTES, "transcript: ");
#endif

  crypto_kdf_hkdf_sha256_expand(res, len, (const char*) hkdflabel, sizeof(hkdflabel), secret);
}

// derive keys according to ietf cfrg draft
static void derive_keys(Opaque_Keys* keys, const uint8_t ikm[crypto_scalarmult_BYTES * 3], const char info[crypto_hash_sha256_BYTES]) {
  uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
  sodium_mlock(prk, sizeof prk);
#ifdef TRACE
  dump(ikm, crypto_scalarmult_BYTES*3, "ikm ");
  dump((uint8_t*) info, crypto_hash_sha256_BYTES, "info ");
#endif
  // prk = HKDF-Extract(salt=0, IKM)
  crypto_kdf_hkdf_sha256_extract(prk, NULL, 0, ikm, crypto_scalarmult_BYTES*3);

  // keys->sk         = Derive-Secret(., "session secret", info)
  hkdf_expand_label(keys->sk, prk, "session secret", info, OPAQUE_SHARED_SECRETBYTES);

  // handshake_secret = Derive-Secret(., "handshake secret", info)
  uint8_t handshake_secret[OPAQUE_HANDSHAKE_SECRETBYTES];
  sodium_mlock(handshake_secret, sizeof handshake_secret);
  hkdf_expand_label(handshake_secret, prk, "handshake secret", info, sizeof(handshake_secret));
  sodium_munlock(prk,sizeof(prk));

  //Km2 = HKDF-Expand-Label(handshake_secret, "server mac", "", Hash.length)
  hkdf_expand_label(keys->km2, handshake_secret, "server mac", NULL, crypto_auth_hmacsha256_KEYBYTES);
  //Km3 = HKDF-Expand-Label(handshake_secret, "client mac", "", Hash.length)
  hkdf_expand_label(keys->km3, handshake_secret, "client mac", NULL, crypto_auth_hmacsha256_KEYBYTES);
  //Ke2 = HKDF-Expand-Label(handshake_secret, "server enc", "", key_length)
  hkdf_expand_label(keys->ke2, handshake_secret, "server enc", NULL, OPAQUE_HANDSHAKE_SECRETBYTES);
  //Ke3 = HKDF-Expand-Label(handshake_secret, "client enc", "", key_length)
  hkdf_expand_label(keys->ke3, handshake_secret, "client enc", NULL, OPAQUE_HANDSHAKE_SECRETBYTES);
  sodium_munlock(handshake_secret, sizeof handshake_secret);
#ifdef TRACE
  dump(keys->sk, OPAQUE_SHARED_SECRETBYTES, "keys->sk");
  dump(keys->km2, crypto_auth_hmacsha256_KEYBYTES, "keys->km2");
  dump(keys->km3, crypto_auth_hmacsha256_KEYBYTES, "keys->km3");
  dump(keys->ke2, OPAQUE_HANDSHAKE_SECRETBYTES, "keys->ke2");
  dump(keys->ke3, OPAQUE_HANDSHAKE_SECRETBYTES, "keys->ke3");
#endif
}

static void calc_info(char info[crypto_hash_sha256_BYTES],
                      const uint8_t nonceU[OPAQUE_NONCE_BYTES],
                      const uint8_t nonceS[OPAQUE_NONCE_BYTES],
                      const Opaque_Ids *ids) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

#ifdef TRACE
  fprintf(stderr,"calc info\n");
  dump(ids->idU, ids->idU_len,"idU ");
  dump(ids->idS, ids->idS_len,"idS ");
  dump(nonceU, OPAQUE_NONCE_BYTES, "nonceU ");
  dump(nonceS, OPAQUE_NONCE_BYTES, "nonceS ");
#endif

  uint16_t len = htons(OPAQUE_NONCE_BYTES);
  crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
  crypto_hash_sha256_update(&state, nonceU, OPAQUE_NONCE_BYTES);
  crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
  crypto_hash_sha256_update(&state, nonceS, OPAQUE_NONCE_BYTES);
  if(ids->idU!=NULL && ids->idU_len > 0) {
    len=htons(ids->idU_len);
    crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
    crypto_hash_sha256_update(&state, ids->idU, ids->idU_len);
  } else {
    len=0;
    crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
  }
  if(ids->idS!=NULL && ids->idS_len > 0) {
    len=htons(ids->idS_len);
    crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
    crypto_hash_sha256_update(&state, ids->idS, ids->idS_len);
  } else {
    len=0;
    crypto_hash_sha256_update(&state, (uint8_t*) &len, 2);
  }
  crypto_hash_sha256_final(&state, (uint8_t *) info);
}

static void get_xcript(uint8_t xcript[crypto_hash_sha256_BYTES],
                       crypto_hash_sha256_state *xcript_state,
                       const uint8_t oprf1[crypto_core_ristretto255_BYTES],
                       const uint8_t nonceU[OPAQUE_NONCE_BYTES],
                       const uint8_t epubu[crypto_scalarmult_BYTES],
                       const uint8_t oprf2[crypto_core_ristretto255_BYTES],
                       const uint8_t *envu, const size_t envu_len,
                       const uint8_t nonceS[OPAQUE_NONCE_BYTES],
                       const uint8_t epubs[crypto_scalarmult_BYTES],
                       const Opaque_App_Infos *infos,
                       const int use_info3) {
  // OPRF1, nonceU, info1*, IdU*, ePubU, OPRF2, EnvU, nonceS, info2*, ePubS, Einfo2*, info3*, Einfo3*
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

#ifdef TRACE
  if(xcript_state!=NULL) dump((uint8_t*)xcript_state,sizeof state, "xcript_state ");
  else fprintf(stderr,"no xcript_state\n");
  dump(oprf1,crypto_core_ristretto255_BYTES, "oprf1 ");
  dump(nonceU,OPAQUE_NONCE_BYTES,"nonceU ");
  dump(epubu,crypto_scalarmult_BYTES,"epubu ");
  dump(oprf2,crypto_core_ristretto255_BYTES,"oprf2 ");
  dump(envu, envu_len, "envu ");
  dump(nonceS,OPAQUE_NONCE_BYTES,"nonceS ");
  dump(epubs,crypto_scalarmult_BYTES,"epubs ");
  if(infos) dump( (uint8_t*) infos, sizeof(Opaque_App_Infos), "infos ");
  else fprintf(stderr,"no infos\n");
#endif

  crypto_hash_sha256_update(&state, oprf1, crypto_core_ristretto255_BYTES);
  crypto_hash_sha256_update(&state, nonceU, OPAQUE_NONCE_BYTES);
  if(infos!=NULL && infos->info1!=NULL) crypto_hash_sha256_update(&state, infos->info1, infos->info1_len);
  crypto_hash_sha256_update(&state, epubu, crypto_scalarmult_BYTES);
  crypto_hash_sha256_update(&state, oprf2, crypto_core_ristretto255_BYTES);
  crypto_hash_sha256_update(&state, envu, envu_len);
  crypto_hash_sha256_update(&state, nonceS, OPAQUE_NONCE_BYTES);
  if(infos!=NULL && infos->info2!=NULL) crypto_hash_sha256_update(&state, infos->info2, infos->info2_len);
  crypto_hash_sha256_update(&state, epubs, crypto_scalarmult_BYTES);
  if(infos!=NULL) {
    if(infos->einfo2!=NULL) crypto_hash_sha256_update(&state, infos->einfo2, infos->einfo2_len);
    if(use_info3!=0) {
      if(infos->info3!=NULL) crypto_hash_sha256_update(&state, infos->info3, infos->info3_len);
      if(infos->einfo3!=NULL) crypto_hash_sha256_update(&state, infos->einfo3, infos->einfo3_len);
    }
  }

  // preserve xcript hash state for server so it does not have to
  // remember/recalc the xcript so far when authenticating the client
  if(xcript_state && (!infos || !(infos->einfo3 || infos->info3))) {
    memcpy(xcript_state, &state, sizeof state);
  }
  crypto_hash_sha256_final(&state, xcript);
#ifdef TRACE
  dump(xcript, crypto_hash_sha256_BYTES,"xcript ");
#endif
}

static void get_xcript_srv(uint8_t xcript[crypto_hash_sha256_BYTES],
                           uint8_t _sec[OPAQUE_SERVER_AUTH_CTX_LEN],
                           const Opaque_UserSession *pub,
                           const Opaque_ServerSession *resp,
                           const Opaque_App_Infos *infos) {

  Opaque_ServerAuthCTX *sec = (Opaque_ServerAuthCTX *)_sec;

  if(sec!=NULL)
    get_xcript(xcript, &sec->xcript_state, pub->M, pub->nonceU, pub->X_u, resp->Z, (uint8_t*) &resp->envU, resp->envU_len, resp->nonceS, resp->X_s, infos, 0);
  else
    get_xcript(xcript, NULL, pub->M, pub->nonceU, pub->X_u, resp->Z, (uint8_t*) &resp->envU, resp->envU_len, resp->nonceS, resp->X_s, infos, 0);
}

static void get_xcript_usr(uint8_t xcript[crypto_hash_sha256_BYTES],
                           const Opaque_UserSession_Secret *sec,
                           const Opaque_ServerSession *resp,
                           const uint8_t *env,
                           const uint8_t X_u[crypto_scalarmult_BYTES],
                           const Opaque_App_Infos *infos,
                           const int use_info3) {
  get_xcript(xcript, 0, sec->M, sec->nonceU, X_u, resp->Z, env, resp->envU_len, resp->nonceS, resp->X_s, infos, use_info3);
}

// implements server end of triple-dh
static int server_3dh(Opaque_Keys *keys,
               const uint8_t ix[crypto_scalarmult_SCALARBYTES],
               const uint8_t ex[crypto_scalarmult_SCALARBYTES],
               const uint8_t Ip[crypto_scalarmult_BYTES],
               const uint8_t Ep[crypto_scalarmult_BYTES],
               const char info[crypto_hash_sha256_BYTES]) {
  uint8_t sec[crypto_scalarmult_BYTES * 3], *ptr = sec;
  sodium_mlock(sec, sizeof sec);

  if(0!=crypto_scalarmult(ptr,ix,Ep)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ip)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ep)) return 1;
#ifdef TRACE
  dump(sec, 96, "sec");
#endif

  derive_keys(keys, sec, info);
#ifdef TRACE
  dump((uint8_t*) keys, sizeof(Opaque_Keys), "keys ");
#endif

  sodium_munlock(sec,sizeof(sec));
  return 0;
}

// implements user end of triple-dh
static int user_3dh(Opaque_Keys *keys,
             const uint8_t ix[crypto_scalarmult_SCALARBYTES],
             const uint8_t ex[crypto_scalarmult_SCALARBYTES],
             const uint8_t Ip[crypto_scalarmult_BYTES],
             const uint8_t Ep[crypto_scalarmult_BYTES],
             const char info[crypto_hash_sha256_BYTES]) {
  uint8_t sec[crypto_scalarmult_BYTES * 3], *ptr = sec;
  sodium_mlock(sec, sizeof sec);

  if(0!=crypto_scalarmult(ptr,ex,Ip)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ix,Ep)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ep)) return 1;
#ifdef TRACE
  dump(sec, 96, "sec");
#endif

  // and hash for the result SK = f_K(0)
  derive_keys(keys, sec, info);
#ifdef TRACE
  dump((uint8_t*) keys, sizeof(Opaque_Keys), "keys ");
#endif

  sodium_munlock(sec,sizeof(sec));
  return 0;
}

// enveloping function as specified in the ietf cfrg draft https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06#section-4
static int opaque_envelope(const uint8_t rwdU[crypto_secretbox_KEYBYTES],
                     const uint8_t *SecEnv, const size_t SecEnv_len,
                     const uint8_t *ClrEnv, const size_t ClrEnv_len,
                     uint8_t *envU, // must be of size: OPAQUE_ENVELOPE_META_LEN + SecEnv_len+ClrEnv_len
                                    // len(nonce|uint16|SecEnv|uint16|ClrEnv|hmacTag)
                     uint8_t export_key[crypto_hash_sha256_BYTES]) {
  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwdU || !envU) return 1;
  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envU + crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp,ClrEnv_len, &tmp)) return 1;
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv0 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv0 ");
#endif

  // (2) Set E = Nonce | ....
  randombytes(envU,crypto_hash_sha256_BYTES);

  if(__builtin_add_overflow(2*crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  char ctx[crypto_hash_sha256_BYTES+9];
  memcpy(ctx,envU,crypto_hash_sha256_BYTES);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  uint8_t pad[SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwdU);

  uint8_t *c = envU+crypto_hash_sha256_BYTES;

  if(SecEnv) {
    // set secenv_len prefix
    *((uint16_t*) c) = SecEnv_len;
    c+=2;

    //(1) Set C = SecEnv XOR PAD
    //(2) Set E = nonce | C | ...
    size_t i;
#ifdef TRACE
    dump(pad,SecEnv_len, "pad ");
    dump(c,SecEnv_len, "target ");
#endif
    for(i=0;i<SecEnv_len;i++) c[i]=SecEnv[i]^pad[i];
    c+=SecEnv_len;
  } else {
    *((uint16_t*) c) = 0;
    c+=2;
  }
  sodium_munlock(pad, sizeof pad);

  //(2) Set E = nonce | C | ClrEnv
  if(ClrEnv) {
    // set clrenv_len prefix
    *((uint16_t*) c) = ClrEnv_len;
    c+=2;
    memcpy(c, ClrEnv, ClrEnv_len);
    c+=ClrEnv_len;
  } else {
    *((uint16_t*) c) = 0;
    c+=2;
  }
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv1 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv1 ");
#endif

  // auth_key = HKDF-Expand(RwdU, concat(nonce, "AuthKey"), Nh)
  uint8_t auth_key[crypto_hash_sha256_BYTES];
  memcpy(ctx+crypto_hash_sha256_BYTES,"AuthKey",7);
  sodium_mlock(auth_key, sizeof auth_key);
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwdU);
  //(3) Set T = HMAC(E,auth_key)
  const size_t envU_len=crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t);
#ifdef TRACE
  dump(envU,envU_len,"envU auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
#endif
  crypto_auth_hmacsha256(envU + envU_len, // out
                         envU,            // in
                         envU_len,        // len(in)
                         auth_key);       // key
  sodium_munlock(auth_key, sizeof auth_key);
#ifdef TRACE
  dump(envU+envU_len, crypto_hash_sha256_BYTES, "auth tag ");
  dump(envU,crypto_hash_sha256_BYTES*2+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t), "envU ");
#endif

  if(export_key) {
    // export_key = HKDF-Expand(RwdU, concat(nonce, "ExportKey"), Nh)
    memcpy(ctx+crypto_hash_sha256_BYTES,"ExportKey",9);
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwdU);
#ifdef TRACE
    dump(export_key,crypto_hash_sha256_BYTES, "export_key ");
#endif
  }

  return 0;
}

static int opaque_envelope_open(const uint8_t rwdU[crypto_secretbox_KEYBYTES], const uint8_t *envU, const size_t envU_len,
                         uint8_t *SecEnv, uint16_t *SecEnv_len,
                         uint8_t **ClrEnv, uint16_t *ClrEnv_len,
                         uint8_t export_key[crypto_hash_sha256_BYTES]) {

  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwdU || !envU || envU_len < 2*crypto_hash_sha256_BYTES+2*sizeof(uint16_t)) return 1;

#ifdef TRACE
  dump(envU,envU_len, "open envU ");
#endif

  // (1) verify authentication tag on the envelope
  // auth_key = HKDF-Expand(RwdU, concat(nonce, "AuthKey"), Nh)
  char ctx[crypto_hash_sha256_BYTES+9]; // reused also for pad and export key, hence bigger than needed
  memcpy(ctx,envU,crypto_hash_sha256_BYTES);

  uint8_t auth_key[crypto_hash_sha256_BYTES];
  sodium_mlock(auth_key, sizeof auth_key);
  memcpy(ctx+crypto_hash_sha256_BYTES,"AuthKey",7);
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwdU);

  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envU - crypto_hash_sha256_BYTES,envU_len, &tmp)) return 1;

#ifdef TRACE
  dump(envU,envU_len-crypto_hash_sha256_BYTES,"envU auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
  dump((uint8_t*) tmp,crypto_hash_sha256_BYTES, "auth tag ");
#endif
  if(-1 == crypto_auth_hmacsha256_verify((uint8_t*) tmp,                    // tag
                                         envU,                              // in
                                         envU_len-crypto_hash_sha256_BYTES, // inlen
                                         auth_key)) {
    sodium_munlock(auth_key, sizeof auth_key);
    return 1;
  }
  sodium_munlock(auth_key, sizeof auth_key);

  // parse envelope for *envU_len fields
  const uint8_t *ptr = envU+crypto_hash_sha256_BYTES;
  uint16_t sl,cl;
  sl = *((uint16_t*) ptr);
  ptr += 2 + sl;
  cl = *((uint16_t*) (ptr));
  *SecEnv_len=sl;
  *ClrEnv_len=cl;
#ifdef TRACE
  fprintf(stderr,"SecEnv_len: %d\nClrEnv_len: %d\n", sl, cl);
#endif
  // sanity check the two lengths, already authenticated by the hmac above, but make sure the sender is not some joker
  if(envU_len != sl + cl + 2*sizeof(uint16_t) + 2*crypto_hash_sha256_BYTES) return 1;
  if(__builtin_add_overflow((uintptr_t) envU + crypto_hash_sha256_BYTES+sizeof(uint16_t),*SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp+sizeof(uint16_t),*ClrEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  uint8_t pad[*SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwdU);
#ifdef TRACE
  dump(pad,sizeof pad, "pad ");
#endif

  const uint8_t *c = envU+crypto_hash_sha256_BYTES+sizeof(uint16_t);
  // decrypt SecEnv
  if(SecEnv) {
    size_t i;
    for(i=0;i<*SecEnv_len;i++) SecEnv[i]=c[i]^pad[i];
    c+=*SecEnv_len;
  }
  sodium_munlock(pad, sizeof pad);

  // return ClrEnv
  c+=sizeof(uint16_t);
  if (ClrEnv) *ClrEnv=(uint8_t*)c;
#ifdef TRACE
  dump(SecEnv,*SecEnv_len, "SecEnv ");
  dump(*ClrEnv,*ClrEnv_len, "ClrEnv ");
#endif

  if(export_key) {
    // export_key = HKDF-Expand(RwdU, concat(nonce, "ExportKey"), Nh)
    memcpy(ctx+crypto_hash_sha256_BYTES,"ExportKey",9);
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwdU);
#ifdef TRACE
    dump(export_key,crypto_hash_sha256_BYTES, "export_key ");
#endif
  }
  return 0;
}

size_t opaque_package_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, const Opaque_PkgTarget type) {
  size_t res=0;
  if(cfg->skU==type) res+=crypto_scalarmult_SCALARBYTES+3;
  if(cfg->pkU==type) res+=crypto_scalarmult_BYTES+3;
  if(cfg->pkS==type) res+=crypto_scalarmult_BYTES+3;
  if(cfg->idU==type) res+=ids->idU_len+3;
  if(cfg->idS==type) res+=ids->idS_len+3;
  return res;
}

size_t opaque_envelope_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids) {
  const uint16_t ClrEnv_len = opaque_package_len(cfg, ids, InClrEnv);
  const uint16_t SecEnv_len = opaque_package_len(cfg, ids, InSecEnv);
  return OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
}

static int extend_package(const uint8_t *src, const size_t src_len, const Opaque_PkgTarget ptype, const CredentialType type, uint8_t **SecEnv, uint8_t **ClrEnv) {
  if(ptype==NotPackaged) return 0;
  if(src_len>=(1<<16)) return 1;
  uint8_t **target_ptr;
  if(ptype==InSecEnv) target_ptr=SecEnv;
  else if(ptype==InClrEnv) target_ptr=ClrEnv;
  else if(ptype==NotPackaged) return 0;
  else return 1;

  CredentialExtension *target = (CredentialExtension*) *target_ptr;
  target->type = type;
  target->size=src_len;
  memcpy(&target->data, src, src_len);
  *target_ptr+=src_len+3;

  return 0;
}

// pack: serialize to envelope
// takes skU, pkU, pkS, idU, idS and puts them into SecEnv or ClrEnv according to configuration
static int pack(const Opaque_PkgConfig *cfg, const Opaque_Credentials *cred, const Opaque_Ids *ids, uint8_t *SecEnv, uint8_t *ClrEnv) {
  uint8_t *senv = SecEnv, *cenv = ClrEnv;
  if(cfg->skU==InClrEnv || 0!=extend_package(cred->skU, crypto_scalarmult_SCALARBYTES, cfg->skU, skU, &senv, &cenv)) return 1;
  if(0!=extend_package(cred->pkU, crypto_scalarmult_BYTES, cfg->pkU, pkU, &senv, &cenv)) return 1;
  if(0!=extend_package(cred->pkS, crypto_scalarmult_BYTES, cfg->pkS, pkS, &senv, &cenv)) return 1;
  if(0!=extend_package(ids->idU, ids->idU_len, cfg->idU, idU, &senv, &cenv)) return 1;
  if(0!=extend_package(ids->idS, ids->idS_len, cfg->idS, idS, &senv, &cenv)) return 1;
  return 0;
}

static int extract_credential(const Opaque_PkgConfig *cfg, const Opaque_PkgTarget current_target, const CredentialExtension *cred, uint8_t *seen, Opaque_Credentials *creds, Opaque_Ids *ids) {
  // only allow each type to be seen once
  if(*seen & (1 << (cred->type - 1))) return 1;

  // validate that the cred is in the correct part of the envelope
  switch(cred->type) {
  case skU: {
    if(InSecEnv!=current_target) return 1;
    if(cred->size!=crypto_scalarmult_SCALARBYTES) return 1;
    memcpy(&creds->skU, &cred->data, crypto_scalarmult_SCALARBYTES);
    break;
  };
  case pkU: {
    if(cfg->pkU!=current_target) return 1;
    if(cred->size!=crypto_scalarmult_BYTES) return 1;
    memcpy(&creds->pkU, &cred->data, crypto_scalarmult_BYTES);
    break;
  };
  case pkS: {
    if(cfg->pkS!=current_target) return 1;
    if(cred->size!=crypto_scalarmult_BYTES) return 1;
    memcpy(&creds->pkS, &cred->data, crypto_scalarmult_BYTES);
    break;
  };
  case idU: {
    if(cfg->idU!=current_target) return 1;
    if(ids->idU_len < cred->size) return 1;
    memcpy(ids->idU, &cred->data, cred->size);
    ids->idU_len = cred->size;
    break;
  };
  case idS: {
    if(cfg->idS!=current_target) return 1;
    if(ids->idS_len < cred->size) return 1;
    memcpy(ids->idS, &cred->data, cred->size);
    ids->idS_len = cred->size;
    break;
  };
  default: return 1;
  }

  *seen|=(1 << (cred->type - 1));

  return 0;
}

static int unpack(const Opaque_PkgConfig *cfg, const uint8_t *SecEnv, const uint16_t SecEnv_len, const uint8_t *ClrEnv, const uint16_t ClrEnv_len, const uint8_t rwdU[crypto_secretbox_KEYBYTES], Opaque_Credentials *creds, Opaque_Ids *ids) {
  const uint8_t *ptr;
  uint8_t seen=0;
  const CredentialExtension* cred;
  // parse SecEnv
  for(ptr=SecEnv;
      ptr<SecEnv+SecEnv_len;
      ptr+=cred->size + 3) {
    cred = (const CredentialExtension*) ptr;
    extract_credential(cfg, InSecEnv, cred, &seen, creds, ids);
  }
  // parse ClrEnv
  for(ptr=ClrEnv;
      ptr<ClrEnv+ClrEnv_len;
      ptr+=cred->size + 3) {
    cred = (const CredentialExtension*) ptr;
    extract_credential(cfg, InClrEnv, cred, &seen, creds, ids);
  }
  // skU might not be packaged according to the rfc draft. In this case
  // rwdU is used to derive a seed for the keygen - which for 25519 is
  // a null op and we use directly the seed as the secret key
  // HKDF-Expand(KdKey; info="KG seed", L)
  if(cfg->skU == NotPackaged) {
    if(seen & (1 << (skU-1))) return 1; // skU was packaged in the envelope
    crypto_kdf_hkdf_sha256_expand(creds->skU, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rwdU);
    seen|=(1 << (skU - 1));
  }

  // recalculate non-packaged pkU
  if(cfg->pkU == NotPackaged) {
    if(!(seen & (1 << (skU-1)))) return 1;
    crypto_scalarmult_base(creds->pkU, creds->skU);
    seen|=(1 << (pkU - 1));
  }

  if(seen!=( 3 | ((!!cfg->pkS) << 2) | ((!!cfg->idU) << 3) | ((!!cfg->idS) << 4) )) {
#ifdef TRACE
    fprintf(stderr, "seen: %x, expected: %x\n", seen, (3 | ((!!cfg->pkS) << 2) | ((!!cfg->idU) << 3) | ((!!cfg->idS) << 4)));
#endif
      return 1;
    }
  return 0;
}

// (StorePwdFile, sid , U, pw): S computes k_s ←_R Z_q , rw := F_k_s (pw),
// p_s ←_R Z_q , p_u ←_R Z_q , P_s := g^p_s , P_u := g^p_u , c ← AuthEnc_rw (p_u, P_u, P_s);
// it records file[sid] := {k_s, p_s, P_s, P_u, c}.
int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len,
                    const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                    const Opaque_PkgConfig *cfg,
                    const Opaque_Ids *ids,
                    uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
                    uint8_t export_key[crypto_hash_sha256_BYTES]) {
  Opaque_UserRecord *rec = (Opaque_UserRecord *)_rec;

  const uint16_t ClrEnv_len = opaque_package_len(cfg, ids, InClrEnv);
  const uint16_t SecEnv_len = opaque_package_len(cfg, ids, InSecEnv);
  const uint32_t envU_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump((uint8_t*) cfg,2, "cfg ");
  fprintf(stderr, "cfg skU: %d, pkU:%d, pkS:%d, idU:%d, idS:%d\n", cfg->skU, cfg->pkU, cfg->pkS, cfg->idU, cfg->idS);
  dump(ids->idU, ids->idU_len,"idU ");
  dump(ids->idS, ids->idS_len,"idS ");
  fprintf(stderr,"clrenv_len: %d\n", ClrEnv_len);
  fprintf(stderr,"secenv_len: %d\n", SecEnv_len);
  fprintf(stderr,"envU_len: %d\n", envU_len);
  fprintf(stderr,"rec_len: %ld\n", OPAQUE_USER_RECORD_LEN+envU_len);
  memset(_rec,0,OPAQUE_USER_RECORD_LEN+envU_len);
#endif

  // k_s ←_R Z_q
  // 1. (kU, _) = KeyGen()
#ifdef VOPRF_TEST_VEC_1
  unsigned char rtest[] = {
    0x86, 0xbd, 0x5e, 0xea, 0xbf, 0x29, 0xa8, 0x7c, 0xb4, 0xa5, 0xc7, 0x20,
    0x7c, 0xb3, 0xad, 0xe5, 0x29, 0x7e, 0x65, 0xf9, 0xb7, 0x4c, 0x97, 0x9b,
    0xd3, 0x55, 0x18, 0x91, 0xf4, 0xb2, 0x15, 0x15
  };
  unsigned int rtest_len = 32;
  memcpy(rec->kU,rtest,rtest_len);
#elif VOPRF_TEST_VEC_2
  unsigned char rtest[] = {
    0x06, 0x3b, 0x91, 0xa1, 0x2e, 0x7c, 0xbb, 0x98, 0xdf, 0xeb, 0x75, 0xd8,
    0xa7, 0xee, 0xb8, 0x3a, 0xac, 0xf9, 0xfd, 0x6d, 0xf7, 0xe0, 0xb4, 0x19,
    0x74, 0x66, 0xfb, 0x77, 0xa2, 0x7f, 0xa6, 0x31
  };
  unsigned int rtest_len = 32;
  memcpy(rec->kU,rtest,rtest_len);
#else
  oprf_KeyGen(rec->kU);
#endif
#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "kU\nplain user rec ");
#endif

  // rw := F_k_s (pw),
  uint8_t rwdU[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rwdU,sizeof rwdU)) {
    return -1;
  }
  if(prf(pwdU, pwdU_len, rec->kU, rwdU)!=0) {
    sodium_munlock(rwdU,sizeof rwdU);
    return -1;
  }

  // p_s ←_R Z_q
  if(skS==NULL) {
    randombytes(rec->skS, crypto_scalarmult_SCALARBYTES); // random server secret key
  } else {
    memcpy(rec->skS, skS, crypto_scalarmult_SCALARBYTES);
  }

#ifdef TRACE
  dump(rec->skS, crypto_scalarmult_SCALARBYTES, "skS ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "plain user rec ");
#endif
  Opaque_Credentials cred;
  sodium_mlock(&cred, sizeof cred);
  // p_u ←_R Z_q
  if(cfg->skU != NotPackaged) {
    randombytes(cred.skU, crypto_scalarmult_SCALARBYTES); // random user secret key
  } else {
    crypto_kdf_hkdf_sha256_expand(cred.skU, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rwdU);
  }

#ifdef TRACE
  dump(cred.skU, crypto_core_ristretto255_SCALARBYTES, "skU ");
#endif
  // P_s := g^p_s
  crypto_scalarmult_base(rec->pkS, rec->skS);

#ifdef TRACE
  dump(rec->pkS, crypto_scalarmult_BYTES, "pkS ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "plain user rec ");
#endif
  // P_u := g^p_u
  crypto_scalarmult_base(rec->pkU, cred.skU);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "pkU\nplain user rec ");
#endif
  // copy Pubkeys also into rec.c
  memcpy(cred.pkU, rec->pkU,crypto_scalarmult_BYTES*2);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "pk[US] -> c\nplain user rec ");
#endif

  // package up credential for the envelope
  uint8_t SecEnv[SecEnv_len], ClrEnv[ClrEnv_len];

  if(0!=pack(cfg, &cred, ids, SecEnv, ClrEnv)) {
    sodium_munlock(&cred, sizeof cred);
    return -1;
  }
  sodium_munlock(&cred, sizeof cred);
  // c ← AuthEnc_rw(p_u,P_u,P_s);
  if(0!=opaque_envelope(rwdU, SecEnv_len ? SecEnv : NULL, SecEnv_len, ClrEnv_len ? ClrEnv : NULL, ClrEnv_len, rec->envU, export_key)) {
    return -1;
  }
  rec->envU_len = envU_len;

  sodium_munlock(rwdU, sizeof(rwdU));

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "cipher user rec ");
#endif
  return 0;
}

//(UsrSession, sid , ssid , S, pw): U picks r, x_u ←_R Z_q ; sets α := (H^0(pw))^r and
//X_u := g^x_u ; sends α and X_u to S.
// more or less corresponds to CreateCredentialRequest in the ietf draft
int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/], uint8_t _pub[OPAQUE_USER_SESSION_PUBLIC_LEN]) {
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret*) _sec;
  Opaque_UserSession *pub = (Opaque_UserSession*) _pub;
#ifdef TRACE
  memset(_sec, 0, OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len);
  memset(_pub, 0, OPAQUE_USER_SESSION_PUBLIC_LEN);
#endif

  // 1. (blind, M) = Blind(pwdU)
  if(0!=oprf_Blind(pwdU, pwdU_len, sec->blind, pub->M)) return -1;
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
  memcpy(sec->M, pub->M, crypto_core_ristretto255_BYTES);

  // x_u ←_R Z_q
  randombytes(sec->x_u, crypto_scalarmult_SCALARBYTES);

  // nonceU
  randombytes(sec->nonceU, OPAQUE_NONCE_BYTES);
  memcpy(pub->nonceU, sec->nonceU, OPAQUE_NONCE_BYTES);

  // X_u := g^x_u
  crypto_scalarmult_base(pub->X_u, sec->x_u);

  sec->pwdU_len = pwdU_len;
  memcpy(sec->pwdU, pwdU, pwdU_len);

#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
  return 0;
}

// more or less corresponds to CreateCredentialResponse in the ietf draft
// 2. (SvrSession, sid , ssid ): On input α from U, S proceeds as follows:
// (a) Checks that α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
// (c) Picks x_s ←_R Z_q and computes β := α^k_s and X_s := g^x_s ;
// (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f K (0);
// (e) Sends β, X s and c to U;
// (f) Outputs (sid , ssid , SK).
int opaque_CreateCredentialResponse(const uint8_t _pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t _resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], uint8_t sk[OPAQUE_SHARED_SECRETBYTES],  uint8_t _sec[OPAQUE_SERVER_AUTH_CTX_LEN]) {

  Opaque_ServerAuthCTX *sec = (Opaque_ServerAuthCTX *)_sec;
  Opaque_UserSession *pub = (Opaque_UserSession *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;

  memset(_sec, 0, sizeof(Opaque_ServerAuthCTX));
#ifdef TRACE
  dump(_pub, sizeof(Opaque_UserSession), "session srv pub ");
  dump(_rec, OPAQUE_USER_SESSION_PUBLIC_LEN, "session srv rec ");
#endif

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(pub->M)!=1) return -1;

  // (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
  // provided as parameter rec

  // (c) Picks x_s ←_R Z_q
  uint8_t x_s[crypto_scalarmult_SCALARBYTES];
  if(-1==sodium_mlock(x_s,sizeof x_s)) return -1;
  randombytes(x_s, crypto_scalarmult_SCALARBYTES);
#ifdef TRACE
  dump(x_s, sizeof(x_s), "session srv x_s ");
#endif

#ifdef TRACE
  dump(rec->kU, sizeof(rec->kU), "session srv kU ");
  dump(pub->M, sizeof(pub->M), "session srv M ");
#endif

  // computes β := α^k_s
  // 1. Z = Evaluate(DeserializeScalar(credentialFile.kU), request.data)
  if (oprf_Evaluate(rec->kU, pub->M, resp->Z) != 0) {
    sodium_munlock(x_s, sizeof x_s);
    return -1;
  }

  // X_s := g^x_s;
  crypto_scalarmult_base(resp->X_s, x_s);
#ifdef TRACE
  dump(resp->X_s, sizeof(resp->X_s), "session srv X_s ");
#endif

  // nonceS
  randombytes(resp->nonceS, OPAQUE_NONCE_BYTES);

  // mixing in things from the ietf cfrg spec
  char info[crypto_hash_sha256_BYTES];
  calc_info(info, pub->nonceU, resp->nonceS, ids);
  Opaque_Keys keys;
  sodium_mlock(&keys,sizeof(keys));

  // (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f_K(0);
  // paper instantiates HMQV, we do only triple-dh
#ifdef TRACE
  dump(rec->skS,crypto_scalarmult_SCALARBYTES, "rec->skS ");
  dump(x_s,crypto_scalarmult_SCALARBYTES, "x_s ");
  dump(rec->pkU,crypto_scalarmult_BYTES, "rec->pkU ");
  dump(pub->X_u,crypto_scalarmult_BYTES, "pub->X_u ");
#endif
  if(0!=server_3dh(&keys, rec->skS, x_s, rec->pkU, pub->X_u, info)) {
    sodium_munlock(x_s, sizeof(x_s));
    sodium_munlock(&keys,sizeof(keys));
    return -1;
  }
  sodium_munlock(x_s, sizeof(x_s));
#ifdef TRACE
  dump(keys.sk, sizeof(keys.sk), "session srv sk ");
  dump(keys.km3,crypto_auth_hmacsha256_KEYBYTES,"session srv km3 ");
#endif

  // (e) Sends β, X_s and c to U;
  memcpy(&resp->envU, &rec->envU, rec->envU_len);
  memcpy(&resp->envU_len, &rec->envU_len, sizeof rec->envU_len);

  // Mac(Km2; xcript2) - from the ietf cfrg draft
  uint8_t xcript[crypto_hash_sha256_BYTES];
  get_xcript_srv(xcript, _sec, pub, resp, infos);
  crypto_auth_hmacsha256(resp->auth,                          // out
                         xcript,                              // in
                         crypto_hash_sha256_BYTES,            // len(in)
                         keys.km2);                           // key
#ifdef TRACE
  dump(resp->auth, sizeof resp->auth, "resp->auth ");
  dump(keys.km2, sizeof keys.km2, "km2 ");
#endif

  memcpy(sk,keys.sk,sizeof(keys.sk));
  if(sec!=NULL) memcpy(sec->km3,keys.km3,sizeof(keys.km3));
  sodium_munlock(&keys,sizeof(keys));

#ifdef TRACE
  dump(resp->auth, sizeof(resp->auth), "session srv auth ");
#endif

  // (f) Outputs (sid , ssid , SK).
  // e&f handled as parameters

#ifdef TRACE
  dump(_resp,OPAQUE_SERVER_SESSION_LEN, "session srv resp ");
#endif

  return 0;
}

// more or less corresponds to RecoverCredentials in the ietf draft
// 3. On β, X_s and c from S, U proceeds as follows:
// (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
// (b) Computes rw := H(key, pw|β^1/r );
// (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
//     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
// (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
// (e) Outputs (sid, ssid, SK).
int opaque_RecoverCredentials(const uint8_t _resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
                              const uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
                              const uint8_t pkS[crypto_scalarmult_BYTES],
                              const Opaque_PkgConfig *cfg,
                              const Opaque_App_Infos *infos,
                              Opaque_Ids *ids,
                              uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
                              uint8_t authU[crypto_auth_hmacsha256_BYTES],
                              uint8_t export_key[crypto_hash_sha256_BYTES]) {
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret *) _sec;

#ifdef TRACE
  dump(sec->pwdU,sec->pwdU_len, "session user finish pwdU ");
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "session user finish sec ");
  dump(_resp,OPAQUE_SERVER_SESSION_LEN, "session user finish resp ");
#endif

  uint8_t N[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(N, sizeof N)) return -1;
  // 1. N = Unblind(blind, response.data)
  if(0!=oprf_Unblind(sec->blind, resp->Z, N)) {
    sodium_munlock(N, sizeof N);
    return -1;
  }

  // rw = H(pw, β^(1/r))
  uint8_t rwdU[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rwdU,sizeof rwdU)) {
    sodium_munlock(N, sizeof N);
    return -1;
  }
  // 2. y = Finalize(pwdU, N, "OPAQUE01")
  if(0!=oprf_Finalize(sec->pwdU, sec->pwdU_len, N, OPAQUE_FINALIZE_INFO, OPAQUE_FINALIZE_INFO_LEN, rwdU)) {
    sodium_munlock(N, sizeof N);
    sodium_munlock(rwdU,sizeof rwdU);
    return -1;
  }
  sodium_munlock(N,sizeof N);

  // (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
  //     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
  if(resp->envU_len > OPAQUE_ENVELOPE_META_LEN + ((1<<17) - 2)  ) {
    sodium_munlock(rwdU, sizeof rwdU);
    return -1; // avoid integer overflow in next line
  }
  uint8_t *ClrEnv, env[resp->envU_len], SecEnv[resp->envU_len];
  uint16_t ClrEnv_len, SecEnv_len;
  // preserve envelope for later transcript calculation
  memcpy(env, &resp->envU, resp->envU_len);
  if(0!=opaque_envelope_open(rwdU, resp->envU, resp->envU_len, SecEnv, &SecEnv_len, &ClrEnv, &ClrEnv_len, export_key)) {
    sodium_munlock(rwdU, sizeof(rwdU));
    return -1;
  }

  Opaque_Credentials cred={0};
  sodium_mlock(&cred,sizeof cred);
  if(0!=unpack(cfg, SecEnv, SecEnv_len, ClrEnv, ClrEnv_len, rwdU, &cred, ids)) {
    sodium_munlock(&cred,sizeof cred);
    return -1;
  }

  if(cfg->pkS==NotPackaged && pkS!=NULL) {
    memcpy(cred.pkS, pkS, crypto_scalarmult_BYTES);
  } else if ((cfg->pkS==NotPackaged) ^ (pkS!=NULL)) {
    return -1;
  }

#ifdef TRACE
  dump((uint8_t*)&cred, sizeof cred, "unpacked cred ");
#endif

  sodium_munlock(rwdU, sizeof(rwdU));

  // mixing in things from the ietf cfrg spec
  char hkdf_info[crypto_hash_sha256_BYTES];
  calc_info(hkdf_info, sec->nonceU, resp->nonceS, ids);
  Opaque_Keys keys;
  sodium_mlock(&keys,sizeof(keys));

  // (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
#ifdef TRACE
  dump(cred.skU,crypto_scalarmult_SCALARBYTES, "c->skU ");
  dump(sec->x_u,crypto_scalarmult_SCALARBYTES, "sec->x_u ");
  dump(cred.pkS,crypto_scalarmult_BYTES, "c->pkS ");
  dump(resp->X_s,crypto_scalarmult_BYTES, "sec->X_s ");
#endif
  if(0!=user_3dh(&keys, cred.skU, sec->x_u, cred.pkS, resp->X_s, hkdf_info)) {
    sodium_munlock(&keys, sizeof(keys));
    sodium_munlock(&cred, sizeof cred);
    return -1;
  }
  sodium_munlock(&cred, sizeof cred);

  uint8_t xcript[crypto_hash_sha256_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
  crypto_scalarmult_base(X_u, sec->x_u);
  get_xcript_usr(xcript, sec, resp, env, X_u, infos, 0);
#ifdef TRACE
  dump(resp->auth, sizeof resp->auth, "resp->auth ");
  dump(keys.km2, sizeof keys.km2, "km2 ");
#endif
  if(0!=crypto_auth_hmacsha256_verify(resp->auth, xcript, crypto_hash_sha256_BYTES, keys.km2)) {
    sodium_munlock(&keys, sizeof(keys));
    return -1;
  }

  memcpy(sk,keys.sk,sizeof(keys.sk));
#ifdef TRACE
  dump(keys.km3,crypto_auth_hmacsha256_KEYBYTES,"session user finish km3 ");
#endif

  if(authU) {
    get_xcript_usr(xcript, sec, resp, env, X_u, infos, 1);
    crypto_auth_hmacsha256(authU, xcript, crypto_hash_sha256_BYTES, keys.km3);
#ifdef TRACE
  dump(xcript, crypto_hash_sha256_BYTES, "session user finish xcript ");
  if(infos)
    dump((uint8_t*) infos, sizeof(Opaque_App_Infos), "session user finish infos ");
  dump(authU,crypto_auth_hmacsha256_BYTES, "session user finish authU ");
#endif
  }

  sodium_munlock(&keys, sizeof(keys));

  // (e) Outputs (sid, ssid, SK).
  return 0;
}

// extra function to implement the hmac based auth as defined in the ietf cfrg draft
int opaque_UserAuth(const uint8_t _sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos) {
  if(_sec==NULL) return 1;
  Opaque_ServerAuthCTX *sec = (Opaque_ServerAuthCTX *)_sec;

  if(infos!=NULL) {
    if(infos->info3!=NULL) crypto_hash_sha256_update(&sec->xcript_state, infos->info3, infos->info3_len);
    if(infos->einfo3!=NULL) crypto_hash_sha256_update(&sec->xcript_state, infos->einfo3, infos->einfo3_len);
  }
  uint8_t xcript[crypto_hash_sha256_BYTES];
  crypto_hash_sha256_final(&sec->xcript_state, xcript);
#ifdef TRACE
  dump(sec->km3,crypto_auth_hmacsha256_KEYBYTES,"km3 ");
  dump(xcript, crypto_hash_sha256_BYTES, "xcript ");
  if(infos)
    dump((uint8_t*)infos, sizeof(Opaque_App_Infos), "infos ");
  dump(authU,crypto_auth_hmacsha256_BYTES, "authU ");
#endif
  return crypto_auth_hmacsha256_verify(authU, xcript, crypto_hash_sha256_BYTES, sec->km3);
}

// variant where the secrets of U never touch S unencrypted

// U computes: blinded PW
// called CreateRegistrationRequest in the ietf cfrg rfc draft
int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t _sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t M[crypto_core_ristretto255_BYTES]) {
  Opaque_RegisterUserSec *sec = (Opaque_RegisterUserSec *) _sec;
  memcpy(&sec->pwdU, pwdU, pwdU_len);
  sec->pwdU_len = pwdU_len;
  // 1. (blind, M) = Blind(pwdU)
  return oprf_Blind(pwdU, pwdU_len, sec->blind, M);
}

// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
// called CreateRegistrationResponse in the ietf cfrg rfc draft
int opaque_CreateRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  // p_s ←_R Z_q
  randombytes(sec->skS, crypto_scalarmult_SCALARBYTES); // random server long-term key
#ifdef TRACE
  dump((uint8_t*) sec->skS, sizeof sec->skS, "skS ");
#endif
  uint8_t pkS[crypto_scalarmult_BYTES];
  if(-1==sodium_mlock(pkS, sizeof pkS)) return -1;
  // P_s := g^p_s
  crypto_scalarmult_base(pkS, sec->skS);
  int result = opaque_Create1kRegistrationResponse(M, pkS, _sec, _pub);
  sodium_munlock(pkS, sizeof pkS);
  return result;
}

// same function as opaque_CreateRegistrationResponse() but does not generate a long-term server keypair
// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
// called CreateRegistrationResponse in the ietf cfrg rfc draft
int opaque_Create1kRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_RegisterSrvPub *pub = (Opaque_RegisterSrvPub *) _pub;

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(M)!=1) return -1;

  // k_s ←_R Z_q
  // 1. (kU, _) = KeyGen()
  oprf_KeyGen(sec->kU);

  // computes β := α^k_s
  // 2. Z = Evaluate(kU, request.data)
  if (oprf_Evaluate(sec->kU, M, pub->Z) != 0) {
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) pub->Z, sizeof pub->Z, "Z ");
#endif

  memcpy(pub->pkS, pkS, crypto_scalarmult_BYTES);
#ifdef TRACE
  dump((uint8_t*) pub->pkS, sizeof pub->pkS, "pkS ");
#endif

  return 0;
}

// user computes:
// (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
// (b) Computes rw := H(key, pw | β^1/r );
// (c) p_u ←_R Z_q
// (d) P_u := g^p_u,
// (e) c ← AuthEnc_rw (p_u, P_u, P_s);
// called FinalizeRequest in the ietf cfrg rfc draft
int opaque_FinalizeRequest(const uint8_t _sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/],
                                    const uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN],
                                    const Opaque_PkgConfig *cfg,
                                    const Opaque_Ids *ids,
                                    uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
                                    uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_RegisterUserSec *sec = (Opaque_RegisterUserSec *) _sec;
  Opaque_RegisterSrvPub *pub = (Opaque_RegisterSrvPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  const uint16_t ClrEnv_len = opaque_package_len(cfg, ids, InClrEnv);
  const uint16_t SecEnv_len = opaque_package_len(cfg, ids, InSecEnv);

#ifdef TRACE
  const uint32_t envU_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
  memset(_rec,0,OPAQUE_USER_RECORD_LEN+envU_len);
#endif

  uint8_t N[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(N, sizeof N)) return -1;
  // 1. N = Unblind(blind, response.data)
  if(0!=oprf_Unblind(sec->blind, pub->Z, N)) {
    sodium_munlock(N, sizeof N);
    return -1;
  }

  uint8_t rwdU[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rwdU, sizeof rwdU)) {
    sodium_munlock(N, sizeof N);
    return -1;
  }
  // 2. y = Finalize(pwdU, N, "OPAQUE01")
  if(0!=oprf_Finalize(sec->pwdU, sec->pwdU_len, N, OPAQUE_FINALIZE_INFO, OPAQUE_FINALIZE_INFO_LEN, rwdU)) {
    sodium_munlock(N, sizeof N);
    sodium_munlock(rwdU, sizeof(rwdU));
    return -1;
  }
  sodium_munlock(N,sizeof N);

  Opaque_Credentials cred;
  sodium_mlock(&cred, sizeof cred);
  // p_u ←_R Z_q
  if(cfg->skU != NotPackaged) {
    randombytes(cred.skU, crypto_scalarmult_SCALARBYTES); // random user secret key
  } else {
    crypto_kdf_hkdf_sha256_expand(cred.skU, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rwdU);
  }

  // P_u := g^p_u
  crypto_scalarmult_base(cred.pkU, cred.skU);

  // copy P_u also into plaintext rec
  memcpy(rec->pkU, cred.pkU,crypto_scalarmult_BYTES);

  // copy P_s into rec.c
  memcpy(cred.pkS, pub->pkS,crypto_scalarmult_BYTES);

  // c ← AuthEnc_rw(p_u,P_u,P_s);
#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+envU_len, "plain user rec ");
#endif

  // package up credential for the envelope
  uint8_t SecEnv[SecEnv_len], ClrEnv[ClrEnv_len];

  if(0!=pack(cfg, &cred, ids, SecEnv, ClrEnv)) {
    sodium_munlock(&cred, sizeof cred);
    return -1;
  }
  sodium_munlock(&cred, sizeof cred);
  if(0!=opaque_envelope(rwdU, SecEnv_len ? SecEnv : NULL, SecEnv_len, ClrEnv_len ? ClrEnv : NULL, ClrEnv_len, rec->envU, export_key)) {
    return -1;
  }
  rec->envU_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN, "cipher user rec ");
#endif

  sodium_munlock(rwdU, sizeof(rwdU));

  return 0;
}

// S records file[sid ] := {k_s, p_s, P_s, P_u, c}.
// called StoreUserRecord in the ietf cfrg rfc draft
void opaque_StoreUserRecord(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  return opaque_Store1kUserRecord(_sec, sec->skS, _rec);
}

void opaque_Store1kUserRecord(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES], uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  memcpy(rec->kU, sec->kU, sizeof rec->kU);
  memcpy(rec->skS, skS, crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult_base(rec->pkS, skS);
#ifdef TRACE
  dump((uint8_t*) rec, OPAQUE_USER_RECORD_LEN, "user rec ");
#endif
}
