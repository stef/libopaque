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
#include "common.h"
#include <arpa/inet.h>

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

typedef struct {
  uint8_t p_u[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_Credentials;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
  uint32_t env_len;
  uint8_t envelope[];
} __attribute((packed)) Opaque_UserRecord;

typedef struct {
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t x_u[crypto_scalarmult_SCALARBYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint16_t pwdU_len;
  uint8_t pwdU[];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t X_s[crypto_scalarmult_BYTES];
  uint8_t nonceS[OPAQUE_NONCE_BYTES];
  uint8_t auth[crypto_auth_hmacsha256_BYTES];
  uint32_t env_len;
  uint8_t envelope[];
} __attribute((packed)) Opaque_ServerSession;

typedef struct {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint16_t pwdU_len;
  uint8_t pwdU[];
} Opaque_RegisterUserSec;

typedef struct {
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_RegisterSrvPub;

typedef struct {
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
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

static int prf_finalize(const uint8_t *pwdU, const uint16_t pwdU_len,
                        const uint8_t *key, const uint16_t key_len,
                        const uint8_t ue[crypto_core_ristretto255_BYTES], uint8_t result[crypto_hash_sha512_BYTES]) {
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
  uint16_t size=htons(pwdU_len);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, pwdU, pwdU_len);
  // H0_k
  size=htons(crypto_core_ristretto255_BYTES);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, ue, crypto_core_ristretto255_BYTES);
  // info
  if(key!=NULL && key_len>0) {
    size=htons(key_len);
    crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
    crypto_hash_sha512_update(&state, key, key_len);
  }
  const uint8_t DST[]="VOPRF06-Finalize-OPAQUE00";
  const uint8_t DST_size=strlen((const char*) DST);
  size=htons(DST_size);
  crypto_hash_sha512_update(&state, (uint8_t*) &size, 2);
  crypto_hash_sha512_update(&state, DST, DST_size);

  crypto_hash_sha512_final(&state, result);
  sodium_munlock(&state, sizeof state);
  return 0;
}

static int prf(const uint8_t *pwdU, const uint16_t pwdU_len,
                const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                const uint8_t *key, const uint16_t key_len,
                uint8_t rwd[crypto_hash_sha512_BYTES]) {
  // F_k(pwd) = H(pwd, (H0(pwd))^k) for key k ∈ Z_q
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  sodium_mlock(h0,sizeof h0);
  // hash pwd with H0
  crypto_hash_sha512(h0, pwdU, pwdU_len);
#ifdef TRACE
  dump(h0, sizeof h0, "h0");
#endif
  unsigned char H0[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0,sizeof H0);
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);
#ifdef TRACE
  dump(H0, sizeof H0, "H0");
#endif

  // H0 ^ k
  unsigned char H0_k[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0_k,sizeof H0_k);
  if (crypto_scalarmult_ristretto255(H0_k, k, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    sodium_munlock(H0_k,sizeof H0_k);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef TRACE
  dump(H0_k, sizeof H0_k, "H0_k");
#endif

  if(0!=prf_finalize(pwdU, pwdU_len, key, key_len, H0_k, rwd)) {
    sodium_munlock(H0_k,sizeof H0_k);
    return -1;
  }
  sodium_munlock(H0_k,sizeof H0_k);

#ifdef TRACE
  dump(rwd, crypto_hash_sha512_BYTES, "rwd");
#endif

  return 0;
}

// See https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto.
static int blind(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t r[crypto_core_ristretto255_SCALARBYTES], uint8_t alpha[crypto_core_ristretto255_BYTES]) {
  // sets α := (H^0(pw))^r
  // hash x with H^0
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  if(0!=sodium_mlock(h0,sizeof h0)) {
    return -1;
  }
  crypto_hash_sha512(h0, pwdU, pwdU_len);
#ifdef TRACE
  dump(h0, sizeof h0, "h0");
#endif
  unsigned char H0[crypto_core_ristretto255_BYTES];
  if(0!=sodium_mlock(H0,sizeof H0)) {
    sodium_munlock(h0,sizeof h0);
    return -1;
  }
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);
#ifdef TRACE
  dump(H0,sizeof H0, "H0 ");
#endif
  // U picks r
  crypto_core_ristretto255_scalar_random(r);
#ifdef TRACE
  dump(r, crypto_core_ristretto255_SCALARBYTES, "r");
#endif
  // H^0(pw)^r
  if (crypto_scalarmult_ristretto255(alpha, r, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef TRACE
  dump(alpha, crypto_core_ristretto255_BYTES, "alpha");
#endif
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
    get_xcript(xcript, &sec->xcript_state, pub->alpha, pub->nonceU, pub->X_u, resp->beta, (uint8_t*) &resp->envelope, resp->env_len, resp->nonceS, resp->X_s, infos, 0);
  else
    get_xcript(xcript, NULL, pub->alpha, pub->nonceU, pub->X_u, resp->beta, (uint8_t*) &resp->envelope, resp->env_len, resp->nonceS, resp->X_s, infos, 0);
}

static void get_xcript_usr(uint8_t xcript[crypto_hash_sha256_BYTES],
                           const Opaque_UserSession_Secret *sec,
                           const Opaque_ServerSession *resp,
                           const uint8_t *env,
                           const uint8_t X_u[crypto_scalarmult_BYTES],
                           const Opaque_App_Infos *infos,
                           const int use_info3) {
  get_xcript(xcript, 0, sec->alpha, sec->nonceU, X_u, resp->beta, env, resp->env_len, resp->nonceS, resp->X_s, infos, use_info3);
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
static int opaque_envelope(const uint8_t rwd[crypto_secretbox_KEYBYTES],
                     const uint8_t *SecEnv, const size_t SecEnv_len,
                     const uint8_t *ClrEnv, const size_t ClrEnv_len,
                     uint8_t *envelope, // must be of size: OPAQUE_ENVELOPE_META_LEN + SecEnv_len+ClrEnv_len
                                        // len(nonce|uint16|SecEnv|uint16|ClrEnv|hmacTag)
                     uint8_t export_key[crypto_hash_sha256_BYTES]) {
  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope) return 1;
  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp,ClrEnv_len, &tmp)) return 1;
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv0 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv0 ");
#endif

  // (2) Set E = Nonce | ....
  randombytes(envelope,crypto_hash_sha256_BYTES);

  if(__builtin_add_overflow(2*crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  char ctx[crypto_hash_sha256_BYTES+9];
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  uint8_t pad[SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwd);

  uint8_t *c = envelope+crypto_hash_sha256_BYTES;

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
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwd);
  //(3) Set T = HMAC(E,auth_key)
  const size_t env_len=crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t);
#ifdef TRACE
  dump(envelope,env_len,"envelope auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
#endif
  crypto_auth_hmacsha256(envelope + env_len, // out
                         envelope,           // in
                         env_len,            // len(in)
                         auth_key);          // key
  sodium_munlock(auth_key, sizeof auth_key);
#ifdef TRACE
  dump(envelope+env_len, crypto_hash_sha256_BYTES, "auth tag ");
  dump(envelope,crypto_hash_sha256_BYTES*2+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t), "envelope ");
#endif

  if(export_key) {
    // export_key = HKDF-Expand(RwdU, concat(nonce, "ExportKey"), Nh)
    memcpy(ctx+crypto_hash_sha256_BYTES,"ExportKey",9);
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwd);
#ifdef TRACE
    dump(export_key,crypto_hash_sha256_BYTES, "export_key ");
#endif
  }

  return 0;
}

static int opaque_envelope_open(const uint8_t rwd[crypto_secretbox_KEYBYTES], const uint8_t *envelope, const size_t env_len,
                         uint8_t *SecEnv, uint16_t *SecEnv_len,
                         uint8_t **ClrEnv, uint16_t *ClrEnv_len,
                         uint8_t export_key[crypto_hash_sha256_BYTES]) {

  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope || env_len < 2*crypto_hash_sha256_BYTES+2*sizeof(uint16_t)) return 1;

#ifdef TRACE
  dump(envelope,env_len, "open envelope ");
#endif

  // (1) verify authentication tag on the envelope
  // auth_key = HKDF-Expand(RwdU, concat(nonce, "AuthKey"), Nh)
  char ctx[crypto_hash_sha256_BYTES+9]; // reused also for pad and export key, hence bigger than needed
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);

  uint8_t auth_key[crypto_hash_sha256_BYTES];
  sodium_mlock(auth_key, sizeof auth_key);
  memcpy(ctx+crypto_hash_sha256_BYTES,"AuthKey",7);
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwd);

  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envelope - crypto_hash_sha256_BYTES,env_len, &tmp)) return 1;

#ifdef TRACE
  dump(envelope,env_len-crypto_hash_sha256_BYTES,"envelope auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
  dump((uint8_t*) tmp,crypto_hash_sha256_BYTES, "auth tag ");
#endif
  if(-1 == crypto_auth_hmacsha256_verify((uint8_t*) tmp,                     // tag
                                         envelope,                           // in
                                         env_len-crypto_hash_sha256_BYTES,   // inlen
                                         auth_key)) {
    sodium_munlock(auth_key, sizeof auth_key);
    return 1;
  }
  sodium_munlock(auth_key, sizeof auth_key);

  // parse envelope for *env_len fields
  const uint8_t *ptr = envelope+crypto_hash_sha256_BYTES;
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
  if(env_len != sl + cl + 2*sizeof(uint16_t) + 2*crypto_hash_sha256_BYTES) return 1;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES+sizeof(uint16_t),*SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp+sizeof(uint16_t),*ClrEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  uint8_t pad[*SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwd);
#ifdef TRACE
  dump(pad,sizeof pad, "pad ");
#endif

  const uint8_t *c = envelope+crypto_hash_sha256_BYTES+sizeof(uint16_t);
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
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwd);
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
  if(cfg->skU==InClrEnv || 0!=extend_package(cred->p_u, crypto_scalarmult_SCALARBYTES, cfg->skU, skU, &senv, &cenv)) return 1;
  if(0!=extend_package(cred->P_u, crypto_scalarmult_BYTES, cfg->pkU, pkU, &senv, &cenv)) return 1;
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
    memcpy(&creds->p_u, &cred->data, crypto_scalarmult_SCALARBYTES);
    break;
  };
  case pkU: {
    if(cfg->pkU!=current_target) return 1;
    if(cred->size!=crypto_scalarmult_BYTES) return 1;
    memcpy(&creds->P_u, &cred->data, crypto_scalarmult_BYTES);
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

static int unpack(const Opaque_PkgConfig *cfg, const uint8_t *SecEnv, const uint16_t SecEnv_len, const uint8_t *ClrEnv, const uint16_t ClrEnv_len, const uint8_t rwd[crypto_secretbox_KEYBYTES], Opaque_Credentials *creds, Opaque_Ids *ids) {
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
  // rwd is used to derive a seed for the keygen - which for 25519 is
  // a null op and we use directly the seed as the secret key
  // HKDF-Expand(KdKey; info="KG seed", L)
  if(cfg->skU == NotPackaged) {
    if(seen & (1 << (skU-1))) return 1; // skU was packaged in the envelope
    crypto_kdf_hkdf_sha256_expand(creds->p_u, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rwd);
    seen|=(1 << (skU - 1));
  }

  // recalculate non-packaged pkU
  if(cfg->pkU == NotPackaged) {
    if(!(seen & (1 << (skU-1)))) return 1;
    crypto_scalarmult_base(creds->P_u, creds->p_u);
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
                    const uint8_t *key, const uint16_t key_len,
                    const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                    const Opaque_PkgConfig *cfg,
                    const Opaque_Ids *ids,
                    uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+env_len*/],
                    uint8_t export_key[crypto_hash_sha256_BYTES]) {
  Opaque_UserRecord *rec = (Opaque_UserRecord *)_rec;

  const uint16_t ClrEnv_len = opaque_package_len(cfg, ids, InClrEnv);
  const uint16_t SecEnv_len = opaque_package_len(cfg, ids, InSecEnv);
  const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump((uint8_t*) cfg,2, "cfg ");
  fprintf(stderr, "cfg skU: %d, pkU:%d, pkS:%d, idU:%d, idS:%d\n", cfg->skU, cfg->pkU, cfg->pkS, cfg->idU, cfg->idS);
  dump(ids->idU, ids->idU_len,"idU ");
  dump(ids->idS, ids->idS_len,"idS ");
  fprintf(stderr,"clrenv_len: %d\n", ClrEnv_len);
  fprintf(stderr,"secenv_len: %d\n", SecEnv_len);
  fprintf(stderr,"env_len: %d\n", env_len);
  fprintf(stderr,"rec_len: %ld\n", OPAQUE_USER_RECORD_LEN+env_len);
  memset(_rec,0,OPAQUE_USER_RECORD_LEN+env_len);
#endif

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(rec->k_s);

  // rw := F_k_s (pw),
  uint8_t rw0[crypto_hash_sha512_BYTES];
  if(-1==sodium_mlock(rw0,sizeof rw0)) return -1;
  if(prf(pwdU, pwdU_len, rec->k_s, key, key_len, rw0)!=0) {
    sodium_munlock(rw0,sizeof rw0);
    return -1;
  }

#ifdef TRACE
  dump((uint8_t*) rw0, sizeof rw0, "rw0 ");
#endif
  uint8_t rw[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rw,sizeof rw)) {
    sodium_munlock(rw0,sizeof rw0);
    return -1;
  }
  // according to the ietf draft this could be all zeroes
  uint8_t salt[crypto_pwhash_SALTBYTES]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0,sizeof rw0);
    sodium_munlock(rw,sizeof rw);
    return -1;
  }
  sodium_munlock(rw0,sizeof rw0);
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

#ifdef TRACE
  dump((uint8_t*) rw, sizeof rw, "key ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "k_s\nplain user rec ");
#endif
  // p_s ←_R Z_q
  if(skS==NULL) {
    randombytes(rec->p_s, crypto_scalarmult_SCALARBYTES); // random server secret key
  } else {
    memcpy(rec->p_s, skS, crypto_scalarmult_SCALARBYTES);
  }

#ifdef TRACE
  dump(rec->p_s, crypto_scalarmult_SCALARBYTES, "p_s ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "plain user rec ");
#endif
  Opaque_Credentials cred;
  sodium_mlock(&cred, sizeof cred);
  // p_u ←_R Z_q
  if(cfg->skU != NotPackaged) {
    randombytes(cred.p_u, crypto_scalarmult_SCALARBYTES); // random user secret key
  } else {
    crypto_kdf_hkdf_sha256_expand(cred.p_u, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rw);
  }

#ifdef TRACE
  dump(cred.p_u, crypto_core_ristretto255_SCALARBYTES, "p_u ");
#endif
  // P_s := g^p_s
  crypto_scalarmult_base(rec->pkS, rec->p_s);

#ifdef TRACE
  dump(rec->pkS, crypto_scalarmult_BYTES, "pkS ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "plain user rec ");
#endif
  // P_u := g^p_u
  crypto_scalarmult_base(rec->P_u, cred.p_u);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "P_u\nplain user rec ");
#endif
  // copy Pubkeys also into rec.c
  memcpy(cred.P_u, rec->P_u,crypto_scalarmult_BYTES*2);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "P_[us] -> c\nplain user rec ");
#endif

  // package up credential for the envelope
  uint8_t SecEnv[SecEnv_len], ClrEnv[ClrEnv_len];

  if(0!=pack(cfg, &cred, ids, SecEnv, ClrEnv)) {
    sodium_munlock(&cred, sizeof cred);
    return -1;
  }
  sodium_munlock(&cred, sizeof cred);
  // c ← AuthEnc_rw(p_u,P_u,P_s);
  if(0!=opaque_envelope(rw, SecEnv_len ? SecEnv : NULL, SecEnv_len, ClrEnv_len ? ClrEnv : NULL, ClrEnv_len, rec->envelope, export_key)) {
    return -1;
  }
  rec->env_len = env_len;

  sodium_munlock(rw, sizeof(rw));

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "cipher user rec ");
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

  if(0!=blind(pwdU, pwdU_len, sec->r, pub->alpha)) return -1;
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
  memcpy(sec->alpha, pub->alpha, crypto_core_ristretto255_BYTES);

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
int opaque_CreateCredentialResponse(const uint8_t _pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+env_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t _resp[OPAQUE_SERVER_SESSION_LEN/*+env_len*/], uint8_t sk[OPAQUE_SHARED_SECRETBYTES],  uint8_t _sec[OPAQUE_SERVER_AUTH_CTX_LEN]) {

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
  if(crypto_core_ristretto255_is_valid_point(pub->alpha)!=1) return -1;

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
  dump(rec->k_s, sizeof(rec->k_s), "session srv k_s ");
  dump(pub->alpha, sizeof(pub->alpha), "session srv alpha ");
#endif

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(resp->beta, rec->k_s, pub->alpha) != 0) {
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
  dump(rec->p_s,crypto_scalarmult_SCALARBYTES, "rec->p_s ");
  dump(x_s,crypto_scalarmult_SCALARBYTES, "x_s ");
  dump(rec->P_u,crypto_scalarmult_BYTES, "rec->P_u ");
  dump(pub->X_u,crypto_scalarmult_BYTES, "pub->X_u ");
#endif
  if(0!=server_3dh(&keys, rec->p_s, x_s, rec->P_u, pub->X_u, info)) {
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
  memcpy(&resp->envelope, &rec->envelope, rec->env_len);
  memcpy(&resp->env_len, &rec->env_len, sizeof rec->env_len);

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
int opaque_RecoverCredentials(const uint8_t _resp[OPAQUE_SERVER_SESSION_LEN/*+env_len*/],
                              const uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
                              const uint8_t *key, const uint16_t key_len,
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
  dump(key,key_len, "session user finish key ");
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "session user finish sec ");
  dump(_resp,OPAQUE_SERVER_SESSION_LEN, "session user finish resp ");
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(resp->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir,sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, sec->r) != 0) {
    sodium_munlock(ir,sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump(sec->r,sizeof(sec->r), "session user finish r ");
  dump(ir,sizeof(ir), "session user finish r^-1 ");
#endif

  // h0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  uint8_t h0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(h0,sizeof h0)) {
    sodium_munlock(ir,sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump(resp->beta,sizeof(resp->beta), "session user finish beta ");
#endif
  if (crypto_scalarmult_ristretto255(h0, ir, resp->beta) != 0) {
    sodium_munlock(ir,sizeof ir);
    sodium_munlock(h0,sizeof h0);
    return -1;
  }
  sodium_munlock(ir,sizeof ir);
#ifdef TRACE
  dump(h0,sizeof(h0), "session user finish h0 ");
#endif

  // rw = H(pw, β^(1/r))
  uint8_t rw0[crypto_hash_sha512_BYTES];
  if(-1==sodium_mlock(rw0,sizeof rw0)) {
    return -1;
  }
  if(0!=prf_finalize(sec->pwdU, sec->pwdU_len, key, key_len, h0, rw0)) {
    sodium_munlock(h0, sizeof h0);
    return -1;
  }
  sodium_munlock(h0,sizeof h0);

#ifdef TRACE
  dump(rw0,sizeof(rw0), "session user finish rw0 ");
#endif

  uint8_t rw[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rw,sizeof rw)) {
    sodium_munlock(rw0, sizeof(rw0));
    return -1;
  }
  uint8_t salt[crypto_pwhash_SALTBYTES]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0, sizeof rw0);
    sodium_munlock(rw, sizeof rw);
    return -1;
  }
  sodium_munlock(rw0, sizeof rw0);
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

#ifdef TRACE
  dump(rw,sizeof(rw), "session user finish rw ");
#endif

  // (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
  //     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
  if(resp->env_len > OPAQUE_ENVELOPE_META_LEN + ((1<<17) - 2)  ) {
    sodium_munlock(rw, sizeof rw);
    return -1; // avoid integer overflow in next line
  }
  uint8_t *ClrEnv, env[resp->env_len], SecEnv[resp->env_len];
  uint16_t ClrEnv_len, SecEnv_len;
  // preserve envelope for later transcript calculation
  memcpy(env, &resp->envelope, resp->env_len);
  if(0!=opaque_envelope_open(rw, resp->envelope, resp->env_len, SecEnv, &SecEnv_len, &ClrEnv, &ClrEnv_len, export_key)) {
    sodium_munlock(rw, sizeof(rw));
    return -1;
  }

  Opaque_Credentials cred={0};
  sodium_mlock(&cred,sizeof cred);
  if(0!=unpack(cfg, SecEnv, SecEnv_len, ClrEnv, ClrEnv_len, rw, &cred, ids)) {
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

  sodium_munlock(rw, sizeof(rw));

  // mixing in things from the ietf cfrg spec
  char info[crypto_hash_sha256_BYTES];
  calc_info(info, sec->nonceU, resp->nonceS, ids);
  Opaque_Keys keys;
  sodium_mlock(&keys,sizeof(keys));

  // (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
#ifdef TRACE
  dump(cred.p_u,crypto_scalarmult_SCALARBYTES, "c->p_u ");
  dump(sec->x_u,crypto_scalarmult_SCALARBYTES, "sec->x_u ");
  dump(cred.pkS,crypto_scalarmult_BYTES, "c->pkS ");
  dump(resp->X_s,crypto_scalarmult_BYTES, "sec->X_s ");
#endif
  if(0!=user_3dh(&keys, cred.p_u, sec->x_u, cred.pkS, resp->X_s, info)) {
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
int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t _sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t alpha[crypto_core_ristretto255_BYTES]) {
  Opaque_RegisterUserSec *sec = (Opaque_RegisterUserSec *) _sec;
  memcpy(&sec->pwdU, pwdU, pwdU_len);
  sec->pwdU_len = pwdU_len;
  return blind(pwdU, pwdU_len, sec->r, alpha);
}

// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
// called CreateRegistrationResponse in the ietf cfrg rfc draft
int opaque_CreateRegistrationResponse(const uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_RegisterSrvPub *pub = (Opaque_RegisterSrvPub *) _pub;

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(alpha)!=1) return -1;

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(sec->k_s);

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(pub->beta, sec->k_s, alpha) != 0) {
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) pub->beta, sizeof pub->beta, "beta ");
#endif

  // p_s ←_R Z_q
  randombytes(sec->p_s, crypto_scalarmult_SCALARBYTES); // random server long-term key
#ifdef TRACE
  dump((uint8_t*) sec->p_s, sizeof sec->p_s, "p_s ");
#endif

  // P_s := g^p_s
  crypto_scalarmult_base(pub->pkS, sec->p_s);
#ifdef TRACE
  dump((uint8_t*) pub->pkS, sizeof pub->pkS, "pkS ");
#endif

  return 0;
}

// same function as opaque_CreateRegistrationResponse() but does not generate a long-term server keypair
// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
// called CreateRegistrationResponse in the ietf cfrg rfc draft
int opaque_Create1kRegistrationResponse(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_RegisterSrvPub *pub = (Opaque_RegisterSrvPub *) _pub;

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(alpha)!=1) return -1;

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(sec->k_s);

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(pub->beta, sec->k_s, alpha) != 0) {
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*) pub->beta, sizeof pub->beta, "beta ");
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
                                    const uint8_t *key, const uint16_t key_len,        // contributes to the final rwd calculation as a key to the hash
                                    const Opaque_PkgConfig *cfg,
                                    const Opaque_Ids *ids,
                                    uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+env_len*/],
                                    uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_RegisterUserSec *sec = (Opaque_RegisterUserSec *) _sec;
  Opaque_RegisterSrvPub *pub = (Opaque_RegisterSrvPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  const uint16_t ClrEnv_len = opaque_package_len(cfg, ids, InClrEnv);
  const uint16_t SecEnv_len = opaque_package_len(cfg, ids, InSecEnv);

#ifdef TRACE
  const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
  memset(_rec,0,OPAQUE_USER_RECORD_LEN+env_len);
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(pub->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // invert r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir, sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, sec->r) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }

  // H0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  uint8_t h0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(h0,sizeof h0)) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
  if (crypto_scalarmult_ristretto255(h0, ir, pub->beta) != 0) {
    sodium_munlock(ir, sizeof ir);
    sodium_munlock(h0, sizeof h0);
    return -1;
  }
  sodium_munlock(ir, sizeof ir);
#ifdef TRACE
  dump((uint8_t*) h0, sizeof h0, "h0_k ");
#endif

  uint8_t rw0[crypto_hash_sha512_BYTES];
  if(-1==sodium_mlock(rw0, sizeof rw0)) {
    return -1;
  }
  if(0!=prf_finalize(sec->pwdU, sec->pwdU_len, key, key_len, h0, rw0)) {
    sodium_munlock(h0, sizeof h0);
    return -1;
  }
  sodium_munlock(h0,sizeof h0);

#ifdef TRACE
  dump((uint8_t*) rw0, sizeof rw0, "rw0 ");
#endif

  uint8_t rw[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rw, sizeof rw)) {
    sodium_munlock(rw0, sizeof rw0);
    return -1;
  }
  // salt - according to the ietf draft this could be all zeroes
  uint8_t salt[crypto_pwhash_SALTBYTES]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0, sizeof(rw0));
    sodium_munlock(rw, sizeof(rw));
    return -1;
  }
  sodium_munlock(rw0, sizeof(rw0));
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

#ifdef TRACE
  dump((uint8_t*) rw, sizeof rw, "key ");
#endif

  Opaque_Credentials cred;
  sodium_mlock(&cred, sizeof cred);
  // p_u ←_R Z_q
  if(cfg->skU != NotPackaged) {
    randombytes(cred.p_u, crypto_scalarmult_SCALARBYTES); // random user secret key
  } else {
    crypto_kdf_hkdf_sha256_expand(cred.p_u, crypto_core_ristretto255_SCALARBYTES, "KG seed", 7, rw);
  }

  // P_u := g^p_u
  crypto_scalarmult_base(cred.P_u, cred.p_u);

  // copy P_u also into plaintext rec
  memcpy(rec->P_u, cred.P_u,crypto_scalarmult_BYTES);

  // copy P_s into rec.c
  memcpy(cred.pkS, pub->pkS,crypto_scalarmult_BYTES);

  // c ← AuthEnc_rw(p_u,P_u,P_s);
#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+env_len, "plain user rec ");
#endif

  // package up credential for the envelope
  uint8_t SecEnv[SecEnv_len], ClrEnv[ClrEnv_len];

  if(0!=pack(cfg, &cred, ids, SecEnv, ClrEnv)) {
    sodium_munlock(&cred, sizeof cred);
    return -1;
  }
  sodium_munlock(&cred, sizeof cred);
  if(0!=opaque_envelope(rw, SecEnv_len ? SecEnv : NULL, SecEnv_len, ClrEnv_len ? ClrEnv : NULL, ClrEnv_len, rec->envelope, export_key)) {
    return -1;
  }
  rec->env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN, "cipher user rec ");
#endif

  sodium_munlock(rw, sizeof(rw));

  return 0;
}

// S records file[sid ] := {k_s, p_s, P_s, P_u, c}.
// called StoreUserRecord in the ietf cfrg rfc draft
void opaque_StoreUserRecord(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+env_len*/]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  memcpy(rec->k_s, sec->k_s, sizeof rec->k_s);
  memcpy(rec->p_s, sec->p_s, sizeof rec->p_s);
  crypto_scalarmult_base(rec->pkS, rec->p_s);
#ifdef TRACE
  dump((uint8_t*) rec, OPAQUE_USER_RECORD_LEN, "user rec ");
#endif
}

void opaque_Store1kUserRecord(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES], uint8_t _rec[OPAQUE_USER_RECORD_LEN/*+env_len*/]) {
  Opaque_RegisterSrvSec *sec = (Opaque_RegisterSrvSec *) _sec;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  memcpy(rec->k_s, sec->k_s, sizeof rec->k_s);
  memcpy(rec->p_s, skS, crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult_base(rec->pkS, skS);
#ifdef TRACE
  dump((uint8_t*) rec, OPAQUE_USER_RECORD_LEN, "user rec ");
#endif
}
