/*
    @copyright 2018-2020, opaque@ctrlc.hu
    This file is part of libopaque

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
*/

#include <stdio.h>
#include <assert.h>
#include "../opaque.h"
#include "../common.h"

typedef struct {
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
  uint32_t env_len;
  uint8_t envelope[];
} __attribute((packed)) Opaque_UserRecord;

static void _dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  fprintf(stderr, "%s",msg);
  for(i=0;i<len;i++)
    fprintf(stderr, "%02x", p[i]);
  fprintf(stderr, "\n");
}

int main(void) {
  uint8_t pw[]="simple guessable dictionary password";
  uint16_t pw_len=strlen((char*) pw);
  uint8_t key[]="some optional key contributed to the opaque protocol";
  uint16_t key_len=strlen((char*) key);
  uint8_t export_key[crypto_hash_sha256_BYTES];
  uint8_t export_key_x[crypto_hash_sha256_BYTES];
  Opaque_Ids ids={4,(uint8_t*)"user",6,(uint8_t*)"server"};
  ids.idU_len = strlen((char*) ids.idU);
  ids.idS_len = strlen((char*) ids.idS);
  Opaque_PkgConfig cfg={
                        .skU = NotPackaged,
                        .pkU = NotPackaged,
                        .pkS = InSecEnv,
                        .idS = NotPackaged,
                        .idU = NotPackaged,
  };
  _dump((uint8_t*) &cfg,sizeof cfg, "cfg ");
  fprintf(stderr, "cfg sku: %d, pku:%d, pks:%d, idu:%d, ids:%d\n", cfg.skU, cfg.pkU, cfg.pkS, cfg.idU, cfg.idS);
  const uint32_t env_len = opaque_envelope_len(&cfg, &ids);
  unsigned char rec[OPAQUE_USER_RECORD_LEN+env_len];
  fprintf(stderr, "sizeof(rec): %ld\n",sizeof(rec));

  // register user
  fprintf(stderr, "\nopaque_Register\n");
  if(0!=opaque_Register(pw, pw_len, key, key_len, NULL, &cfg, &ids, rec, export_key)) {
    fprintf(stderr, "opaque_Register failed.\n");
    return 1;
  }

  // initiate login
  unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN+pw_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  fprintf(stderr, "\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pw, pw_len, sec, pub);

  unsigned char resp[OPAQUE_SERVER_SESSION_LEN+env_len];
  uint8_t sk[32];
  uint8_t ctx[OPAQUE_SERVER_AUTH_CTX_LEN]={0};
  fprintf(stderr, "\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, NULL, resp, sk, ctx)) {
    fprintf(stderr, "opaque_CreateCredentialResponse failed.\n");
    return 1;
  }

  _dump(sk,32,"sk_s: ");

  uint8_t pk[32];
  fprintf(stderr, "\nopaque_RecoverCredentials\n");
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t idU[ids.idU_len], idS[ids.idS_len]; // must be big enough to fit ids
  Opaque_Ids ids1={sizeof idU,idU, sizeof idS ,idS};
  if(cfg.idU == NotPackaged) {
    ids1.idU_len = ids.idU_len;
    memcpy(idU, ids.idU, ids.idU_len);
  }
  if(cfg.idS == NotPackaged) {
    ids1.idS_len = ids.idS_len;
    memcpy(idS, ids.idS, ids.idS_len);
  }

  uint8_t *pkS = NULL;
  if(cfg.pkS == NotPackaged) {
    Opaque_UserRecord *_rec = (Opaque_UserRecord *) &rec;
    pkS = _rec->P_s;
  }

  //Opaque_App_Infos infos;
  if(0!=opaque_RecoverCredentials(resp, sec, key, key_len, pkS, &cfg, NULL, &ids1, pk, authU, export_key_x)) {
    fprintf(stderr, "opaque_RecoverCredentials failed.\n");
    return 1;
  }
  _dump(pk,32,"sk_u: ");
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);
  assert(sodium_memcmp(export_key,export_key_x,sizeof export_key)==0);

  fprintf(stderr, "\nopaque_UserAuth\n");
  if(-1==opaque_UserAuth(ctx, authU, NULL)) {
    fprintf(stderr, "failed authenticating user\n");
    return 1;
  }

  fprintf(stderr, "\n\nprivate registration\n\n");

  // variant where user registration does not leak secrets to server
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+pw_len];
  // user initiates:
  fprintf(stderr, "\nopaque_CreateRegistrationRequest\n");
  if(0!=opaque_CreateRegistrationRequest(pw, pw_len, usr_ctx, alpha)) {
    fprintf(stderr, "opaque_CreateRegistrationRequest failed.\n");
    return 1;
  }
  // server responds
  unsigned char rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
  fprintf(stderr, "\nopaque_CreateRegistrationResponse\n");
  if(0!=opaque_CreateRegistrationResponse(alpha, rsec, rpub)) {
    fprintf(stderr, "opaque_CreateRegistrationResponse failed.\n");
    return 1;
  }
  // user commits its secrets
  unsigned char rrec[OPAQUE_USER_RECORD_LEN+env_len];
  fprintf(stderr, "\nopaque_FinalizeRequest\n");
  if(0!=opaque_FinalizeRequest(usr_ctx, rpub, key, key_len, &cfg, &ids, rrec, export_key)) {
    fprintf(stderr, "opaque_FinalizeRequest failed.\n");
    return 1;
  }
  // server "saves"
  fprintf(stderr, "\nopaque_StoreUserRecord\n");
  opaque_StoreUserRecord(rsec, rrec);

  fprintf(stderr, "\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pw, pw_len, sec, pub);
  fprintf(stderr, "\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rrec, &ids, NULL, resp, sk, ctx)) {
    fprintf(stderr, "opaque_CreateCredentialResponse failed.\n");
    return 1;
  }
  _dump(sk,32,"sk_s: ");
  fprintf(stderr, "\nopaque_RecoverCredentials\n");

  if(cfg.pkS == NotPackaged) {
    Opaque_UserRecord *_rec = (Opaque_UserRecord *) &rec;
    pkS = _rec->P_s;
  } else {
    pkS = NULL;
  }
  if(0!=opaque_RecoverCredentials(resp, sec, key, key_len, pkS, &cfg, NULL, &ids1, pk, authU, export_key)) return 1;
  _dump(pk,32,"sk_u: ");
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:

  if(-1==opaque_UserAuth(ctx, authU, NULL)) {
    fprintf(stderr, "failed authenticating user\n");
    return 1;
  }

  fprintf(stderr, "\nall ok\n\n");

  return 0;
}
