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
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libopaque. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <assert.h>
#include "../opaque.h"
#include "../common.h"

int main(void) {
  const uint8_t pwdU[]="asdf";
  const uint16_t pwdU_len=strlen((char*) pwdU);
  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t export_key0[crypto_hash_sha512_BYTES];
  Opaque_Ids ids={4,(uint8_t*)"user",6,(uint8_t*)"server"};
  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  uint8_t rec0[OPAQUE_USER_RECORD_LEN];
  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t pk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU0[crypto_auth_hmacsha512_BYTES];
  uint8_t authU1[crypto_auth_hmacsha512_BYTES];
  const uint8_t context[4]="test";

  fprintf(stderr, "\n\nprivate registration\n\n");

  // variant where user registration does not leak secrets to server
  uint8_t M[crypto_core_ristretto255_BYTES];
  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];
  // user initiates:
  fprintf(stderr, "\nopaque_CreateRegistrationRequest\n");
  if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, usr_ctx, M)) {
    fprintf(stderr, "opaque_CreateRegistrationRequest failed.\n");
    return 1;
  }
  // server responds
  uint8_t rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
  fprintf(stderr, "\nopaque_CreateRegistrationResponse\n");
  if(0!=opaque_CreateRegistrationResponse(M, NULL, rsec, rpub)) {
    fprintf(stderr, "opaque_CreateRegistrationResponse failed.\n");
    return 1;
  }
  // user commits its secrets
  fprintf(stderr, "\nopaque_FinalizeRequest\n");
  unsigned char rrec[OPAQUE_REGISTRATION_RECORD_LEN]={0};
  if(0!=opaque_FinalizeRequest(usr_ctx, rpub, &ids, rrec, export_key)) {
    fprintf(stderr, "opaque_FinalizeRequest failed.\n");
    return 1;
  }
  // server "saves"
  fprintf(stderr, "\nopaque_StoreUserRecord\n");
  opaque_StoreUserRecord(rsec, rrec, rec);

  fprintf(stderr, "\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
  fprintf(stderr, "\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, sizeof context, resp, sk, authU0)) {
    fprintf(stderr, "opaque_CreateCredentialResponse failed.\n");
    return 1;
  }
  fprintf(stderr, "\nopaque_RecoverCredentials\n");

  if(0!=opaque_RecoverCredentials(resp, sec, context, sizeof context, &ids, pk, authU1, export_key)) return 1;
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:

  if(-1==opaque_UserAuth(authU0, authU1)) {
    fprintf(stderr, "failed authenticating user\n");
    return 1;
  }

  // register user
  fprintf(stderr, "\nopaque_Register\n");
  if(0!=opaque_Register(pwdU, pwdU_len, NULL, &ids, rec0, export_key0)) {
    fprintf(stderr, "opaque_Register failed.\n");
    return 1;
  }

  fprintf(stderr, "\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
  fprintf(stderr, "\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rec0, &ids, context, sizeof context, resp, sk, authU0)) {
    fprintf(stderr, "opaque_CreateCredentialResponse failed.\n");
    return 1;
  }
  fprintf(stderr, "\nopaque_RecoverCredentials\n");

  if(0!=opaque_RecoverCredentials(resp, sec, context, sizeof context, &ids, pk, authU1, export_key)) return 1;
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);
  assert(memcmp(export_key, export_key0, sizeof export_key)==0);

  // authenticate both parties:

  if(-1==opaque_UserAuth(authU0, authU1)) {
    fprintf(stderr, "failed authenticating user\n");
    return 1;
  }

  fprintf(stderr, "\nall ok\n\n");

  return 0;
}
