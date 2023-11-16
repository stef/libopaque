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
#include "cfrg_test_vectors.h"

typedef struct {
  uint8_t blind[crypto_core_ristretto255_SCALARBYTES];
  uint16_t pwdU_len;
  uint8_t pwdU[];
} Opaque_RegisterUserSec;

int main(void) {
  // test vector 1
  // create credential workflow

  uint8_t pwdU[]="CorrectHorseBatteryStaple";
  size_t pwdU_len = sizeof(pwdU) - 1;
  uint8_t ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];
  uint8_t regreq[crypto_core_ristretto255_BYTES];

  // create registration request
  if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, ctx, regreq)) return 1;
  // metadata is R blinding factor
  // assert match with test vector
  if(memcmp(((Opaque_RegisterUserSec*) &ctx)->blind,blind_registration, sizeof(blind_registration))!=0) {
    fprintf(stderr, "failed to reproduce reg req blind factor\n");
    dump(blind_registration, sizeof(blind_registration),                      "blind_registration");
    dump(((Opaque_RegisterUserSec*) &ctx)->blind, sizeof(blind_registration), "blind             ");
    exit(1);
  }
  if(memcmp(registration_request, regreq, 32)!=0) {
    fprintf(stderr, "failed to reproduce reg req\n");
    dump(regreq, 32, "regreq");
    dump(registration_request, 32, "registration_request");
    exit(1);
  }

  // create registration response
  // prepare
  unsigned char
    rsec[OPAQUE_REGISTER_SECRET_LEN],
    resp[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(regreq, server_private_key, rsec, resp)) return 1;
  // verify test vectors
  if(memcmp(registration_response, resp, sizeof resp)!=0) {
    fprintf(stderr,"failed to reproduce registration_response\n");
    dump(resp, sizeof resp, "resp");
    dump(registration_response, sizeof registration_response, "registration_response");
    exit(1);
  }

  // finalize request
  // prepare params
  Opaque_Ids ids={0};
  unsigned char rrec[OPAQUE_REGISTRATION_RECORD_LEN]={0};
  uint8_t ek[crypto_hash_sha512_BYTES]={0};

  if(0!=opaque_FinalizeRequest(ctx, resp, &ids, rrec, ek)) return 1;

  // verify test vectors
  if(memcmp(export_key, ek, sizeof export_key)!=0) {
    fprintf(stderr,"failed to reproduce export_key\n");
    dump(ek, sizeof ek, "ek");
    dump(export_key, sizeof export_key, "export_key");
    exit(1);
  }
  if((sizeof rrec != sizeof registration_upload) || memcmp(registration_upload, rrec, sizeof rrec)!=0) {
    fprintf(stderr,"failed to reproduce registration_upload\n");
    dump(rrec, sizeof rrec, "rrec               ");
    dump(registration_upload, sizeof registration_upload, "registration_upload");
    exit(1);
  }

  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(rsec, rrec, rec);

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len];
  uint8_t req[OPAQUE_USER_SESSION_PUBLIC_LEN];
  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, req)) {
    return 1;
  }
  if(sizeof rrec != sizeof registration_upload) {
    fprintf(stderr,"len(ke1) != len(req)\n");
    dump(req, sizeof req, "req");
    dump(ke1, sizeof ke1, "ke1");
    exit(1);
  }
  if(memcmp(ke1, req, sizeof req)!=0) {
    fprintf(stderr,"failed to reproduce ke1\n");
    dump(req, sizeof req, "req");
    dump(ke1, sizeof ke1, "ke1");
    exit(1);
  }

  uint8_t cresp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t context[10]="OPAQUE-POC";
  if(0!=opaque_CreateCredentialResponse(req, rec, &ids, context, sizeof context, cresp, sk, authU)) {
    return -1;
  }

  if(memcmp(session_key, sk, sizeof session_key)!=0) {
    fprintf(stderr,"failed to reproduce session_key\n");
    dump(sk, sizeof sk, "sk");
    dump(session_key, sizeof session_key, "session_key");
    exit(1);
  }

  if(sizeof cresp != sizeof ke2) {
    fprintf(stderr,"len(ke2) != len(resp)\n");
    dump(cresp, sizeof cresp, "resp");
    dump(ke1, sizeof ke2, "ke2");
    exit(1);
  }
  if(memcmp(ke2, cresp, sizeof cresp)!=0) {
    fprintf(stderr,"failed to reproduce ke2\n");
    dump(cresp, sizeof cresp, "resp");
    dump(ke2, sizeof ke2, "ke2");
    exit(1);
  }

  uint8_t skU[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authUu[crypto_auth_hmacsha512_BYTES];
  uint8_t export_keyU[crypto_hash_sha512_BYTES];
  Opaque_Ids ids1={0};
  opaque_RecoverCredentials(cresp, sec, context, sizeof context, &ids1, skU, authUu, export_keyU);

  if(memcmp(session_key, skU, sizeof session_key)!=0) {
    fprintf(stderr,"failed to reproduce session_key\n");
    dump(skU, sizeof skU, "skU");
    dump(session_key, sizeof session_key, "session_key");
    exit(1);
  }

  if(memcmp(export_key, export_keyU, sizeof export_key)!=0) {
    fprintf(stderr,"failed to reproduce export_key\n");
    dump(export_keyU, sizeof export_keyU, "export_keyU");
    dump(export_key, sizeof export_key, "export_key");
    exit(1);
  }

  if(memcmp(authU, authUu, sizeof authU)!=0) {
    fprintf(stderr,"failed to reproduce authU\n");
    dump(authUu, sizeof authUu, "authUu");
    dump(authU, sizeof authU, "authU");
    exit(1);
  }

  fprintf(stderr,"all ok\n");
  return 0;
}
