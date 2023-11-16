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

#define MUNIT_ENABLE_ASSERT_ALIASES
#include "munit/munit.h"

#include <stdio.h>
#include "../opaque.h"
#include "../common.h"

static char* type_params[] = {
  "0",
  "1",
  "2",
  "3",
  NULL
};

static char* pwdU_params[] = {
  "simple guessable dictionary password",
  "",
  NULL
};

static char* idU_params[] = {
  "user",
  "",
  NULL
};

static char* idS_params[] = {
  "server",
  "",
  NULL
};


static MunitParameterEnum init_params[] = {
  { "pwdU", pwdU_params },
  { "idU", idU_params },
  { "idS", idS_params },
  { "type", type_params },
  { NULL, NULL },
};

typedef enum {
              ServerInit = '0',
              Server1kInit = '1',
              PrivateInit = '2',
              Private1kInit = '3'
} TestType;

MunitResult opaque_test(const MunitParameter params[], void* user_data_or_fixture) {
  // variant where user registration does not leak secrets to server
  (void)user_data_or_fixture;
  const TestType type = *((const TestType*)munit_parameters_get(params, "type"));
  const uint8_t *pwdU=(const uint8_t*) munit_parameters_get(params, "pwdU");
  const size_t pwdU_len=strlen((char*) pwdU);
  uint8_t export_key[crypto_hash_sha512_BYTES];

  Opaque_Ids ids={0, (uint8_t*) munit_parameters_get(params, "idU"),
                  0, (uint8_t*) munit_parameters_get(params, "idS")};
  ids.idU_len = strlen((char*)ids.idU);
  ids.idS_len = strlen((char*)ids.idS);

  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t pk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t authUs[crypto_auth_hmacsha512_BYTES];
  // in case we omit the id* in the envelope we must provide it before-hand.
  // if it is in the envelope it will be populated from the envelope
  uint8_t M[crypto_core_ristretto255_BYTES];
  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];

  uint8_t _skS[crypto_scalarmult_SCALARBYTES];
  uint8_t *skS;
  if(type==Private1kInit || type==Server1kInit) {
    skS=_skS;
    randombytes(skS, crypto_scalarmult_SCALARBYTES);
  } else {
    skS=NULL;
  }

  if(type==ServerInit || type==Server1kInit) {
    // register user
    fprintf(stderr,"\nopaque_Register\n");
    if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) {
      fprintf(stderr,"opaque_Register failed.\n");
      return MUNIT_FAIL;
    }
  } else {
    // user initiates:
    fprintf(stderr,"\nopaque_CreateRegistrationRequest\n");
    if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, usr_ctx, M)) {
      fprintf(stderr,"opaque_CreateRegistrationRequest failed.\n");
      return MUNIT_FAIL;
    }
    // server responds
    uint8_t rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
    fprintf(stderr,"\nopaque_CreateRegistrationResponse\n");
    if(0!=opaque_CreateRegistrationResponse(M, skS, rsec, rpub)) {
      fprintf(stderr,"opaque_CreateRegistrationResponse failed.\n");
      return MUNIT_FAIL;
    }
    // user commits its secrets
    fprintf(stderr,"\nopaque_FinalizeRequest\n");
    unsigned char rrec[OPAQUE_REGISTRATION_RECORD_LEN]={0};
    if(0!=opaque_FinalizeRequest(usr_ctx, rpub, &ids, rrec, export_key)) {
      fprintf(stderr,"opaque_FinalizeRequest failed.\n");
      return MUNIT_FAIL;
    }
    // server "saves"
    fprintf(stderr,"\nopaque_Store1kUserRecord\n");
    opaque_StoreUserRecord(rsec, rrec, rec);
  }

  fprintf(stderr,"\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
  fprintf(stderr,"\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, (uint8_t*)"munit", 5, resp, sk, authUs)) {
    fprintf(stderr,"opaque_CreateCredentialResponse failed.\n");
    return MUNIT_FAIL;
  }
  fprintf(stderr,"\nopaque_RecoverCredentials\n");

  if(0!=opaque_RecoverCredentials(resp, sec, (uint8_t*)"munit", 5, &ids, pk, authU, export_key)) {
    fprintf(stderr,"opaque_RecoverCredentials failed.\n");
    return MUNIT_FAIL;
  }
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:
  if(0!=opaque_UserAuth(authUs, authU)) {
    fprintf(stderr,"failed authenticating user\n");
    return MUNIT_FAIL;
  }

  printf("\n");

  return MUNIT_OK;
}

MunitTest tests[] = {
  { "/server-init", /* name */
    opaque_test, /* test */
    NULL, /* setup */
    NULL, /* tear_down */
    MUNIT_TEST_OPTION_NONE, /* options */
    init_params /* parameters */
  },
  /* Mark the end of the array with an entry where the test
   * function is NULL */
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};


static const MunitSuite suite = {
  "/opaque-tests",
  tests, /* tests */
  NULL, /* suites */
  1, /* iterations */
  MUNIT_SUITE_OPTION_NONE /* options */
};

int main (int argc, char* const argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
