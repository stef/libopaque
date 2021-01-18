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

#define MUNIT_ENABLE_ASSERT_ALIASES
#include "munit/munit.h"

#include <stdio.h>
#include "../opaque.h"
#include "../common.h"

typedef struct {
  uint8_t kU[crypto_core_ristretto255_SCALARBYTES];
  uint8_t skS[crypto_scalarmult_SCALARBYTES];
  uint8_t pkU[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
  uint32_t envU_len;
  uint8_t envU[];
} __attribute((packed)) Opaque_UserRecord;

static char* type_params[] = {
  "\x00",
  "\x01",
  "\x02",
  "\x03",
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

static char* cfg_params[]=
  {"\x10\x00",
   "\x10\x01",
   "\x10\x02",
   "\x50\x00",
   "\x50\x01",
   "\x50\x02",
   "\x90\x00",
   "\x90\x01",
   "\x90\x02",
   "\x20\x00",
   "\x20\x01",
   "\x20\x02",
   "\x60\x00",
   "\x60\x01",
   "\x60\x02",
   "\xa0\x00",
   "\xa0\x01",
   "\xa0\x02",
   "\x14\x00",
   "\x14\x01",
   "\x14\x02",
   "\x54\x00",
   "\x54\x01",
   "\x54\x02",
   "\x94\x00",
   "\x94\x01",
   "\x94\x02",
   "\x24\x00",
   "\x24\x01",
   "\x24\x02",
   "\x64\x00",
   "\x64\x01",
   "\x64\x02",
   "\xa4\x00",
   "\xa4\x01",
   "\xa4\x02",
   "\x18\x00",
   "\x18\x01",
   "\x18\x02",
   "\x58\x00",
   "\x58\x01",
   "\x58\x02",
   "\x98\x00",
   "\x98\x01",
   "\x98\x02",
   "\x28\x00",
   "\x28\x01",
   "\x28\x02",
   "\x68\x00",
   "\x68\x01",
   "\x68\x02",
   "\xa8\x00",
   "\xa8\x01",
   "\xa8\x02",
   "\x11\x00",
   "\x11\x01",
   "\x11\x02",
   "\x51\x00",
   "\x51\x01",
   "\x51\x02",
   "\x91\x00",
   "\x91\x01",
   "\x91\x02",
   "\x21\x00",
   "\x21\x01",
   "\x21\x02",
   "\x61\x00",
   "\x61\x01",
   "\x61\x02",
   "\xa1\x00",
   "\xa1\x01",
   "\xa1\x02",
   "\x15\x00",
   "\x15\x01",
   "\x15\x02",
   "\x55\x00",
   "\x55\x01",
   "\x55\x02",
   "\x95\x00",
   "\x95\x01",
   "\x95\x02",
   "\x25\x00",
   "\x25\x01",
   "\x25\x02",
   "\x65\x00",
   "\x65\x01",
   "\x65\x02",
   "\xa5\x00",
   "\xa5\x01",
   "\xa5\x02",
   "\x19\x00",
   "\x19\x01",
   "\x19\x02",
   "\x59\x00",
   "\x59\x01",
   "\x59\x02",
   "\x99\x00",
   "\x99\x01",
   "\x99\x02",
   "\x29\x00",
   "\x29\x01",
   "\x29\x02",
   "\x69\x00",
   "\x69\x01",
   "\x69\x02",
   "\xa9\x00",
   "\xa9\x01",
   "\xa9\x02",
   NULL
};

static MunitParameterEnum init_params[] = {
  { "pwdU", pwdU_params },
  { "idU", idU_params },
  { "idS", idS_params },
  { "cfg", cfg_params },
  { "type", type_params },
  { NULL, NULL },
};

typedef enum {
              ServerInit,
              Server1kInit,
              PrivateInit,
              Private1kInit
} TestType;

MunitResult opaque_test(const MunitParameter params[], void* user_data_or_fixture) {
  // variant where user registration does not leak secrets to server
  (void)user_data_or_fixture;
  const TestType type = *((const TestType*)munit_parameters_get(params, "type"));
  const uint8_t *pwdU=(const uint8_t*) munit_parameters_get(params, "pwdU");
  const size_t pwdU_len=strlen((char*) pwdU);
  uint8_t export_key[crypto_hash_sha256_BYTES];

  Opaque_Ids ids={0, (uint8_t*) munit_parameters_get(params, "idU"),
                  0, (uint8_t*) munit_parameters_get(params, "idS")};
  ids.idU_len = strlen((char*)ids.idU);
  ids.idS_len = strlen((char*)ids.idS);

  Opaque_PkgConfig *cfg=(Opaque_PkgConfig *) munit_parameters_get(params, "cfg");
  fprintf(stderr, "cfg sku: %d, pku:%d, pks:%d, idu:%d, ids:%d\n", cfg->skU, cfg->pkU, cfg->pkS, cfg->idU, cfg->idS);

  const uint32_t envU_len = opaque_envelope_len(cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];
  fprintf(stderr,"sizeof(rec): %ld\n",sizeof(rec));

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
  uint8_t sk[32];
  uint8_t pk[32];
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t idU[ids.idU_len], idS[ids.idS_len]; // must be big enough to fit ids
  Opaque_Ids ids1={sizeof idU,idU,sizeof idS,idS};
  // in case we omit the id* in the envelope we must provide it before-hand.
  // if it is in the envelope it will be populated from the envelope
  if(cfg->idU == NotPackaged) {
    ids1.idU_len = ids.idU_len;
    memcpy(idU, ids.idU, ids.idU_len);
  }
  if(cfg->idS == NotPackaged) {
    ids1.idS_len = ids.idS_len;
    memcpy(idS, ids.idS, ids.idS_len);
  }
  uint8_t ctx[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

  uint8_t M[crypto_core_ristretto255_BYTES];
  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];

  uint8_t _skS[crypto_scalarmult_SCALARBYTES], _pkS[crypto_scalarmult_BYTES];
  uint8_t *skS, *pkS;
  if(type==Private1kInit || type==Server1kInit) {
    skS=_skS;
    pkS=_pkS;
    randombytes(skS, crypto_scalarmult_SCALARBYTES);
    crypto_scalarmult_base(pkS, skS);
  } else {
    skS=NULL;
    pkS=NULL;
  }

  if(type==ServerInit || type==Server1kInit) {
    // register user
    fprintf(stderr,"\nopaque_Register\n");
    if(0!=opaque_Register(pwdU, pwdU_len, skS, cfg, &ids, rec, export_key)) {
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
    if(type==Private1kInit) {
      fprintf(stderr,"\nopaque_Create1kRegistrationResponse\n");
      if(0!=opaque_Create1kRegistrationResponse(M, pkS, rsec, rpub)) {
        fprintf(stderr,"opaque_Create1kRegistrationResponse failed.\n");
        return MUNIT_FAIL;
      }
    } else {
      fprintf(stderr,"\nopaque_CreateRegistrationResponse\n");
      if(0!=opaque_CreateRegistrationResponse(M, rsec, rpub)) {
        fprintf(stderr,"opaque_CreateRegistrationResponse failed.\n");
        return MUNIT_FAIL;
      }
    }
    // user commits its secrets
    fprintf(stderr,"\nopaque_FinalizeRequest\n");
    if(0!=opaque_FinalizeRequest(usr_ctx, rpub, cfg, &ids, rec, export_key)) {
      fprintf(stderr,"opaque_FinalizeRequest failed.\n");
      return MUNIT_FAIL;
    }
    // server "saves"
    if(type==Private1kInit) {
      fprintf(stderr,"\nopaque_Store1kUserRecord\n");
      opaque_Store1kUserRecord(rsec, skS, rec);
    } else {
      fprintf(stderr,"\nopaque_StoreUserRecord\n");
      opaque_StoreUserRecord(rsec, rec);
    }
  }

  fprintf(stderr,"\nopaque_CreateCredentialRequest\n");
  opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
  fprintf(stderr,"\nopaque_CreateCredentialResponse\n");
  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, NULL, resp, sk, ctx)) {
    fprintf(stderr,"opaque_CreateCredentialResponse failed.\n");
    return MUNIT_FAIL;
  }
  fprintf(stderr,"\nopaque_RecoverCredentials\n");

  if(cfg->pkS == NotPackaged) {
    Opaque_UserRecord *_rec = (Opaque_UserRecord *) &rec;
    if(type!=Private1kInit && type!=Server1kInit) {
      pkS = _rec->pkS;
    }
  } else {
    pkS = NULL;
  }

  if(0!=opaque_RecoverCredentials(resp, sec, pkS, cfg, NULL, &ids1, pk, authU, export_key)) {
    fprintf(stderr,"opaque_RecoverCredentials failed.\n");
    return MUNIT_FAIL;
  }
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:
  if(-1==opaque_UserAuth(ctx, authU, NULL)) {
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
  cfg_params[2]=NULL;
  return munit_suite_main(&suite, NULL, argc, argv);
}
