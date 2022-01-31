#include <stdint.h>
#include <string.h>

#include <lua5.3/lua.h>
#include <lua5.3/lauxlib.h>
#include <opaque.h>

static int reg(lua_State *L) {
  const uint8_t *pwdU, *skS;
  size_t pwdU_len, skS_len;

  pwdU=(const uint8_t *)luaL_checklstring(L,1,&pwdU_len);

  skS=(const uint8_t *) luaL_optlstring(L,2,NULL,&skS_len);
  if(skS != NULL && skS_len!=crypto_scalarmult_SCALARBYTES)  {
    lua_pushstring(L, "invalid server key length, must be 32");
    return lua_error(L);
  }

  Opaque_Ids ids;
  size_t id_len;
  ids.idU=(uint8_t *) luaL_optlstring(L,3,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idU_len=id_len;
  ids.idS=(uint8_t *) luaL_optlstring(L,4,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idS_len=id_len;

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) {
    lua_pushstring(L, "opaque register failed.");
    return lua_error(L);
  }

  luaL_Buffer r, ek;
  char *ptr = luaL_buffinitsize(L, &r, OPAQUE_USER_RECORD_LEN);
  memcpy(ptr,rec,OPAQUE_USER_RECORD_LEN);
  luaL_pushresultsize(&r, OPAQUE_USER_RECORD_LEN);
  ptr = luaL_buffinitsize(L, &ek, crypto_hash_sha512_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha512_BYTES);
  luaL_pushresultsize(&ek, crypto_hash_sha512_BYTES);

  return 2;
}

static int create_cred_req(lua_State *L) {
  const uint8_t *pwdU;
  size_t pwdU_len;

  pwdU=(const uint8_t *)luaL_checklstring(L,1,&pwdU_len);

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
    pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  // todo sodium_mlock(sec)

  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) {
    lua_pushstring(L, "failed to create an opaque credential request.");
    return lua_error(L);
  }

  luaL_Buffer s, p;
  char *ptr = luaL_buffinitsize(L, &s, OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len);
  memcpy(ptr,sec,OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len);
  // todo sodium_mlock(ptr)
  luaL_pushresultsize(&s, OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len);

  ptr = luaL_buffinitsize(L, &p, OPAQUE_USER_SESSION_PUBLIC_LEN);
  memcpy(ptr,pub, OPAQUE_USER_SESSION_PUBLIC_LEN);
  luaL_pushresultsize(&p, OPAQUE_USER_SESSION_PUBLIC_LEN);

  return 2;
}

static int create_cred_resp(lua_State *L) {
  const uint8_t *pub, // OPAQUE_USER_SESSION_PUBLIC_LEN
                *rec, // OPAQUE_USER_RECORD_LEN+envU_len
                *context;
  size_t pub_len, rec_len, context_len;

  pub=(const uint8_t *)luaL_checklstring(L,1,&pub_len);
  if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    lua_pushstring(L, "invalid request size");
    return lua_error(L);
  }

  rec=(const uint8_t *) luaL_checklstring(L,2,&rec_len);
  if(rec_len!=OPAQUE_USER_RECORD_LEN)  {
    lua_pushstring(L, "invalid record size");
    return lua_error(L);
  }

  context=(const uint8_t *) luaL_checklstring(L,3,&context_len);

  Opaque_Ids ids;
  size_t id_len;
  ids.idU=(uint8_t *) luaL_optlstring(L,4,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idU_len=id_len;
  ids.idS=(uint8_t *) luaL_optlstring(L,5,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idS_len=id_len;


  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[crypto_auth_hmacsha512_BYTES]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, sec)) {
    lua_pushstring(L, "opaque create credential response failed.");
    return lua_error(L);
  }

  luaL_Buffer resp_, sk_, sec_;
  char *ptr = luaL_buffinitsize(L, &resp_, OPAQUE_SERVER_SESSION_LEN);
  memcpy(ptr,resp,OPAQUE_SERVER_SESSION_LEN);
  luaL_pushresultsize(&resp_, OPAQUE_SERVER_SESSION_LEN);

  ptr = luaL_buffinitsize(L, &sk_, OPAQUE_SHARED_SECRETBYTES);
  memcpy(ptr,sk, OPAQUE_SHARED_SECRETBYTES);
  luaL_pushresultsize(&sk_, OPAQUE_SHARED_SECRETBYTES);

  ptr = luaL_buffinitsize(L, &sec_, crypto_auth_hmacsha512_BYTES);
  memcpy(ptr,sec, crypto_auth_hmacsha512_BYTES);
  luaL_pushresultsize(&sec_, crypto_auth_hmacsha512_BYTES);

  return 3;
}

static int recover_creds(lua_State *L) {
  const uint8_t *resp, *sec, *context, *pub;
  size_t resp_len, sec_len, context_len, pub_len;

  resp=(const uint8_t *)luaL_checklstring(L,1,&resp_len); // length validation below after we have envU_len
  if(resp_len!=OPAQUE_SERVER_SESSION_LEN) {
    lua_pushstring(L, "invalid response size");
    return lua_error(L);
  }

  sec=(const uint8_t *) luaL_checklstring(L,2,&sec_len);
  if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
    lua_pushstring(L, "sec parameter too short");
    return lua_error(L);
  }

  context=(const uint8_t *) luaL_checklstring(L,3,&context_len);

  Opaque_Ids ids;
  size_t id_len;
  ids.idU=(uint8_t *) luaL_optlstring(L,4,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idU_len=id_len;
  ids.idS=(uint8_t *) luaL_optlstring(L,5,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idS_len=id_len;

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key)) {
    lua_pushstring(L, "opaque recover credentials failed.");
    return lua_error(L);
  }

  luaL_Buffer sk_, authU_, ek_;
  char *ptr = luaL_buffinitsize(L, &sk_, OPAQUE_SHARED_SECRETBYTES);
  memcpy(ptr,sk,OPAQUE_SHARED_SECRETBYTES);
  luaL_pushresultsize(&sk_, OPAQUE_SHARED_SECRETBYTES);

  ptr = luaL_buffinitsize(L, &authU_, crypto_auth_hmacsha512_BYTES);
  memcpy(ptr,authU, crypto_auth_hmacsha512_BYTES);
  luaL_pushresultsize(&authU_, crypto_auth_hmacsha512_BYTES);

  ptr = luaL_buffinitsize(L, &ek_, crypto_hash_sha512_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha512_BYTES);
  luaL_pushresultsize(&ek_, crypto_hash_sha512_BYTES);

  return 3;
}

static int user_auth(lua_State *L) {
  const uint8_t *sec, *authU;
  size_t sec_len, authU_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len!=crypto_auth_hmacsha512_BYTES) {
    lua_pushstring(L, "sec parameter too short");
    return lua_error(L);
  }

  authU=(const uint8_t *) luaL_checklstring(L,2,&authU_len);
  if(authU_len!=crypto_auth_hmacsha512_BYTES) {
    lua_pushstring(L, "authU parameter too short");
    return lua_error(L);
  }

  lua_pushboolean(L, !opaque_UserAuth(sec, authU));

  return 1;
}

static int create_reg_req(lua_State *L) {
  const uint8_t *pwdU;
  size_t pwdU_len;

  pwdU=(const uint8_t *)luaL_checklstring(L,1,&pwdU_len);

  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];
  uint8_t M[crypto_core_ristretto255_BYTES];

  if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M)) {
    lua_pushstring(L, "opaque create registation request failed.");
    return lua_error(L);
  }

  luaL_Buffer s, m;
  char *ptr = luaL_buffinitsize(L, &s, OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len);
  memcpy(ptr,sec,OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len);
  luaL_pushresultsize(&s, OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len);

  ptr = luaL_buffinitsize(L, &m, crypto_core_ristretto255_BYTES);
  memcpy(ptr,M, crypto_core_ristretto255_BYTES);
  luaL_pushresultsize(&m, crypto_core_ristretto255_BYTES);

  return 2;
}

static int create_reg_resp(lua_State *L) {
  const uint8_t *M, *skS=NULL;
  size_t M_len, skS_len;

  M=(const uint8_t *)luaL_checklstring(L,1,&M_len);
  if(M_len!=crypto_core_ristretto255_BYTES)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  skS=(const uint8_t *)luaL_optlstring(L,2,NULL,&skS_len);
  if(skS != NULL && skS_len!=crypto_scalarmult_SCALARBYTES)  {
    lua_pushstring(L, "invalid skS size");
    return lua_error(L);
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(M, skS, sec, pub)) {
    lua_pushstring(L, "opaque create registration response failed.");
    return lua_error(L);
  }

  luaL_Buffer s, p;
  char *ptr = luaL_buffinitsize(L, &s, OPAQUE_REGISTER_SECRET_LEN);
  memcpy(ptr,sec,OPAQUE_REGISTER_SECRET_LEN);
  luaL_pushresultsize(&s, OPAQUE_REGISTER_SECRET_LEN);

  ptr = luaL_buffinitsize(L, &p, OPAQUE_REGISTER_PUBLIC_LEN);
  memcpy(ptr,pub, OPAQUE_REGISTER_PUBLIC_LEN);
  luaL_pushresultsize(&p, OPAQUE_REGISTER_PUBLIC_LEN);

  return 2;
}

static int finalize_req(lua_State *L) {
  const uint8_t *sec, *pub;
  size_t sec_len, pub_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len<=OPAQUE_REGISTER_USER_SEC_LEN)  {
    lua_pushstring(L, "invalid secret client context size");
    return lua_error(L);
  }
  pub=(const uint8_t *) luaL_optlstring(L,2,NULL,&pub_len);
  if(pub_len!=OPAQUE_REGISTER_PUBLIC_LEN)  {
    lua_pushstring(L, "invalid response size");
    return lua_error(L);
  }
  Opaque_Ids ids;
  size_t id_len;
  ids.idU=(uint8_t *) luaL_optlstring(L,3,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idU_len=id_len;
  ids.idS=(uint8_t *) luaL_optlstring(L,4,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  ids.idS_len=id_len;

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];

  if(0!=opaque_FinalizeRequest(sec, pub, &ids, rec, export_key)) {
    lua_pushstring(L, "opaque finalize request failed.");
    return lua_error(L);
  }

  luaL_Buffer r, ek;
  char *ptr = luaL_buffinitsize(L, &r, OPAQUE_REGISTRATION_RECORD_LEN);
  memcpy(ptr,rec,OPAQUE_REGISTRATION_RECORD_LEN);
  luaL_pushresultsize(&r, OPAQUE_REGISTRATION_RECORD_LEN);

  ptr = luaL_buffinitsize(L, &ek, crypto_hash_sha512_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha512_BYTES);
  luaL_pushresultsize(&ek, crypto_hash_sha512_BYTES);

  return 2;
}

static int store_rec(lua_State *L) {
//void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
  const uint8_t *sec;
  uint8_t *recU;
  size_t sec_len, recU_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  recU=(uint8_t *)luaL_checklstring(L,2,&recU_len);
  if(recU_len!=OPAQUE_REGISTRATION_RECORD_LEN)  {
    lua_pushstring(L, "invalid record size");
    return lua_error(L);
  }

  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(sec, recU, rec);

  luaL_Buffer r;
  char *ptr = luaL_buffinitsize(L, &r, sizeof rec);
  memcpy(ptr,rec,sizeof rec);
  luaL_pushresultsize(&r, sizeof rec);

  return 1;
}

static const struct luaL_Reg opaque_registry[] = {
  { "register", reg},
  { "createCredentialReq", create_cred_req},
  { "createCredentialResp", create_cred_resp},
  { "recoverCredentials", recover_creds},
  { "userAuth", user_auth},
  { "createRegistrationReq", create_reg_req},
  { "createRegistrationResp", create_reg_resp},
  { "finalizeReq", finalize_req},
  { "storeRec", store_rec},
  { NULL, NULL }
};

int luaopen_opaque(lua_State *L) {
  luaL_newlib(L,opaque_registry);
  return 1;
}
