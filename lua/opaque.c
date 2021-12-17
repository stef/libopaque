#include <stdint.h>
#include <string.h>

#include <lua5.3/lua.h>
#include <lua5.3/lauxlib.h>
#include <opaque.h>

static Opaque_PkgTarget getcfgval(lua_State *L, int index, const char *field) {
  int  type, val;
  type=lua_getfield (L, index, field);
  if(type!=LUA_TNUMBER) {
    lua_pushstring(L, "invalid cfg value for skU");
    return lua_error(L);
  }
  val = lua_tointeger(L,-1);
  if(val!=NotPackaged && val!= InSecEnv && val!=InClrEnv) {
    lua_pushstring(L, "invalid cfg value for skU");
    return lua_error(L);
  }
  lua_remove(L,-1);
  return (Opaque_PkgTarget) val;
}

static void getcfg(lua_State *L, int index, Opaque_PkgConfig *cfg) {
  //const char *fields[6]={"skU", "pkU", "pkS", "idU", "idS",NULL};
  cfg->skU = getcfgval(L, index, "skU");
  cfg->pkU = getcfgval(L, index, "pkU");
  cfg->pkS = getcfgval(L, index, "pkS");
  cfg->idU = getcfgval(L, index, "idU");
  cfg->idS = getcfgval(L, index, "idS");
}

static Opaque_App_Infos* get_infos(lua_State *L, Opaque_App_Infos *infos, const int index) {
  Opaque_App_Infos *ret=NULL;

  if(lua_isnil(L,index)) return NULL;

  lua_pushinteger(L,1);
  lua_gettable(L,index);
  if(!lua_isnil(L,-1)) {
    if(!lua_isstring(L,-1)) {
      lua_pushstring(L, "invalid infos value");
      lua_error(L);
    }
    infos->info = (uint8_t*) lua_tolstring(L,-1, &infos->info_len);
    ret = infos;
  }

  lua_pushinteger(L,2);
  lua_gettable(L,index);
  if(!lua_isnil(L,-1)) {
    if(!lua_isstring(L,-1)) {
      lua_pushstring(L, "invalid einfos value");
      lua_error(L);
    }
    infos->einfo = (uint8_t*) lua_tolstring(L,-1, &infos->einfo_len);
    ret = infos;
  }
  return ret;
}

static int reg(lua_State *L) {
  //int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len, const uint8_t skS[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);

  const uint8_t *pwdU, *skS;
  size_t pwdU_len, skS_len;

  pwdU=(const uint8_t *)luaL_checklstring(L,1,&pwdU_len);
  skS=(const uint8_t *) luaL_optlstring(L,2,NULL,&skS_len);
  if(skS != NULL && skS_len!=crypto_scalarmult_SCALARBYTES)  {
    lua_pushstring(L, "invalid server key length, must be 32");
    return lua_error(L);
  }
  Opaque_PkgConfig cfg;
  getcfg(L, 3, &cfg);
  //fprintf(stderr, "skU: %d, pkU: %d, pkS: %d, idU: %d, idS: %d\n", cfg.skU, cfg.pkU, cfg.pkS, cfg.idU, cfg.idS);

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

  uint8_t export_key[crypto_hash_sha256_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key)) {
    lua_pushstring(L, "opaque register failed.");
    return lua_error(L);
  }

  luaL_Buffer r, ek;
  char *ptr = luaL_buffinitsize(L, &r, OPAQUE_USER_RECORD_LEN+envU_len);
  memcpy(ptr,rec,OPAQUE_USER_RECORD_LEN+envU_len);
  luaL_pushresultsize(&r, OPAQUE_USER_RECORD_LEN+envU_len);
  ptr = luaL_buffinitsize(L, &ek, crypto_hash_sha256_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha256_BYTES);
  luaL_pushresultsize(&ek, crypto_hash_sha256_BYTES);

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
//int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], uint8_t *sk, uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);

  const uint8_t *pub, // OPAQUE_USER_SESSION_PUBLIC_LEN
                *rec; // OPAQUE_USER_RECORD_LEN+envU_len
  size_t pub_len, rec_len;

  pub=(const uint8_t *)luaL_checklstring(L,1,&pub_len);
  if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    lua_pushstring(L, "invalid request size");
    return lua_error(L);
  }

  rec=(const uint8_t *) luaL_checklstring(L,2,&rec_len);

  Opaque_PkgConfig cfg;
  getcfg(L, 3, &cfg);

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

  Opaque_App_Infos infos={0}, *infos_p=get_infos(L, &infos, 6);

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  if(rec_len!=OPAQUE_USER_RECORD_LEN+envU_len)  {
    lua_pushstring(L, "invalid record size");
    return lua_error(L);
  }

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, infos_p, resp, sk, sec)) {
    lua_pushstring(L, "opaque create credential response failed.");
    return lua_error(L);
  }

  luaL_Buffer resp_, sk_, sec_;
  char *ptr = luaL_buffinitsize(L, &resp_, OPAQUE_SERVER_SESSION_LEN+envU_len);
  memcpy(ptr,resp,OPAQUE_SERVER_SESSION_LEN+envU_len);
  luaL_pushresultsize(&resp_, OPAQUE_SERVER_SESSION_LEN+envU_len);

  ptr = luaL_buffinitsize(L, &sk_, OPAQUE_SHARED_SECRETBYTES);
  memcpy(ptr,sk, OPAQUE_SHARED_SECRETBYTES);
  luaL_pushresultsize(&sk_, OPAQUE_SHARED_SECRETBYTES);

  ptr = luaL_buffinitsize(L, &sec_, OPAQUE_SERVER_AUTH_CTX_LEN);
  memcpy(ptr,sec, OPAQUE_SERVER_AUTH_CTX_LEN);
  luaL_pushresultsize(&sec_, OPAQUE_SERVER_AUTH_CTX_LEN);

  return 3;
}

static int recover_creds(lua_State *L) {
//int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/], const uint8_t pkS[crypto_scalarmult_BYTES], const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t *sk, uint8_t authU[crypto_auth_hmacsha256_BYTES], uint8_t export_key[crypto_hash_sha256_BYTES]);

  const uint8_t *resp, *sec, *pkS;
  size_t resp_len, sec_len, pkS_len;

  resp=(const uint8_t *)luaL_checklstring(L,1,&resp_len); // length validation below after we have envU_len

  sec=(const uint8_t *) luaL_checklstring(L,2,&sec_len);
  if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
    lua_pushstring(L, "sec parameter too short");
    return lua_error(L);
  }

  pkS=(uint8_t *) luaL_optlstring(L,3,NULL,&pkS_len);
  if(pkS && pkS_len!=crypto_scalarmult_BYTES) {
    lua_pushstring(L, "pkS has invalid size");
    return lua_error(L);
  }

  Opaque_PkgConfig cfg;
  getcfg(L, 4, &cfg);

  if (cfg.pkS==NotPackaged && pkS==NULL) {
    lua_pushstring(L, "pkS cannot be None if cfg.pkS is NotPackaged.");
    return lua_error(L);
  }
  if (cfg.pkS!=NotPackaged && pkS!=NULL) {
    lua_pushstring(L, "pkS cannot be redundantly provided and packaged according to cfg.pkS.");
    return lua_error(L);
  }

  Opaque_App_Infos infos={0}, *infos_p=get_infos(L, &infos, 5);

  uint8_t idU[65535]={0}, idS[65535]={0};
  size_t idU_len=sizeof(idU), idS_len=sizeof(idS), id_len;
  uint8_t *id=(uint8_t *) luaL_optlstring(L,6,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idU too long");
    return lua_error(L);
  }
  if (cfg.idU==NotPackaged) {
    if (id==NULL) {
      lua_pushstring(L, "idU cannot be NULL if cfg.idU is NotPackaged.");
      return lua_error(L);
    }
    memcpy(idU, id, id_len);
    idU_len = id_len;
  } else {
    if (id!=NULL) {
      lua_pushstring(L, "idU cannot be supplied if cfg.idU is packaged.");
      return lua_error(L);
    }
    idU_len = sizeof(idU);
  }

  id=(uint8_t *) luaL_optlstring(L,7,NULL,&id_len);
  if(id_len>(2<<16)-1) {
    lua_pushstring(L, "idS too long");
    return lua_error(L);
  }
  if (cfg.idU==NotPackaged) {
    if (id==NULL) {
      lua_pushstring(L, "idS cannot be NULL if cfg.idS is NotPackaged.");
      return lua_error(L);
    }
    memcpy(idS, id, id_len);
    idS_len = id_len;
  } else {
    if (id!=NULL) {
      lua_pushstring(L, "idS cannot be supplied if cfg.idU is packaged.");
      return lua_error(L);
    }
    idS_len = sizeof(idS);
  }

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);

  if(resp_len<=OPAQUE_SERVER_SESSION_LEN+envU_len) {
    fprintf(stderr, "resplen: %ld, expected: %ld\n", resp_len, OPAQUE_SERVER_SESSION_LEN+envU_len);
    lua_pushstring(L, "invalid response size");
    return lua_error(L);
  }

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t export_key[crypto_hash_sha256_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, pkS, &cfg, infos_p, &ids, sk, authU, export_key)) {
    lua_pushstring(L, "opaque recover credentials failed.");
    return lua_error(L);
  }

  luaL_Buffer sk_, authU_, ek_;
  char *ptr = luaL_buffinitsize(L, &sk_, OPAQUE_SHARED_SECRETBYTES);
  memcpy(ptr,sk,OPAQUE_SHARED_SECRETBYTES);
  luaL_pushresultsize(&sk_, OPAQUE_SHARED_SECRETBYTES);

  ptr = luaL_buffinitsize(L, &authU_, crypto_auth_hmacsha256_BYTES);
  memcpy(ptr,authU, crypto_auth_hmacsha256_BYTES);
  luaL_pushresultsize(&authU_, crypto_auth_hmacsha256_BYTES);

  ptr = luaL_buffinitsize(L, &ek_, crypto_hash_sha256_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha256_BYTES);
  luaL_pushresultsize(&ek_, crypto_hash_sha256_BYTES);

  return 3;
}

static int user_auth(lua_State *L) {
// int opaque_UserAuth(const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES]);

  const uint8_t *sec, *authU;
  size_t sec_len, authU_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len!=OPAQUE_SERVER_AUTH_CTX_LEN) {
    lua_pushstring(L, "sec parameter too short");
    return lua_error(L);
  }

  authU=(const uint8_t *) luaL_checklstring(L,2,&authU_len);
  if(authU_len!=crypto_auth_hmacsha256_BYTES) {
    lua_pushstring(L, "authU parameter too short");
    return lua_error(L);
  }

  lua_pushboolean(L, !opaque_UserAuth(sec, authU));

  return 1;
}

static int create_reg_req(lua_State *L) {
//int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t M[crypto_core_ristretto255_BYTES]);
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
//int opaque_CreateRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
  const uint8_t *M;
  size_t M_len;

  M=(const uint8_t *)luaL_checklstring(L,1,&M_len);
  if(M_len!=crypto_core_ristretto255_BYTES)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(M, sec, pub)) {
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

static int create_1k_reg_resp(lua_State *L) {
//int opaque_Create1kRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
  const uint8_t *M, *pkS;
  size_t M_len, pkS_len;

  M=(const uint8_t *)luaL_checklstring(L,1,&M_len);
  if(M_len!=crypto_core_ristretto255_BYTES)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  pkS=(const uint8_t *)luaL_checklstring(L,2,&pkS_len);
  if(pkS_len!=crypto_scalarmult_BYTES)  {
    lua_pushstring(L, "invalid pkS size");
    return lua_error(L);
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_Create1kRegistrationResponse(M, pkS, sec, pub)) {
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
//int opaque_FinalizeRequest(const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);

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
  Opaque_PkgConfig cfg;
  getcfg(L, 3, &cfg);
  //fprintf(stderr, "skU: %d, pkU: %d, pkS: %d, idU: %d, idS: %d\n", cfg.skU, cfg.pkU, cfg.pkS, cfg.idU, cfg.idS);

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

  uint8_t export_key[crypto_hash_sha256_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key)) {
    lua_pushstring(L, "opaque finalize request failed.");
    return lua_error(L);
  }

  luaL_Buffer r, ek;
  char *ptr = luaL_buffinitsize(L, &r, OPAQUE_USER_RECORD_LEN+envU_len);
  memcpy(ptr,rec,OPAQUE_USER_RECORD_LEN+envU_len);
  luaL_pushresultsize(&r, OPAQUE_USER_RECORD_LEN+envU_len);

  ptr = luaL_buffinitsize(L, &ek, crypto_hash_sha256_BYTES);
  memcpy(ptr,export_key, crypto_hash_sha256_BYTES);
  luaL_pushresultsize(&ek, crypto_hash_sha256_BYTES);

  return 2;
}

static int store_rec(lua_State *L) {
//void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
  const uint8_t *sec;
  uint8_t *rec;
  size_t sec_len, rec_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  rec=(uint8_t *)luaL_checklstring(L,2,&rec_len);
  if(rec_len<=OPAQUE_USER_RECORD_LEN)  {
    lua_pushstring(L, "invalid record size");
    return lua_error(L);
  }

  opaque_StoreUserRecord(sec, rec);

  luaL_Buffer r;
  char *ptr = luaL_buffinitsize(L, &r, rec_len);
  memcpy(ptr,rec,rec_len);
  luaL_pushresultsize(&r, rec_len);

  return 1;
}

static int store_1krec(lua_State *L) {
//void opaque_Store1kUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
  const uint8_t *sec, *skS;
  uint8_t *rec;
  size_t sec_len, rec_len, skS_len;

  sec=(const uint8_t *)luaL_checklstring(L,1,&sec_len);
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN)  {
    lua_pushstring(L, "invalid message length");
    return lua_error(L);
  }

  skS=(uint8_t *)luaL_checklstring(L,2,&skS_len);
  if(skS_len!=crypto_scalarmult_SCALARBYTES)  {
    lua_pushstring(L, "invalid server private key size");
    return lua_error(L);
  }

  rec=(uint8_t *)luaL_checklstring(L,3,&rec_len);
  if(rec_len<=OPAQUE_USER_RECORD_LEN)  {
    lua_pushstring(L, "invalid record size");
    return lua_error(L);
  }

  opaque_Store1kUserRecord(sec, skS, rec);

  luaL_Buffer r;
  char *ptr = luaL_buffinitsize(L, &r, rec_len);
  memcpy(ptr,rec,rec_len);
  luaL_pushresultsize(&r, rec_len);

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
  { "create1kRegistrationResp", create_1k_reg_resp},
  { "finalizeReq", finalize_req},
  { "storeRec", store_rec},
  { "store1kRec", store_1krec},
  { NULL, NULL }
};

int luaopen_opaque(lua_State *L) {
  luaL_newlib(L,opaque_registry);
  lua_pushinteger(L,NotPackaged);
  lua_setfield(L,-2,"NotPackaged");
  lua_pushinteger(L,InSecEnv);
  lua_setfield(L,-2,"InSecEnv");
  lua_pushinteger(L,InClrEnv);
  lua_setfield(L,-2,"InClrEnv");
  return 1;
}
