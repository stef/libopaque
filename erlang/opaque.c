#include <erl_nif.h>
#include <stdio.h>
#include <string.h>
#include <opaque.h>

#define OPAQUE_ERL_NOT_TUPLE 1
#define OPAQUE_ERL_INVALID_CFG_SIZE 2
#define OPAQUE_ERL_INVALID_CFG_ELEM 3
#define OPAQUE_ERL_CFG_WAS_ATOM 4
#define OPAQUE_ERL_TRUNCATED_CFG_ATOM 5
#define OPAQUE_ERL_INVALID_CFG_ATOM 6

static int getcfg(ErlNifEnv* env, const ERL_NIF_TERM tuple, Opaque_PkgConfig *cfg) {
  int items=0, i;
  const ERL_NIF_TERM* array;
  if(!enif_get_tuple(env, tuple, &items, &array)) return OPAQUE_ERL_NOT_TUPLE;
  if(items!=5) {
    return OPAQUE_ERL_INVALID_CFG_SIZE;
  }
  //fprintf(stderr, "cfg items: %d\n", items);
  int atom_len, c;
  for(i=0;i<items;i++) {
    if(!enif_get_atom_length(env, array[i], &atom_len, ERL_NIF_LATIN1)) return OPAQUE_ERL_INVALID_CFG_ELEM;
    char atom[atom_len+1];
    int res = enif_get_atom(env, array[i], atom, atom_len+1, ERL_NIF_LATIN1);
    if(res==0) return OPAQUE_ERL_CFG_WAS_ATOM;
    if(atom_len+1!=res) return OPAQUE_ERL_TRUNCATED_CFG_ATOM;
    //fprintf(stderr, "%s ", atom);
    if(0==memcmp(atom,"notPackaged", 11)) {
      // nothing to do, it maps to 0
      c = 0;
    } else if(0==memcmp(atom,"inSecEnv", 8)) {
      c = 1;
    } else if(0==memcmp(atom,"inClrEnv", 8)) {
      c = 2;
    } else {
      return OPAQUE_ERL_INVALID_CFG_ATOM;
    }
    if(0==i) {
      cfg->skU = c;
    } else if(1==i) {
      cfg->pkU = c;
    } else if(2==i) {
      cfg->pkS = c;
    } else if(3==i) {
      cfg->idU = c;
    } else if(4==i) {
      cfg->idS = c;
    }
  }
  //fprintf(stderr, "\n");
  return 0;
}

static int getids(ErlNifEnv* env, const ERL_NIF_TERM tuple, Opaque_Ids *ids) {
  int items=0;
  const ERL_NIF_TERM* array;
  if(!enif_get_tuple(env, tuple, &items, &array)) {
    enif_raise_exception(env, enif_make_atom(env, "ids_invalid_elems"));
    return 1;
  }
  if(items!=2) {
    enif_raise_exception(env, enif_make_atom(env, "ids_invalid_size"));
    return 1;
  }

  ErlNifBinary bin;
  if(enif_inspect_binary(env, array[0], &bin)) {
    if(bin.size>=(2<<16)) {
        enif_raise_exception(env, enif_make_atom(env, "idU_too_big"));
        return 1;
    }
    ids->idU=(uint8_t*) bin.data;
    ids->idU_len=bin.size;
  } else {
        enif_raise_exception(env, enif_make_atom(env, "idU_missing"));
        return 1;
  }

  if(enif_inspect_binary(env, array[1], &bin)) {
    if(bin.size>=(2<<16)) {
        enif_raise_exception(env, enif_make_atom(env, "idU_too_big"));
        return 1;
    }
    ids->idS=(uint8_t*) bin.data;
    ids->idS_len=bin.size;
  } else {
        enif_raise_exception(env, enif_make_atom(env, "idS_missing"));
        return 1;
  }

  return 0;
}

static Opaque_App_Infos* get_infos(ErlNifEnv* env, const ERL_NIF_TERM tuple, Opaque_App_Infos *infos) {
  Opaque_App_Infos *ret=NULL;

  int items=0;
  const ERL_NIF_TERM* array;
  if(!enif_get_tuple(env, tuple, &items, &array)) return NULL;
  if(items!=2) {
    enif_raise_exception(env, enif_make_atom(env, "infos_invalid_elems"));
    return NULL;
  }

  ErlNifBinary bin;
  if(enif_inspect_binary(env, array[0], &bin)) {
    infos->info=(uint8_t*) bin.data;
    infos->info_len=bin.size;
    ret = infos;
  }

  if(enif_inspect_binary(env, array[1], &bin)) {
    infos->einfo=(uint8_t*) bin.data;
    infos->einfo_len=bin.size;
    ret = infos;
  }

  return ret;
}

static ERL_NIF_TERM c_register(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  //int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len,
  // opt: const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  // const Opaque_PkgConfig *cfg,
  // const Opaque_Ids *ids,
  // uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
  // uint8_t export_key[crypto_hash_sha512_BYTES]);
  unsigned pwdU_len;
  if(!enif_get_list_length(env, argv[0], &pwdU_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_list"));
  }
  char pwdU[pwdU_len+1];
  if (!enif_get_string(env, argv[0], pwdU, pwdU_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_string"));
  }
  //fprintf(stderr,"> %.*s\n", pwdU_len, pwdU);

  int sks_offset = argc == 4;
  uint8_t *skS=NULL;
  ErlNifBinary skS_bin;
  if(sks_offset) {
    if(!enif_inspect_binary(env, argv[1], &skS_bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_not_binary"));
    }
    if(skS_bin.size!=crypto_scalarmult_SCALARBYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_invalid_size"));
    }
    skS=(uint8_t*) skS_bin.data;
    //int k;
    //fprintf(stderr, "skS: ");
    //for(k=0;k<skS_bin.size;k++) {
    //  fprintf(stderr, "%02x", skS[k]);
    //}
    //fprintf(stderr, "\n");
  }

  Opaque_PkgConfig cfg;
  int res = getcfg(env, argv[1+sks_offset], &cfg);
  if(res!=0) {
    return enif_raise_exception(env, enif_make_atom(env, "cfg_parse_error")); // todo pass also res
  }
  //fprintf(stderr,"getcfg returns %d\n", res);
  //fprintf(stderr, "skU: %d, pkU: %d, pkS: %d, idU: %d, idS: %d\n", cfg.skU, cfg.pkU, cfg.pkS, cfg.idU, cfg.idS);

  Opaque_Ids ids;
  res = getids(env, argv[2+sks_offset], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;
  //fprintf(stderr,"idU: \"%.*s\", idS: \"%.*s\"\n", ids.idU_len, ids.idU, ids.idS_len, ids.idS);

  uint8_t export_key[crypto_hash_sha512_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "register_failed"));
  }

  ERL_NIF_TERM r, ek;
  memcpy(enif_make_new_binary(env, sizeof rec, &r), rec, sizeof rec);
  memcpy(enif_make_new_binary(env, sizeof export_key, &ek), export_key, sizeof export_key);
  return enif_make_tuple2(env, r, ek);
}

static ERL_NIF_TERM c_create_cred_req(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
//int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
  unsigned pwdU_len;
  if(!enif_get_list_length(env, argv[0], &pwdU_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_list"));
  }
  //fprintf(stderr,"strsize: %d\n", pwdU_len);
  char pwdU[pwdU_len+1];
  if (!enif_get_string(env, argv[0], pwdU, pwdU_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_string"));
  }

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
    pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  // todo sodium_mlock(sec)

  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) {
    return enif_raise_exception(env, enif_make_atom(env, "create_cred_req"));
  }

  ERL_NIF_TERM s, p;
  memcpy(enif_make_new_binary(env, sizeof sec, &s), sec, sizeof sec);
  memcpy(enif_make_new_binary(env, sizeof pub, &p), pub, sizeof pub);
  return enif_make_tuple2(env, s, p);
}

static ERL_NIF_TERM c_create_cred_resp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
//int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
//                                    const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
//                                    const Opaque_Ids *ids,
//                                    const Opaque_App_Infos *infos,
// uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
// uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
// uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);

  ErlNifBinary bin;
  uint8_t *pub=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_not_binary"));
  }
  if(bin.size!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_invalid_size"));
  }
  pub=(uint8_t*) bin.data;

  Opaque_PkgConfig cfg;
  int res = getcfg(env, argv[2], &cfg);
  if(res!=0) {
    return enif_raise_exception(env, enif_make_atom(env, "cfg_parse_error")); // todo pass also res
  }

  Opaque_Ids ids;
  res = getids(env, argv[3], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  Opaque_App_Infos infos={0}, *infos_p=get_infos(env, argv[4], &infos);
  if(enif_has_pending_exception(env,&exc)) return exc;

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);

  uint8_t *rec=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_not_binary"));
  }
  if(bin.size!=OPAQUE_USER_RECORD_LEN+envU_len) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_invalid_size"));
  }
  rec=(uint8_t*) bin.data;

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, infos_p, resp, sk, sec)) {
    return enif_raise_exception(env, enif_make_atom(env, "create_cred_resp"));
  }

  ERL_NIF_TERM resp_, sk_, sec_;
  memcpy(enif_make_new_binary(env, sizeof resp, &resp_), resp, sizeof resp);
  memcpy(enif_make_new_binary(env, sizeof sk, &sk_), sk, sizeof sk);
  memcpy(enif_make_new_binary(env, sizeof sec, &sec_), sec, sizeof sec);
  return enif_make_tuple3(env, resp_, sk_, sec_);
}

static ERL_NIF_TERM c_recover_cred(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
// int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
//                               const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
//                               const uint8_t pkS[crypto_scalarmult_BYTES],
//                               const Opaque_PkgConfig *cfg,
//                               const Opaque_App_Infos *infos,
//                               Opaque_Ids *ids,
// uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
// uint8_t authU[crypto_auth_hmacsha512_BYTES],
// uint8_t export_key[crypto_hash_sha512_BYTES]);

  int pkS_offset = argc == 6;

  ErlNifBinary bin;

  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size<=OPAQUE_USER_SESSION_SECRET_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  uint8_t *pkS=NULL;
  if(pkS_offset) {
    if(!enif_inspect_binary(env, argv[2], &bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "pkS_not_binary"));
    }
    if(bin.size!=crypto_scalarmult_BYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "pkS_invalid_size"));
    }
    pkS=(uint8_t*) bin.data;
  }

  Opaque_PkgConfig cfg;
  int res = getcfg(env, argv[2+pkS_offset], &cfg);
  if(res!=0) {
    return enif_raise_exception(env, enif_make_atom(env, "cfg_parse_error")); // todo pass also res
  }

  if (cfg.pkS!=NotPackaged && pkS!=NULL) {
    return enif_raise_exception(env, enif_make_atom(env, "redundant_pkS")); // todo pass also res
  }

  if (cfg.pkS==NotPackaged && pkS==NULL) {
    return enif_raise_exception(env, enif_make_atom(env, "missing_pkS")); // todo pass also res
  }

  Opaque_App_Infos infos={0}, *infos_p=get_infos(env, argv[3+pkS_offset], &infos);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  int items=0, i;
  const ERL_NIF_TERM* idarray;
  if(!enif_get_tuple(env, argv[4+pkS_offset], &items, &idarray)) {
    return enif_raise_exception(env, enif_make_atom(env, "ids_parse_error"));
  }
  if(items!=2) {
    return enif_raise_exception(env, enif_make_atom(env, "ids_invalid_items"));
  }

  uint8_t idU[65535]={0}, idS[65535]={0};
  size_t idU_len=sizeof(idU), idS_len=sizeof(idS);
  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  if(!enif_inspect_binary(env, idarray[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "ids_parse_error"));
  }
  if(bin.size>=(2<<16)) {
    return enif_raise_exception(env, enif_make_atom(env, "idU_too_big"));
  }
  if(bin.size>0) {
    if(cfg.idU != NotPackaged) {
      return enif_raise_exception(env, enif_make_atom(env, "idU_is_packaged"));
    }
    ids.idU=(uint8_t*) bin.data;
    ids.idU_len=bin.size;
  } else if (cfg.idU==NotPackaged) {
    return enif_raise_exception(env, enif_make_atom(env, "idU_missing"));
  }

  if(!enif_inspect_binary(env, idarray[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "ids_parse_error"));
  }
  if(bin.size>=(2<<16)) {
    return enif_raise_exception(env, enif_make_atom(env, "idS_too_big"));
  }
  if(bin.size>0) {
    if(cfg.idS != NotPackaged) {
      return enif_raise_exception(env, enif_make_atom(env, "idS_is_packaged"));
    }
    ids.idS=(uint8_t*) bin.data;
    ids.idS_len=bin.size;
  } else if (cfg.idS==NotPackaged) {
    return enif_raise_exception(env, enif_make_atom(env, "idS_missing"));
  }
  //fprintf(stderr,"idU(%d): \"%.*s\", idS(%d): \"%.*s\"\n", ids.idU_len, ids.idU_len, ids.idU, ids.idS_len, ids.idS_len, ids.idS);

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);

  uint8_t *resp=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "resp_not_binary"));
  }
  if(bin.size<OPAQUE_SERVER_SESSION_LEN+envU_len) {
    return enif_raise_exception(env, enif_make_atom(env, "resp_invalid_size"));
  }
  resp=(uint8_t*) bin.data;

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, pkS, &cfg, infos_p, &ids, sk, authU, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "recover_cred_failed"));
  }

  ERL_NIF_TERM authU_, sk_, export_key_, idU_, idS_;

  memcpy(enif_make_new_binary(env, ids.idU_len, &idU_), ids.idU, ids.idU_len);
  memcpy(enif_make_new_binary(env, ids.idS_len, &idS_), ids.idS, ids.idS_len);
  ERL_NIF_TERM ids_ = enif_make_tuple(env,2, idU_, idS_);
  memcpy(enif_make_new_binary(env, sizeof authU, &authU_), authU, sizeof authU);
  memcpy(enif_make_new_binary(env, sizeof sk, &sk_), sk, sizeof sk);
  memcpy(enif_make_new_binary(env, sizeof export_key, &export_key_), export_key, sizeof export_key);
  return enif_make_tuple4(env, sk_, authU_, export_key_, ids_);
}

static ERL_NIF_TERM c_user_auth(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
// int opaque_UserAuth(
//      const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN],
//      const uint8_t authU[crypto_auth_hmacsha512_BYTES]);

  ErlNifBinary bin;
  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size!=OPAQUE_SERVER_AUTH_CTX_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  uint8_t *authU=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "authU_not_binary"));
  }
  if(bin.size!=crypto_auth_hmacsha512_BYTES) {
    return enif_raise_exception(env, enif_make_atom(env, "authU_invalid_size"));
  }
  authU=(uint8_t*) bin.data;


  if(0!=opaque_UserAuth(sec, authU)) {
    return enif_make_atom(env,"fail");
  }
  return enif_make_atom(env,"ok");
}

static ERL_NIF_TERM c_create_reg_req(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
//int opaque_CreateRegistrationRequest(
//           const uint8_t *pwdU, const uint16_t pwdU_len,
// uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
// uint8_t M[crypto_core_ristretto255_BYTES]);
  unsigned pwdU_len;
  if(!enif_get_list_length(env, argv[0], &pwdU_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_list"));
  }

  //fprintf(stderr,"strsize: %d\n", pwdU_len);
  char pwdU[pwdU_len+1];
  if (!enif_get_string(env, argv[0], pwdU, pwdU_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_string"));
  }
  //fprintf(stderr,"> %.*s\n", pwdU_len, pwdU);

  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
          M[crypto_core_ristretto255_BYTES];

  if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M)) {
    return enif_raise_exception(env, enif_make_atom(env, "create_reg_req_failed"));
  }

  ERL_NIF_TERM sec_, m_;
  memcpy(enif_make_new_binary(env, sizeof sec, &sec_), sec, sizeof sec);
  memcpy(enif_make_new_binary(env, sizeof M, &m_), M, sizeof M);
  return enif_make_tuple2(env, sec_, m_);
}

static ERL_NIF_TERM c_create_reg_resp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
// int opaque_CreateRegistrationResponse(
//              const uint8_t M[crypto_core_ristretto255_BYTES],
//       opt:   const uint8_t pkS[crypto_scalarmult_BYTES],
//  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
//  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
  ErlNifBinary bin;
  uint8_t *M=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "m_not_binary"));
  }
  if(bin.size!=crypto_core_ristretto255_BYTES) {
    return enif_raise_exception(env, enif_make_atom(env, "m_invalid_size"));
  }
  M=(uint8_t*) bin.data;

  uint8_t *pkS=NULL;
  if(argc==2) {
    if(!enif_inspect_binary(env, argv[1], &bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "pkS_not_binary"));
    }
    if(bin.size!=crypto_scalarmult_BYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "pkS_invalid_size"));
    }
    pkS=(uint8_t*) bin.data;
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
          pub[OPAQUE_REGISTER_PUBLIC_LEN];

  if(NULL!=pkS) {
    if(0!=opaque_Create1kRegistrationResponse(M, pkS, sec, pub)) {
      return enif_raise_exception(env, enif_make_atom(env, "create_reg_resp_failed"));
    }
  } else {
    if(0!=opaque_CreateRegistrationResponse(M, sec, pub)) {
      return enif_raise_exception(env, enif_make_atom(env, "create_reg_resp_failed"));
    }
  }

  ERL_NIF_TERM sec_, pub_;
  memcpy(enif_make_new_binary(env, sizeof sec, &sec_), sec, sizeof sec);
  memcpy(enif_make_new_binary(env, sizeof pub, &pub_), pub, sizeof pub);
  return enif_make_tuple2(env, sec_, pub_);
}

static ERL_NIF_TERM c_finalize_reg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
// int opaque_FinalizeRequest(
//            const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/],
//            const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
//            const Opaque_PkgConfig *cfg,
//            const Opaque_Ids *ids,
//  uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
//  uint8_t export_key[crypto_hash_sha512_BYTES]);
  ErlNifBinary bin;

  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size<=OPAQUE_REGISTER_USER_SEC_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  uint8_t *pub=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_not_binary"));
  }
  if(bin.size!=OPAQUE_REGISTER_PUBLIC_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_invalid_size"));
  }
  pub=(uint8_t*) bin.data;

  Opaque_PkgConfig cfg;
  int res = getcfg(env, argv[2], &cfg);
  if(res!=0) {
    return enif_raise_exception(env, enif_make_atom(env, "cfg_parse_error")); // todo pass also res
  }

  Opaque_Ids ids;
  res = getids(env, argv[3], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  uint8_t export_key[crypto_hash_sha512_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "finalize_reg_failed"));
  }

  ERL_NIF_TERM r, ek;
  memcpy(enif_make_new_binary(env, sizeof rec, &r), rec, sizeof rec);
  memcpy(enif_make_new_binary(env, sizeof export_key, &ek), export_key, sizeof export_key);
  return enif_make_tuple2(env, r, ek);
}


static ERL_NIF_TERM c_store_rec(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
//void opaque_StoreUserRecord(
//         const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
//    opt  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
// in/out  uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
  ErlNifBinary bin;

  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size!=OPAQUE_REGISTER_SECRET_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  int sks_offset = argc == 3;
  uint8_t *skS=NULL;
  if(sks_offset) {
    if(!enif_inspect_binary(env, argv[1], &bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_not_binary"));
    }
    if(bin.size!=crypto_scalarmult_SCALARBYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_invalid_size"));
    }
    skS=(uint8_t*) bin.data;
  }

  uint8_t *rec=NULL;
  if(!enif_inspect_binary(env, argv[1+sks_offset], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_not_binary"));
  }
  if(bin.size<=OPAQUE_USER_RECORD_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_invalid_size"));
  }
  rec=(uint8_t*) bin.data;
  unsigned rec_len = bin.size;

  if(NULL!=skS) {
    opaque_Store1kUserRecord(sec, skS, rec);
  } else {
    opaque_StoreUserRecord(sec, rec);
  }

  ERL_NIF_TERM rec_;
  memcpy(enif_make_new_binary(env, rec_len, &rec_), rec, rec_len);
  return rec_;
}


static ErlNifFunc nif_funcs[] = {
 {"register", 3, c_register},
 {"register", 4, c_register},
 {"create_cred_req", 1, c_create_cred_req},
 {"create_cred_resp", 5, c_create_cred_resp},
 {"recover_cred", 5, c_recover_cred},
 {"recover_cred", 6, c_recover_cred},
 {"user_auth", 2, c_user_auth},
 {"create_reg_req", 1, c_create_reg_req},
 {"create_reg_resp", 1, c_create_reg_resp},
 {"create_reg_resp", 2, c_create_reg_resp},
 {"finalize_reg", 4, c_finalize_reg},
 {"store_rec", 2, c_store_rec},
 {"store_rec", 3, c_store_rec},
};

ERL_NIF_INIT(opaque,nif_funcs,NULL,NULL,NULL,NULL)
