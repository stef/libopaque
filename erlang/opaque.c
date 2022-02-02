#include <erl_nif.h>
#include <stdio.h>
#include <string.h>
#include <opaque.h>

#define OPAQUE_ERL_NOT_TUPLE 1

static int is_nil(ErlNifEnv* env, const ERL_NIF_TERM term) {
  int res;
  char buf[5];
  res = enif_get_atom(env, term, buf, sizeof buf, ERL_NIF_LATIN1);
  if(memcmp(buf,"nil", 4)==0) return 1;
  return 0;
}

static void getids(ErlNifEnv* env, const ERL_NIF_TERM tuple, Opaque_Ids *ids) {
  int items=0;
  const ERL_NIF_TERM* array;
  if(!enif_get_tuple(env, tuple, &items, &array)) {
    enif_raise_exception(env, enif_make_atom(env, "ids_invalid_elems"));
    return;
  }
  if(items!=2) {
    enif_raise_exception(env, enif_make_atom(env, "ids_invalid_size"));
    return;
  }

  ErlNifBinary bin;
  if(is_nil(env,array[0])) {
    ids->idU=NULL;
    ids->idU_len=0;
  } else {
    if(enif_inspect_binary(env, array[0], &bin)) {
      if(bin.size>=(2<<16)) {
        enif_raise_exception(env, enif_make_atom(env, "idU_too_big"));
        return;
      }
      ids->idU=(uint8_t*) bin.data;
      ids->idU_len=bin.size;
    } else {
      enif_raise_exception(env, enif_make_atom(env, "idU_missing"));
      return;
    }
  }

  if(is_nil(env,array[1])) {
    ids->idS=NULL;
    ids->idS_len=0;
  } else {
    if(enif_inspect_binary(env, array[1], &bin)) {
      if(bin.size>=(2<<16)) {
        enif_raise_exception(env, enif_make_atom(env, "idU_too_big"));
        return;
      }
      ids->idS=(uint8_t*) bin.data;
      ids->idS_len=bin.size;
    } else {
      enif_raise_exception(env, enif_make_atom(env, "idS_missing"));
      return;
    }
  }
}

static ERL_NIF_TERM c_register(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  unsigned pwdU_len;
  if(!enif_get_list_length(env, argv[0], &pwdU_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_list"));
  }
  char pwdU[pwdU_len+1];
  if (!enif_get_string(env, argv[0], pwdU, pwdU_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "pwdU_not_string"));
  }

  Opaque_Ids ids;
  getids(env, argv[1], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  uint8_t *skS=NULL;
  if(argc == 3) {
    ErlNifBinary skS_bin;
    if(!enif_inspect_binary(env, argv[2], &skS_bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_not_binary"));
    }
    if(skS_bin.size!=crypto_scalarmult_SCALARBYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_invalid_size"));
    }
    skS=(uint8_t*) skS_bin.data;
  }

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "register_failed"));
  }

  ERL_NIF_TERM r, ek;
  memcpy(enif_make_new_binary(env, sizeof rec, &r), rec, sizeof rec);
  memcpy(enif_make_new_binary(env, sizeof export_key, &ek), export_key, sizeof export_key);
  return enif_make_tuple2(env, r, ek);
}

static ERL_NIF_TERM c_create_cred_req(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
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
  ErlNifBinary bin;
  uint8_t *pub=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_not_binary"));
  }
  if(bin.size!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "pub_invalid_size"));
  }
  pub=(uint8_t*) bin.data;

  uint8_t *rec=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_not_binary"));
  }
  if(bin.size!=OPAQUE_USER_RECORD_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_invalid_size"));
  }
  rec=(uint8_t*) bin.data;

  Opaque_Ids ids;
  getids(env, argv[2], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  unsigned context_len;
  if(!enif_get_list_length(env, argv[3], &context_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "context_not_list"));
  }
  //fprintf(stderr,"strsize: %d\n", pwdU_len);
  char context[context_len+1];
  if (!enif_get_string(env, argv[3], context, context_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "context_not_string"));
  }

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[crypto_auth_hmacsha512_BYTES]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, sec)) {
    return enif_raise_exception(env, enif_make_atom(env, "create_cred_resp"));
  }

  ERL_NIF_TERM resp_, sk_, sec_;
  memcpy(enif_make_new_binary(env, sizeof resp, &resp_), resp, sizeof resp);
  memcpy(enif_make_new_binary(env, sizeof sk, &sk_), sk, sizeof sk);
  memcpy(enif_make_new_binary(env, sizeof sec, &sec_), sec, sizeof sec);
  return enif_make_tuple3(env, resp_, sk_, sec_);
}

static ERL_NIF_TERM c_recover_cred(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary bin;

  uint8_t *resp=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "resp_not_binary"));
  }
  if(bin.size!=OPAQUE_SERVER_SESSION_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "resp_invalid_size"));
  }
  resp=(uint8_t*) bin.data;

  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size<=OPAQUE_USER_SESSION_SECRET_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  unsigned context_len;
  if(!enif_get_list_length(env, argv[2], &context_len)) {
    return enif_raise_exception(env, enif_make_atom(env, "context_not_list"));
  }
  char context[context_len+1];
  if (!enif_get_string(env, argv[2], context, context_len+1, ERL_NIF_LATIN1)) {
    return enif_raise_exception(env, enif_make_atom(env, "context_not_string"));
  }

  Opaque_Ids ids={0};
  getids(env, argv[3], &ids);

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "recover_cred_failed"));
  }

  ERL_NIF_TERM authU_, sk_, export_key_;
  memcpy(enif_make_new_binary(env, sizeof authU, &authU_), authU, sizeof authU);
  memcpy(enif_make_new_binary(env, sizeof sk, &sk_), sk, sizeof sk);
  memcpy(enif_make_new_binary(env, sizeof export_key, &export_key_), export_key, sizeof export_key);
  return enif_make_tuple3(env, sk_, authU_, export_key_);
}

static ERL_NIF_TERM c_user_auth(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary bin;
  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size!=crypto_auth_hmacsha512_BYTES) {
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
  ErlNifBinary bin;
  uint8_t *M=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "m_not_binary"));
  }
  if(bin.size!=crypto_core_ristretto255_BYTES) {
    return enif_raise_exception(env, enif_make_atom(env, "m_invalid_size"));
  }
  M=(uint8_t*) bin.data;

  uint8_t *skS=NULL;
  if(argc==2) {
    if(!enif_inspect_binary(env, argv[1], &bin)) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_not_binary"));
    }
    if(bin.size!=crypto_scalarmult_BYTES) {
      return enif_raise_exception(env, enif_make_atom(env, "skS_invalid_size"));
    }
    skS=(uint8_t*) bin.data;
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
          pub[OPAQUE_REGISTER_PUBLIC_LEN];

  if(0!=opaque_CreateRegistrationResponse(M, skS, sec, pub)) {
    return enif_raise_exception(env, enif_make_atom(env, "create_reg_resp_failed"));
  }

  ERL_NIF_TERM sec_, pub_;
  memcpy(enif_make_new_binary(env, sizeof sec, &sec_), sec, sizeof sec);
  memcpy(enif_make_new_binary(env, sizeof pub, &pub_), pub, sizeof pub);
  return enif_make_tuple2(env, sec_, pub_);
}

static ERL_NIF_TERM c_finalize_reg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
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

  Opaque_Ids ids;
  getids(env, argv[2], &ids);
  ERL_NIF_TERM exc;
  if(enif_has_pending_exception(env,&exc)) return exc;

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];

  if(0!=opaque_FinalizeRequest(sec, pub, &ids, rec, export_key)) {
    return enif_raise_exception(env, enif_make_atom(env, "finalize_reg_failed"));
  }

  ERL_NIF_TERM r, ek;
  memcpy(enif_make_new_binary(env, sizeof rec, &r), rec, sizeof rec);
  memcpy(enif_make_new_binary(env, sizeof export_key, &ek), export_key, sizeof export_key);
  return enif_make_tuple2(env, r, ek);
}


static ERL_NIF_TERM c_store_rec(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary bin;

  uint8_t *sec=NULL;
  if(!enif_inspect_binary(env, argv[0], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_not_binary"));
  }
  if(bin.size!=OPAQUE_REGISTER_SECRET_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "sec_invalid_size"));
  }
  sec=(uint8_t*) bin.data;

  uint8_t *recU=NULL;
  if(!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_not_binary"));
  }
  if(bin.size!=OPAQUE_REGISTRATION_RECORD_LEN) {
    return enif_raise_exception(env, enif_make_atom(env, "rec_invalid_size"));
  }
  recU=(uint8_t*) bin.data;

  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(sec, recU, rec);

  ERL_NIF_TERM rec_;
  memcpy(enif_make_new_binary(env, sizeof rec, &rec_), rec, sizeof rec);
  return rec_;
}


static ErlNifFunc nif_funcs[] = {
 {"register", 2, c_register},
 {"register", 3, c_register},
 {"create_cred_req", 1, c_create_cred_req},
 {"create_cred_resp", 4, c_create_cred_resp},
 {"recover_cred", 4, c_recover_cred},
 {"user_auth", 2, c_user_auth},
 {"create_reg_req", 1, c_create_reg_req},
 {"create_reg_resp", 1, c_create_reg_resp},
 {"create_reg_resp", 2, c_create_reg_resp},
 {"finalize_reg", 3, c_finalize_reg},
 {"store_rec", 2, c_store_rec},
};

ERL_NIF_INIT(opaque,nif_funcs,NULL,NULL,NULL,NULL)
