#include "opaque.h"
#include "ruby.h"
#include "extconf.h"

static void extract_str(VALUE arg, char **str, size_t *len, const char* err) {
  if (RB_TYPE_P(arg, T_STRING) != 1) {
    rb_raise(rb_eTypeError, "%s", err);
  }
  *len = RSTRING_LEN(arg);
  *str = RSTRING_PTR(arg);
}

static int get_cfgval(VALUE ary, const unsigned int index) {
  VALUE item = rb_ary_entry(ary, index);
  if (RB_TYPE_P(item, T_FIXNUM) != 1) {
    rb_raise(rb_eTypeError, "cfg item %d is not an an int", index);
  }
  int val = FIX2INT(item);
  if(val<0 || val>2) {
    rb_raise(rb_eTypeError, "cfg item %d has invalid value", index);
  }
  return val;
}

static void extract_cfg(VALUE arg, Opaque_PkgConfig *cfg) {
  if (RB_TYPE_P(arg, T_ARRAY) != 1) {
    rb_raise(rb_eTypeError, "cfg is not an array");
  }
  if(rb_array_len(arg)!=5){
    rb_raise(rb_eTypeError, "cfg has insufficient elements");
  }
  cfg->skU = get_cfgval(arg, 0);
  cfg->pkU = get_cfgval(arg, 1);
  cfg->pkS = get_cfgval(arg, 2);
  cfg->idS = get_cfgval(arg, 3);
  cfg->idU = get_cfgval(arg, 4);
}

static void get_infos(Opaque_App_Infos *infos, VALUE arg) {
  if (RB_TYPE_P(arg, T_ARRAY) != 1) {
    rb_raise(rb_eTypeError, "infos is not an array");
  }

  VALUE item = rb_ary_entry(arg, 0);
  if (RB_TYPE_P(arg, T_STRING) == 1) {
    extract_str(item, (char**) &infos->info, &infos->info_len, "");
  }
  item = rb_ary_entry(arg, 1);
  if (RB_TYPE_P(arg, T_STRING) == 1) {
    extract_str(item, (char**) &infos->einfo, &infos->einfo_len, "");
  }
}


VALUE opaque_register(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 4, 5);

  char *pwdU;
  size_t pwdU_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;

  char *skS=NULL;
  size_t skS_len=0;

  extract_str(argv[0], &pwdU, &pwdU_len, "pwdU is not a string");
  extract_str(argv[1], &idU, &idU_len, "idU is not a string");
  extract_str(argv[2], &idS, &idS_len, "idS is not a string");

  Opaque_PkgConfig cfg;

  extract_cfg(argv[3], &cfg);

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  if(argc==5) {
    extract_str(argv[4], &skS, &skS_len, "skS is not a string");
    if(skS_len!=crypto_scalarmult_SCALARBYTES) {
      rb_raise(rb_eTypeError, "skS param is not exactly %d bytes long", crypto_scalarmult_SCALARBYTES);
    }
  }

  uint8_t export_key[crypto_hash_sha256_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key)) {
      rb_raise(rb_eRuntimeError, "register failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(rec,sizeof rec),
                              rb_str_new(export_key, sizeof export_key)
                              );
}


VALUE opaque_create_credential_request(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 1, 1);

  char *pwdU;
  size_t pwdU_len;

  extract_str(argv[0], &pwdU, &pwdU_len, "pwdU is not a string");


  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];

  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) {
      rb_raise(rb_eRuntimeError, "create credential request failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(sec,sizeof sec),
                              rb_str_new(pub,sizeof pub)
                              );
}

VALUE opaque_create_credential_response(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 5, 6);

  char *pub;
  size_t pub_len;
  char *rec;
  size_t rec_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;

  extract_str(argv[0], &pub, &pub_len, "pub is not a string");
  if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    rb_raise(rb_eRuntimeError, "invalid pub param.");
  }
  extract_str(argv[1], &rec, &rec_len, "rec is not a string");
  extract_str(argv[2], &idU, &idU_len, "idU is not a string");
  extract_str(argv[3], &idS, &idS_len, "idS is not a string");

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  Opaque_PkgConfig cfg;
  extract_cfg(argv[4], &cfg);

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  if(rec_len!=OPAQUE_USER_RECORD_LEN+envU_len) {
    rb_raise(rb_eRuntimeError, "invalid rec param.");
  }

  Opaque_App_Infos *infos_p=NULL;

  if(argc==6) {
    Opaque_App_Infos infos={0};
    get_infos(infos_p, argv[5]);
    infos_p=&infos;
  }

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, infos_p, resp, sk, sec)) {
      rb_raise(rb_eRuntimeError, "create credential response failed");
  }

  return rb_ary_new_from_args(3,
                              rb_str_new(resp,sizeof resp),
                              rb_str_new(sk,sizeof sk),
                              rb_str_new(sec,sizeof sec)
                              );
}

VALUE opaque_recover_credentials(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 3, 7);

  char *resp;
  size_t resp_len;
  char *sec;
  size_t sec_len;
  char *pkS=NULL;
  size_t pkS_len=0;
  char *idU=NULL;
  size_t idU_len=0;
  char *idS=NULL;
  size_t idS_len=0;

  extract_str(argv[0], &resp, &resp_len, "resp is not a string");
  // size check after envU_len is available later

  extract_str(argv[1], &sec, &sec_len, "sec is not a string");
  if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
    rb_raise(rb_eTypeError, "invalid sec param.");
  }

  Opaque_PkgConfig cfg;
  extract_cfg(argv[2], &cfg);

  Opaque_App_Infos *infos_p=NULL;
  Opaque_App_Infos infos={0};
  if(argc>3 && RB_TYPE_P(argv[3], T_ARRAY)) {
    get_infos(infos_p, argv[3]);
    infos_p=&infos;
  }

  if(argc>4 && RB_TYPE_P(argv[4], T_STRING) == 1) {
    extract_str(argv[4], &pkS, &pkS_len, "");
    if(pkS_len!=crypto_scalarmult_BYTES) {
      rb_raise(rb_eTypeError, "invalid pkS param.");
    }
  }
  if(argc>5 && RB_TYPE_P(argv[5], T_STRING) == 1) {
    extract_str(argv[5], &idU, &idU_len, "");
  }
  if(argc>6 && RB_TYPE_P(argv[6], T_STRING) == 1) {
    extract_str(argv[6], &idS, &idS_len, "");
  }

  if (cfg.pkS==NotPackaged && pkS==NULL) {
    rb_raise(rb_eRuntimeError, "cfg.pkS is NotPackaged and pkS is nil");
  }
  if (cfg.pkS!=NotPackaged && pkS!=NULL) {
    rb_raise(rb_eRuntimeError, "cfg.pkS is Packaged and pkS is redundantly supplied");
  }

  uint8_t idU1[65535]={0}, idS1[65535]={0};
  size_t idU1_len=sizeof(idU1), idS1_len=sizeof(idS1);
  if (cfg.idU==NotPackaged) {
    if (idU==NULL) {
      rb_raise(rb_eRuntimeError, "cfg.idU is NotPackaged and idU is nil");
    }
    if(idU_len>=(2<<16)) {
      rb_raise(rb_eRuntimeError, "idU too big.");
    }
    memcpy(idU1, idU, idU_len);
    idU1_len = idU_len;
  } else {
    if (idU!=NULL) {
      rb_raise(rb_eRuntimeError, "cfg.idU is Packaged and idU is redundantly supplied");
    }
    idU1_len = sizeof(idU1);
  }

  if (cfg.idS==NotPackaged) {
    if (idS==NULL) {
      rb_raise(rb_eRuntimeError, "cfg.idS is NotPackaged and idS is nil");
    }
    if(idU_len>=(2<<16)) {
      rb_raise(rb_eRuntimeError, "idS too big.");
    }
    memcpy(idS1, idS, idS_len);
    idS1_len = idS_len;
  } else {
    if (idU!=NULL) {
      rb_raise(rb_eRuntimeError, "cfg.idS is Packaged and idS is redundantly supplied");
    }
    idS1_len = sizeof(idS1);
  }
  Opaque_Ids ids1={.idU_len=idU1_len,.idU=idU1,.idS_len=idS1_len,.idS=idS1};

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids1);
  if(resp_len<OPAQUE_SERVER_SESSION_LEN+envU_len) {
    fprintf(stderr, "rl: %ld < %ld\n", resp_len, OPAQUE_SERVER_SESSION_LEN+envU_len);
    rb_raise(rb_eTypeError, "invalid resp param.");
  }

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t export_key[crypto_hash_sha256_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, pkS, &cfg, infos_p, &ids1, sk, authU, export_key)) {
    rb_raise(rb_eRuntimeError, "recover credentials failed");
  }

  return rb_ary_new_from_args(5,
                              rb_str_new(sk,sizeof sk),
                              rb_str_new(authU,sizeof authU),
                              rb_str_new(export_key,sizeof export_key),
                              rb_str_new(ids1.idU, ids1.idU_len),
                              rb_str_new(ids1.idS, ids1.idS_len)
                              );
}

VALUE opaque_user_auth(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 2, 2);

  char *sec;
  size_t sec_len;
  char *authU;
  size_t authU_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len!=OPAQUE_SERVER_AUTH_CTX_LEN) {
    rb_raise(rb_eTypeError, "sec param is invalid");
  }

  extract_str(argv[1], &authU, &authU_len, "authU is not a string");
  if(authU_len!=crypto_auth_hmacsha256_BYTES) {
    rb_raise(rb_eTypeError, "authU param is invalid");
  }

  if(0!=opaque_UserAuth(sec, authU)) return Qfalse;
  return Qtrue;
}

VALUE opaque_create_registration_request(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 1, 1);

  char *pwdU;
  size_t pwdU_len;

  extract_str(argv[0], &pwdU, &pwdU_len, "pwdU is not a string");

  uint8_t M[crypto_core_ristretto255_BYTES];
  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];

  if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M)) {
    rb_raise(rb_eRuntimeError, "create registation request failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(M,sizeof M),
                              rb_str_new(sec, sizeof sec)
                              );
}

VALUE opaque_create_registration_response(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 1, 1);

  char *M;
  size_t M_len;

  extract_str(argv[0], &M, &M_len, "M is not a string");
  if(M_len!=crypto_core_ristretto255_BYTES) {
    rb_raise(rb_eTypeError, "M is not 32B");
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(M, sec, pub)) {
    rb_raise(rb_eRuntimeError, "create registration response failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(sec,sizeof sec),
                              rb_str_new(pub, sizeof pub)
                              );
}

VALUE opaque_create_1k_registration_response(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 2, 2);

  char *M;
  size_t M_len;
  char *pkS;
  size_t pkS_len;

  extract_str(argv[0], &M, &M_len, "M is not a string");
  if(M_len!=crypto_core_ristretto255_BYTES) {
    rb_raise(rb_eTypeError, "M is not 32B");
  }

  extract_str(argv[1], &pkS, &pkS_len, "pkS is not a string");
  if(pkS_len!=crypto_scalarmult_BYTES) {
    rb_raise(rb_eTypeError, "pkS is not 32B");
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_Create1kRegistrationResponse(M, pkS, sec, pub)) {
    rb_raise(rb_eRuntimeError, "create registration response failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(sec,sizeof sec),
                              rb_str_new(pub, sizeof pub)
                              );
}

VALUE opaque_finalize_request(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 5, 5);

  char *sec;
  size_t sec_len;
  char *pub;
  size_t pub_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len<=OPAQUE_REGISTER_USER_SEC_LEN) {
    rb_raise(rb_eTypeError, "sec is invalid size");
  }
  extract_str(argv[1], &pub, &pub_len, "pub is not a string");
  if(pub_len!=OPAQUE_REGISTER_PUBLIC_LEN) {
    rb_raise(rb_eTypeError, "pub is invalid size");
  }
  extract_str(argv[2], &idU, &idU_len, "idU is not a string");
  extract_str(argv[3], &idS, &idS_len, "idS is not a string");

  Opaque_PkgConfig cfg;
  extract_cfg(argv[4], &cfg);

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];
  uint8_t export_key[crypto_hash_sha256_BYTES];
  if(0!=opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key)) {
    rb_raise(rb_eRuntimeError, "create registration response failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(rec,sizeof rec),
                              rb_str_new(export_key, sizeof export_key)
                              );
}

VALUE opaque_store_user_record(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 2, 2);

  char *sec;
  size_t sec_len;
  char *rec;
  size_t rec_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
    rb_raise(rb_eTypeError, "sec is invalid");
  }

  extract_str(argv[1], &rec, &rec_len, "rec is not a string");
  if(rec_len<=OPAQUE_USER_RECORD_LEN) {
    rb_raise(rb_eTypeError, "rec is invalid");
  }

  opaque_StoreUserRecord(sec, rec);

  return rb_str_new(rec,rec_len);
}

VALUE opaque_store_1k_user_record(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 3, 3);

  char *sec;
  size_t sec_len;
  char *skS;
  size_t skS_len;
  char *rec;
  size_t rec_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
    rb_raise(rb_eTypeError, "sec is invalid");
  }

  extract_str(argv[1], &skS, &skS_len, "skS is not a string");
  if(skS_len!=crypto_scalarmult_SCALARBYTES) {
    rb_raise(rb_eTypeError, "skS is not 32B");
  }

  extract_str(argv[2], &rec, &rec_len, "rec is not a string");
  if(rec_len<=OPAQUE_USER_RECORD_LEN) {
    rb_raise(rb_eTypeError, "rec is invalid");
  }

  opaque_Store1kUserRecord(sec, skS, rec);

  return rb_str_new(rec,rec_len);
}

VALUE opaque_create_server_keys() {
  char pkS[crypto_scalarmult_BYTES];
  char skS[crypto_scalarmult_SCALARBYTES];

  randombytes(skS, crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult_base(pkS, skS);
  return rb_ary_new_from_args(2,
                              rb_str_new(pkS,sizeof pkS),
                              rb_str_new(skS, sizeof skS)
                              );
}

void Init_opaque() {
  VALUE opaque = rb_define_module("Opaque");

  rb_define_const(opaque, "NotPackaged", INT2FIX(NotPackaged));
  rb_define_const(opaque, "InSecEnv", INT2FIX(InSecEnv));
  rb_define_const(opaque, "InClrEnv", INT2FIX(InClrEnv));

  rb_define_method(opaque, "register", opaque_register, -1);
  rb_define_method(opaque, "create_credential_request", opaque_create_credential_request, -1);
  rb_define_method(opaque, "create_credential_response", opaque_create_credential_response, -1);
  rb_define_method(opaque, "recover_credentials", opaque_recover_credentials, -1);
  rb_define_method(opaque, "user_auth", opaque_user_auth, -1);

  rb_define_method(opaque, "create_registration_request", opaque_create_registration_request, -1);
  rb_define_method(opaque, "create_registration_response", opaque_create_registration_response, -1);
  rb_define_method(opaque, "create_1k_registration_response", opaque_create_1k_registration_response, -1);
  rb_define_method(opaque, "finalize_request", opaque_finalize_request, -1);
  rb_define_method(opaque, "store_user_record", opaque_store_user_record, -1);
  rb_define_method(opaque, "store_1k_user_record", opaque_store_1k_user_record, -1);

  rb_define_method(opaque, "create_server_keys", opaque_create_server_keys, 0);
}
