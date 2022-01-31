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

VALUE opaque_register(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 3, 4);

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

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  if(argc==4) {
    extract_str(argv[3], &skS, &skS_len, "skS is not a string");
    if(skS_len!=crypto_scalarmult_SCALARBYTES) {
      rb_raise(rb_eTypeError, "skS param is not exactly %d bytes long", crypto_scalarmult_SCALARBYTES);
    }
  }

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) {
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
  rb_check_arity(argc, 5, 5);

  char *pub;
  size_t pub_len;
  char *rec;
  size_t rec_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;
  char *context;
  size_t context_len;

  extract_str(argv[0], &pub, &pub_len, "pub is not a string");
  if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    rb_raise(rb_eRuntimeError, "invalid pub param.");
  }

  extract_str(argv[1], &rec, &rec_len, "rec is not a string");
  if(rec_len!=OPAQUE_USER_RECORD_LEN) {
    rb_raise(rb_eRuntimeError, "invalid rec param.");
  }

  extract_str(argv[2], &idU, &idU_len, "idU is not a string");
  extract_str(argv[3], &idS, &idS_len, "idS is not a string");
  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  extract_str(argv[4], &context, &context_len, "context is not a string");

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[crypto_auth_hmacsha512_BYTES]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, sec)) {
      rb_raise(rb_eRuntimeError, "create credential response failed");
  }

  return rb_ary_new_from_args(3,
                              rb_str_new(resp,sizeof resp),
                              rb_str_new(sk,sizeof sk),
                              rb_str_new(sec,sizeof sec)
                              );
}

VALUE opaque_recover_credentials(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 3, 5);

  char *resp;
  size_t resp_len;
  char *sec;
  size_t sec_len;
  char *context;
  size_t context_len;
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

  extract_str(argv[2], &context, &context_len, "context is not a string");

  if(argc>3 && RB_TYPE_P(argv[3], T_STRING) == 1) {
    extract_str(argv[3], &idU, &idU_len, "");
  }
  if(argc>4 && RB_TYPE_P(argv[4], T_STRING) == 1) {
    extract_str(argv[4], &idS, &idS_len, "");
  }

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key)) {
    rb_raise(rb_eRuntimeError, "recover credentials failed");
  }

  return rb_ary_new_from_args(3,
                              rb_str_new(sk,sizeof sk),
                              rb_str_new(authU,sizeof authU),
                              rb_str_new(export_key,sizeof export_key)
                              );
}

VALUE opaque_user_auth(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 2, 2);

  char *sec;
  size_t sec_len;
  char *authU;
  size_t authU_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len!=crypto_auth_hmacsha512_BYTES) {
    rb_raise(rb_eTypeError, "sec param is invalid");
  }

  extract_str(argv[1], &authU, &authU_len, "authU is not a string");
  if(authU_len!=crypto_auth_hmacsha512_BYTES) {
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
  rb_check_arity(argc, 1, 2);

  char *M;
  size_t M_len;
  char *skS=NULL;
  size_t skS_len;

  extract_str(argv[0], &M, &M_len, "M is not a string");
  if(M_len!=crypto_core_ristretto255_BYTES) {
    rb_raise(rb_eTypeError, "M is not 32B");
  }
  if(argc>1) {
    extract_str(argv[1], &skS, &skS_len, "skS is not a string");
    if(skS_len!=crypto_scalarmult_SCALARBYTES) {
      rb_raise(rb_eTypeError, "skS is not 32B");
    }
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(M, skS, sec, pub)) {
    rb_raise(rb_eRuntimeError, "create registration response failed");
  }

  return rb_ary_new_from_args(2,
                              rb_str_new(sec,sizeof sec),
                              rb_str_new(pub, sizeof pub)
                              );
}

VALUE opaque_finalize_request(int argc, VALUE *argv, VALUE obj) {
  rb_check_arity(argc, 4, 4);

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

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];
  uint8_t export_key[crypto_hash_sha512_BYTES];
  if(0!=opaque_FinalizeRequest(sec, pub, &ids, rec, export_key)) {
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
  char *recU;
  size_t recU_len;

  extract_str(argv[0], &sec, &sec_len, "sec is not a string");
  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
    rb_raise(rb_eTypeError, "sec is invalid");
  }

  extract_str(argv[1], &recU, &recU_len, "rec is not a string");
  if(recU_len!=OPAQUE_REGISTRATION_RECORD_LEN) {
    rb_raise(rb_eTypeError, "rec is invalid");
  }

  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(sec, recU, rec);

  return rb_str_new(rec,sizeof rec);
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

  rb_define_method(opaque, "register", opaque_register, -1);
  rb_define_method(opaque, "create_credential_request", opaque_create_credential_request, -1);
  rb_define_method(opaque, "create_credential_response", opaque_create_credential_response, -1);
  rb_define_method(opaque, "recover_credentials", opaque_recover_credentials, -1);
  rb_define_method(opaque, "user_auth", opaque_user_auth, -1);

  rb_define_method(opaque, "create_registration_request", opaque_create_registration_request, -1);
  rb_define_method(opaque, "create_registration_response", opaque_create_registration_response, -1);
  rb_define_method(opaque, "finalize_request", opaque_finalize_request, -1);
  rb_define_method(opaque, "store_user_record", opaque_store_user_record, -1);

  rb_define_method(opaque, "create_server_keys", opaque_create_server_keys, 0);
}
