#include <stdio.h>
#include <stdint.h>
#include <jni.h>
#include "opaque.h"

static const char *JNIT_CLASS = "Opaque";

static void exception(JNIEnv *env, const char* msg) {
    jclass cls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, cls, msg);
    (*env)->DeleteLocalRef(env, cls);
}

typedef struct {
  const char *key;    /**< length of idU, most useful if idU is binary */
  char* val;
  size_t len;
} RetVal;

static jobject retlist(JNIEnv *env, const char* cls, RetVal *vals) {
  // Get the class we wish to return an instance of
  jclass clazz = (*env)->FindClass(env, cls);

  // Get the method id of an empty constructor in clazz
  jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");

  // Create an instance of clazz
  jobject obj = (*env)->NewObject(env, clazz, constructor);

  int i;
  for(i=0;vals[i].key!=NULL;i++) {
    jfieldID attr = (*env)->GetFieldID(env, clazz, vals[i].key, "[B");
    jbyteArray arr = (*env)->NewByteArray(env, vals[i].len);
    (*env)->SetByteArrayRegion(env, arr, 0, vals[i].len, vals[i].val);
    (*env)->SetObjectField(env, obj, attr, arr);
    (*env)->DeleteLocalRef(env, arr);
  }

  (*env)->ExceptionClear(env);
  (*env)->DeleteLocalRef(env, clazz);

  return obj;
}

static Opaque_PkgTarget getitem(JNIEnv *env, jobject obj, const char* cls, const char *key) {
  jclass clazz = (*env)->FindClass(env, cls);
  jfieldID attr = (*env)->GetFieldID(env, clazz, key, "LOpaqueConfig$PkgTarget;");
  jobject val = (*env)->GetObjectField(env, obj, attr);
  jclass ecls = (*env)->FindClass(env, "OpaqueConfig$PkgTarget");
  jmethodID mid = (*env)->GetMethodID(env, ecls, "ordinal", "()I");
  jint res = (*env)->CallIntMethod(env, val, mid);
  if(res != NotPackaged && res != InSecEnv && res != InClrEnv) {
    exception(env,"item is not packaged in envelope");
  }
  (*env)->ExceptionClear(env);
  (*env)->DeleteLocalRef(env, clazz);
  (*env)->DeleteLocalRef(env, val);
  (*env)->DeleteLocalRef(env, ecls);
  return res;
}

static void getcfg(JNIEnv *env, jobject cfg_, Opaque_PkgConfig *cfg) {
  cfg->skU = getitem(env, cfg_, "OpaqueConfig", "skU");
  cfg->pkU = getitem(env, cfg_, "OpaqueConfig", "pkU");
  cfg->pkS = getitem(env, cfg_, "OpaqueConfig", "pkS");
  cfg->idU = getitem(env, cfg_, "OpaqueConfig", "idU");
  cfg->idS = getitem(env, cfg_, "OpaqueConfig", "idS");
}

typedef struct {
  jbyte *idU_jb;
  jbyteArray idU;
  jbyte *idS_jb;
  jbyteArray idS;
} IdGC;

static void getids(JNIEnv *env, jobject ids_, Opaque_Ids *ids, IdGC *gc) {
    jclass   cls;
    jfieldID idUfid, idSfid;
    cls = (*env)->FindClass(env, "OpaqueIds");
    idUfid = (*env)->GetFieldID(env, cls, "idU", "[B");
    gc->idU = (jbyteArray)(*env)->GetObjectField(env, ids_, idUfid);
    idSfid = (*env)->GetFieldID(env, cls, "idS", "[B");
    gc->idS = (jbyteArray)(*env)->GetObjectField(env, ids_, idSfid);

    size_t len;
    if(NULL==gc->idU) {
      ids->idU = NULL;
      ids->idU_len = 0;
      gc->idU=NULL;
    } else {
      len = (*env)->GetArrayLength(env, gc->idU);
      if(len>=65536) {
        exception(env, "idU too big");
      }
      gc->idU_jb = (*env)->GetByteArrayElements(env, gc->idU, NULL);
      ids->idU=(uint8_t*) gc->idU_jb;
      ids->idU_len = len;
    }

    if(NULL==gc->idS) {
      ids->idS = NULL;
      ids->idS_len = 0;
      gc->idS=NULL;
    } else {
      len = (*env)->GetArrayLength(env, gc->idS);
      if(len>=65536) {
        exception(env, "idS too big");
      }
      gc->idS_jb = (*env)->GetByteArrayElements(env, gc->idS, NULL);
      ids->idS=(uint8_t*) gc->idS_jb;
      ids->idS_len = len;
    }
}

static jobject c_register(JNIEnv *env, jobject obj, jstring pwd_, jbyteArray skS_, jobject cfg_, jobject ids_) {
  //int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len, const uint8_t skS[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha512_BYTES]);
  const char *pwdU, *skS=NULL;
  jbyte *skS_jb=NULL;
  size_t pwdU_len;

  if(NULL!=skS_) {
    if((*env)->GetArrayLength(env, skS_)!=crypto_scalarmult_SCALARBYTES) {
      exception(env, "skS has invalid size");
    }
    skS_jb = (*env)->GetByteArrayElements(env, skS_, NULL);
    skS = (char*) skS_jb;
  }

  pwdU  = (*env)->GetStringUTFChars(env, pwd_, 0);
  pwdU_len = (*env)->GetStringLength(env, pwd_);
  //fprintf(stderr,"pwdU: %s, pwdU_len: %ld\n", pwdU, pwdU_len);

  Opaque_PkgConfig cfg = {0};
  getcfg(env, cfg_, &cfg);
  Opaque_Ids ids = {0};
  IdGC gc;
  getids(env, ids_, &ids, &gc);

  uint8_t export_key[crypto_hash_sha512_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key)) {
    exception(env,"opaque register() failed...");
  }
  (*env)->ReleaseStringUTFChars(env, pwd_, pwdU);
  if(skS_!=NULL) {
    (*env)->ReleaseByteArrayElements(env, skS_, skS_jb, JNI_ABORT);
  }
  (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);

  RetVal ret[] = {{.key = "rec", .val = rec, .len = sizeof(rec) },
                  {.key = "export_key", .val = export_key, .len = sizeof(export_key)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRecExpKey", ret);
}

static jobject c_register_noskS(JNIEnv *env, jobject obj, jstring pwd_, jobject cfg_, jobject ids_) {
  return c_register(env, obj, pwd_, NULL, cfg_, ids_);
}

//int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
static jobject c_createCredReq(JNIEnv *env, jobject obj, jstring pwd_) {
  const char *pwdU;
  size_t pwdU_len;

  pwdU  = (*env)->GetStringUTFChars(env, pwd_, 0);
  pwdU_len = (*env)->GetStringLength(env, pwd_);
  //fprintf(stderr,"pwdU: %s, pwdU_len: %ld\n", pwdU, pwdU_len);

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
    pub[OPAQUE_USER_SESSION_PUBLIC_LEN];

  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) {
    exception(env,"opaque createCredReq() failed...");
  }
  (*env)->ReleaseStringUTFChars(env, pwd_, pwdU);

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "pub", .val = pub, .len = sizeof(pub)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueCredReq", ret);
}

//int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);
static jobject _c_createCredResp(JNIEnv *env, jobject obj, jbyteArray pub_, jbyteArray rec_, jobject cfg_, jobject ids_) {
  const uint8_t *pub, // OPAQUE_USER_SESSION_PUBLIC_LEN
                *rec; // OPAQUE_USER_RECORD_LEN+envU_len

  if((*env)->GetArrayLength(env, pub_)!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    exception(env, "invalid request size");
  }
  jbyte *pub_jb=NULL;
  pub_jb = (*env)->GetByteArrayElements(env, pub_, NULL);
  pub = (char*) pub_jb;

  jbyte *rec_jb=NULL;
  rec_jb = (*env)->GetByteArrayElements(env, rec_, NULL);
  rec = (char*) rec_jb;

  Opaque_PkgConfig cfg = {0};
  getcfg(env, cfg_, &cfg);
  Opaque_Ids ids = {0};
  IdGC gc;
  getids(env, ids_, &ids, &gc);

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);

  if((*env)->GetArrayLength(env, rec_)!=OPAQUE_USER_RECORD_LEN+envU_len) {
    exception(env, "invalid record size");
  }

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, NULL, resp, sk, sec)) {
    exception(env,"opaque createCredResp() failed...");
  }

  (*env)->ReleaseByteArrayElements(env, pub_, pub_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, rec_, rec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "sk", .val = sk, .len = sizeof(sk)},
                  {.key = "pub", .val = resp, .len = sizeof(resp)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueCredResp", ret);
}

static jobject c_createCredResp(JNIEnv *env, jobject obj, jbyteArray pub_, jbyteArray rec_, jobject cfg_, jobject ids_) {
  return _c_createCredResp(env,obj,pub_,rec_,cfg_,ids_);
}


//int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/], const uint8_t pkS[crypto_scalarmult_BYTES], const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t authU[crypto_auth_hmacsha512_BYTES], uint8_t export_key[crypto_hash_sha512_BYTES]);
static jobject _c_recoverCredentials(JNIEnv *env, jobject obj, jbyteArray resp_, jbyteArray sec_, jbyteArray pkS_, jobject cfg_, jobject ids_) {

  Opaque_PkgConfig cfg = {0};
  getcfg(env, cfg_, &cfg);

  Opaque_Ids ids = {0};
  IdGC gc={0};
  getids(env, ids_, &ids, &gc);

  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);

  const size_t resp_len = (*env)->GetArrayLength(env, resp_);
  if(resp_len<OPAQUE_SERVER_SESSION_LEN+envU_len) {
    exception(env, "invalid response size");
  }
  uint8_t *resp;
  jbyte *resp_jb;
  resp_jb = (*env)->GetByteArrayElements(env, resp_, NULL);
  resp = (char*) resp_jb;

  const size_t sec_len = (*env)->GetArrayLength(env, sec_);
  if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
    exception(env, "invalid secret context size");
  }
  uint8_t *sec;
  jbyte *sec_jb;
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  uint8_t *pkS=0;
  jbyte *pkS_jb=NULL;
  if(NULL!=pkS_) {
    if (cfg.pkS!=NotPackaged) {
      exception(env, "pkS is packaged according to cfg and also provided as param");
    }
    if((*env)->GetArrayLength(env, sec_)!=crypto_scalarmult_BYTES) {
      exception(env, "invalid pkS size");
    }
    pkS_jb = (*env)->GetByteArrayElements(env, pkS_, NULL);
    pkS = (char*) pkS_jb;
  } else if (cfg.pkS==NotPackaged) {
    exception(env, "pkS is NotPackaged in cfg and also not provided as param");
  }

  uint8_t idU[1024]={0}, idS[1024]={0};
  if (cfg.idU==NotPackaged) {
    if (ids.idU==NULL) {
      exception(env, "ids.idU cannot be nil if cfg.idU is NotPackaged.");
    }
  } else {
    if(ids.idS!=NULL) {
      exception(env, "ids.idU cannot be provided if cfg.idU is packaged.");
    }
    ids.idU = idU;
    ids.idU_len = sizeof(idU);
  }
  if (cfg.idS==NotPackaged) {
    if (ids.idS==NULL) {
      exception(env, "ids.idS cannot be nil if cfg.idS is NotPackaged.");
    }
  } else {
    if(ids.idS!=NULL) {
      exception(env, "ids.idS cannot be provided if cfg.idS is packaged.");
    }
    ids.idS = idS;
    ids.idS_len = sizeof(idS);
  }

  //  exception(env,"opaque createCredResp() failed...");
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, pkS, &cfg, NULL, &ids, sk, authU, export_key)) {
    exception(env,"opaque recoverCredentials() failed...");
  }

  if(NULL!=gc.idU_jb) {
    (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
  }
  if(NULL!=gc.idS_jb) {
    (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);
  }
  (*env)->ReleaseByteArrayElements(env, resp_, resp_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  if(NULL!=pkS_) {
    (*env)->ReleaseByteArrayElements(env, pkS_, pkS_jb, JNI_ABORT);
  }

  RetVal retvals[] = {{.key = "authU", .val = authU, .len = sizeof(authU) },
                  {.key = "sk", .val = sk, .len = sizeof(sk)},
                  {.key = "export_key", .val = export_key, .len = sizeof(export_key)},
                  { .key = NULL, .val = NULL}};

  jobject ret = retlist(env, "OpaqueCreds", retvals);
  jclass clazz = (*env)->FindClass(env, "OpaqueCreds");
  jfieldID attr = (*env)->GetFieldID(env, clazz, "ids", "LOpaqueIds;");
  (*env)->SetObjectField(env, ret, attr, ids_);
  (*env)->DeleteLocalRef(env, clazz);

  jclass oidcls=(*env)->FindClass(env, "OpaqueIds");
  if(cfg.idU!=NotPackaged) {
    jfieldID attr = (*env)->GetFieldID(env, oidcls, "idU", "[B");
    jbyteArray arr = (*env)->NewByteArray(env, ids.idU_len);
    (*env)->SetByteArrayRegion(env, arr, 0, ids.idU_len, ids.idU);
    (*env)->SetObjectField(env, ids_, attr, arr);
    (*env)->DeleteLocalRef(env, arr);
  }
  if(cfg.idS!=NotPackaged) {
    jfieldID attr = (*env)->GetFieldID(env, oidcls, "idS", "[B");
    jbyteArray arr = (*env)->NewByteArray(env, ids.idS_len);
    (*env)->SetByteArrayRegion(env, arr, 0, ids.idS_len, ids.idS);
    (*env)->SetObjectField(env, ids_, attr, arr);
    (*env)->DeleteLocalRef(env, arr);
  }
  (*env)->DeleteLocalRef(env, oidcls);

  return ret;
}

static jobject _c_recoverCredentials_NP(JNIEnv *env, jobject obj, jbyteArray resp_, jbyteArray sec_, jobject cfg_, jobject ids_) {
  return _c_recoverCredentials(env,obj,resp_,sec_,NULL,cfg_,ids_);
}

static jboolean c_userAuth(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray authU_) {
//int opaque_UserAuth(const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha512_BYTES]);
  const uint8_t *sec,
                *authU;

  if((*env)->GetArrayLength(env, sec_)!=OPAQUE_SERVER_AUTH_CTX_LEN) {
    exception(env, "invalid secret context size");
    return JNI_FALSE;
  }
  if((*env)->GetArrayLength(env, authU_)!=crypto_auth_hmacsha512_BYTES) {
    exception(env, "invalid auth token size");
    return JNI_FALSE;
  }
  jbyte *sec_jb=NULL;
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  jbyte *authU_jb=NULL;
  authU_jb = (*env)->GetByteArrayElements(env, authU_, NULL);
  authU = (char*) authU_jb;

  int ret = opaque_UserAuth(sec, authU);

  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, authU_, authU_jb, JNI_ABORT);

  if(0!=ret) {
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

static jobject c_createRegReq(JNIEnv *env, jobject obj, jstring pwd_) {
// int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len,
// uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t M[crypto_core_ristretto255_BYTES]);
  const char *pwdU;
  size_t pwdU_len;
  pwdU  = (*env)->GetStringUTFChars(env, pwd_, 0);
  pwdU_len = (*env)->GetStringLength(env, pwd_);

  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];
  uint8_t M[crypto_core_ristretto255_BYTES];

  int res = opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M);
  (*env)->ReleaseStringUTFChars(env, pwd_, pwdU);
  if(0!=res) {
    exception(env,"opaque register() failed...");
    return NULL;
  }
  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "M", .val = M, .len = sizeof(M)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRegReq", ret);
}

static jobject c_createRegResp(JNIEnv *env, jobject obj, jbyteArray M_) {
  // int opaque_CreateRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
  const char *M=NULL;
  jbyte *M_jb=NULL;

  if((*env)->GetArrayLength(env, M_)!=crypto_core_ristretto255_BYTES) {
    exception(env, "M has invalid size");
  }
  M_jb = (*env)->GetByteArrayElements(env, M_, NULL);
  M = (char*) M_jb;

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];

  int res = opaque_CreateRegistrationResponse(M, sec, pub);

  (*env)->ReleaseByteArrayElements(env, M_, M_jb, JNI_ABORT);

  if(0!=res) {
    exception(env,"opaque create registration response () failed...");
    return NULL;
  }

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "pub", .val = pub, .len = sizeof(pub)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRegResp", ret);
}

static jobject c_create1kRegResp(JNIEnv *env, jobject obj, jbyteArray M_, jbyteArray pkS_) {
  // int opaque_Create1kRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
  const char *pkS=NULL, *M=NULL;
  jbyte *pkS_jb=NULL, *M_jb=NULL;

  if(NULL!=pkS_) {
    if((*env)->GetArrayLength(env, pkS_)!=crypto_scalarmult_BYTES) {
      exception(env, "pkS has invalid size");
    }
    pkS_jb = (*env)->GetByteArrayElements(env, pkS_, NULL);
    pkS = (char*) pkS_jb;
  }

  if((*env)->GetArrayLength(env, M_)!=crypto_core_ristretto255_BYTES) {
    exception(env, "M has invalid size");
  }
  M_jb = (*env)->GetByteArrayElements(env, M_, NULL);
  M = (char*) M_jb;

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];

  int res = opaque_Create1kRegistrationResponse(M, pkS, sec, pub);

  if(pkS_!=NULL) {
    (*env)->ReleaseByteArrayElements(env, pkS_, pkS_jb, JNI_ABORT);
  }
  (*env)->ReleaseByteArrayElements(env, M_, M_jb, JNI_ABORT);

  if(0!=res) {
    exception(env,"opaque create registration response () failed...");
    return NULL;
  }

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "pub", .val = pub, .len = sizeof(pub)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRegResp", ret);
}

static jobject c_finalizeReg(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray pub_, jobject cfg_, jobject ids_) {
// int opaque_FinalizeRequest(const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids,
// uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha512_BYTES]);
  const char *sec=NULL, *pub=NULL;
  jbyte *sec_jb=NULL, *pub_jb = NULL;

  if((*env)->GetArrayLength(env, sec_)<=OPAQUE_REGISTER_USER_SEC_LEN) {
    exception(env, "sec has invalid size");
  }
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  if((*env)->GetArrayLength(env, pub_)!=OPAQUE_REGISTER_PUBLIC_LEN) {
    exception(env, "pub has invalid size");
  }
  pub_jb = (*env)->GetByteArrayElements(env, pub_, NULL);
  pub = (char*) pub_jb;

  Opaque_PkgConfig cfg = {0};
  getcfg(env, cfg_, &cfg);
  Opaque_Ids ids = {0};
  IdGC gc;
  getids(env, ids_, &ids, &gc);

  uint8_t export_key[crypto_hash_sha512_BYTES];
  const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
  uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

  if(0!=opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key)) {
    exception(env,"opaque register() failed...");
  }

  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, pub_, pub_jb, JNI_ABORT);

  (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);

  RetVal ret[] = {{.key = "rec", .val = rec, .len = sizeof(rec) },
                  {.key = "export_key", .val = export_key, .len = sizeof(export_key)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaquePreRecExpKey", ret);
}

static jbyteArray c_storeRec(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray rec_) {
// void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
// uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
  const char *sec=NULL;
  char *rec=NULL;
  jbyte *sec_jb=NULL, *rec_jb = NULL;

  if((*env)->GetArrayLength(env, sec_)<=OPAQUE_REGISTER_USER_SEC_LEN) {
    exception(env, "sec has invalid size");
    return NULL;
  }
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  size_t rec_len= (*env)->GetArrayLength(env, rec_);
  if(rec_len<=OPAQUE_USER_RECORD_LEN) {
    exception(env, "rec has invalid size");
    return NULL;
  }
  rec_jb = (*env)->GetByteArrayElements(env, rec_, NULL);
  rec = (char*) rec_jb;

  opaque_StoreUserRecord(sec, rec);

  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, rec_, rec_jb, 0);

  return rec_;
}

static jbyteArray c_store1kRec(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray skS_, jbyteArray rec_) {
// void opaque_Store1kUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES],
// uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);

  const char *sec=NULL, *skS=NULL;
  char *rec=NULL;
  jbyte *sec_jb=NULL, *rec_jb = NULL, *skS_jb = NULL;

  if((*env)->GetArrayLength(env, sec_)<=OPAQUE_REGISTER_USER_SEC_LEN) {
    exception(env, "sec has invalid size");
    return NULL;
  }
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  size_t rec_len= (*env)->GetArrayLength(env, rec_);
  if(rec_len<=OPAQUE_USER_RECORD_LEN) {
    exception(env, "rec has invalid size");
    return NULL;
  }
  rec_jb = (*env)->GetByteArrayElements(env, rec_, NULL);
  rec = (char*) rec_jb;

  if((*env)->GetArrayLength(env, skS_)!=crypto_scalarmult_SCALARBYTES) {
    exception(env, "skS has invalid size");
    return NULL;
  }
  skS_jb = (*env)->GetByteArrayElements(env, skS_, NULL);
  skS = (char*) skS_jb;

  opaque_Store1kUserRecord(sec, skS, rec);

  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, rec_, rec_jb, 0);
  (*env)->ReleaseByteArrayElements(env, skS_, skS_jb, JNI_ABORT);

  return rec_;
}

static JNINativeMethod funcs[] = {
    { "c_register", "(Ljava/lang/String;[BLOpaqueConfig;LOpaqueIds;)LOpaqueRecExpKey;", (void *)&c_register },
    { "c_register", "(Ljava/lang/String;LOpaqueConfig;LOpaqueIds;)LOpaqueRecExpKey;", (void *)&c_register_noskS },
    { "c_createCredReq", "(Ljava/lang/String;)LOpaqueCredReq;", (void *)&c_createCredReq },
    { "c_createCredResp", "([B[BLOpaqueConfig;LOpaqueIds;)LOpaqueCredResp;", (void *)&c_createCredResp },
    { "c_recoverCreds", "([B[B[BLOpaqueConfig;LOpaqueIds;)LOpaqueCreds;", (void *)&_c_recoverCredentials },
    { "c_recoverCreds", "([B[BLOpaqueConfig;LOpaqueIds;)LOpaqueCreds;", (void *)&_c_recoverCredentials_NP },
    { "c_userAuth", "([B[B)Z", (void *)&c_userAuth },
    { "c_createRegReq", "(Ljava/lang/String;)LOpaqueRegReq;", (void *)&c_createRegReq },
    { "c_createRegResp", "([B)LOpaqueRegResp;", (void *)&c_createRegResp},
    { "c_createRegResp", "([B[B)LOpaqueRegResp;", (void *)&c_create1kRegResp },
    { "c_finalizeReg", "([B[BLOpaqueConfig;LOpaqueIds;)LOpaquePreRecExpKey;", (void *)&c_finalizeReg },
    { "c_storeRec", "([B[B)[B", (void *)&c_storeRec },
    { "c_storeRec", "([B[B[B)[B", (void *)&c_store1kRec },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv *env;
	jclass  cls;
	jint    res;

	(void)reserved;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8) != JNI_OK)
		return -1;

	cls = (*env)->FindClass(env, JNIT_CLASS);
	if (cls == NULL)
		return -1;

	res = (*env)->RegisterNatives(env, cls, funcs, sizeof(funcs)/sizeof(*funcs));
	if (res != 0)
		return -1;

	return JNI_VERSION_1_8;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env;
	jclass  cls;

	(void)reserved;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8) != JNI_OK)
		return;

	cls = (*env)->FindClass(env, JNIT_CLASS);
	if (cls == NULL)
		return;

	(*env)->UnregisterNatives(env, cls);
}
