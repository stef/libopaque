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
  const char *key;
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

static jobject c_register(JNIEnv *env, jobject obj, jstring pwd_, jbyteArray skS_, jobject ids_) {
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

  Opaque_Ids ids = {0};
  IdGC gc;
  if(NULL!=ids_) getids(env, ids_, &ids, &gc);

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) {
    exception(env,"opaque register() failed...");
  }
  (*env)->ReleaseStringUTFChars(env, pwd_, pwdU);
  if(skS_!=NULL) {
    (*env)->ReleaseByteArrayElements(env, skS_, skS_jb, JNI_ABORT);
  }
  if(NULL!=ids_) {
    (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);
  }

  RetVal ret[] = {{.key = "rec", .val = rec, .len = sizeof(rec) },
                  {.key = "export_key", .val = export_key, .len = sizeof(export_key)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRecExpKey", ret);
}

static jobject c_register_noIds(JNIEnv *env, jobject obj, jstring pwd_, jbyteArray sks_) {
  return c_register(env, obj, pwd_, sks_, NULL);
}

static jobject c_register_noSks(JNIEnv *env, jobject obj, jstring pwd_, jobject ids_) {
  return c_register(env, obj, pwd_, NULL, ids_);
}

static jobject c_register1(JNIEnv *env, jobject obj, jstring pwd_) {
  return c_register(env, obj, pwd_, NULL, NULL);
}

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

static jobject c_createCredResp(JNIEnv *env, jobject obj, jbyteArray pub_, jbyteArray rec_, jobject ids_, jstring context_) {
  const uint8_t *pub, // OPAQUE_USER_SESSION_PUBLIC_LEN
                *rec; // OPAQUE_USER_RECORD_LEN+envU_len

  if((*env)->GetArrayLength(env, pub_)!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    exception(env, "invalid request size");
  }
  jbyte *pub_jb=NULL;
  pub_jb = (*env)->GetByteArrayElements(env, pub_, NULL);
  pub = (char*) pub_jb;

  if((*env)->GetArrayLength(env, rec_)!=OPAQUE_USER_RECORD_LEN) {
    exception(env, "invalid record size");
  }
  jbyte *rec_jb=NULL;
  rec_jb = (*env)->GetByteArrayElements(env, rec_, NULL);
  rec = (char*) rec_jb;

  const char *context;
  size_t context_len;
  context  = (*env)->GetStringUTFChars(env, context_, 0);
  context_len = (*env)->GetStringLength(env, context_);

  Opaque_Ids ids = {0};
  IdGC gc;
  getids(env, ids_, &ids, &gc);

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[crypto_auth_hmacsha512_BYTES]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, sec)) {
    exception(env,"opaque createCredResp() failed...");
  }

  (*env)->ReleaseByteArrayElements(env, pub_, pub_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, rec_, rec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idU, gc.idU_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, gc.idS, gc.idS_jb, JNI_ABORT);
  (*env)->ReleaseStringUTFChars(env, context_, context);

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "sk", .val = sk, .len = sizeof(sk)},
                  {.key = "pub", .val = resp, .len = sizeof(resp)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueCredResp", ret);
}

static jobject c_recoverCredentials(JNIEnv *env, jobject obj, jbyteArray resp_, jbyteArray sec_, jstring context_, jobject ids_) {

  Opaque_Ids ids = {0};
  IdGC gc={0};
  getids(env, ids_, &ids, &gc);

  const size_t resp_len = (*env)->GetArrayLength(env, resp_);
  if(resp_len!=OPAQUE_SERVER_SESSION_LEN) {
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

  const char *context;
  size_t context_len;
  context  = (*env)->GetStringUTFChars(env, context_, 0);
  context_len = (*env)->GetStringLength(env, context_);

  //  exception(env,"opaque createCredResp() failed...");
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key)) {
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
  (*env)->ReleaseStringUTFChars(env, context_, context);

  RetVal retvals[] = {{.key = "authU", .val = authU, .len = sizeof(authU) },
                  {.key = "sk", .val = sk, .len = sizeof(sk)},
                  {.key = "export_key", .val = export_key, .len = sizeof(export_key)},
                  { .key = NULL, .val = NULL}};

  jobject ret = retlist(env, "OpaqueCreds", retvals);
  jclass clazz = (*env)->FindClass(env, "OpaqueCreds");

  return ret;
}

static jboolean c_userAuth(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray authU_) {
//int opaque_UserAuth(const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha512_BYTES]);
  const uint8_t *sec,
                *authU;

  if((*env)->GetArrayLength(env, sec_)!=crypto_auth_hmacsha512_BYTES) {
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

static jobject c_createRegResp(JNIEnv *env, jobject obj, jbyteArray M_, jbyteArray sks_) {
  const char *M=NULL;
  jbyte *M_jb=NULL;

  if((*env)->GetArrayLength(env, M_)!=crypto_core_ristretto255_BYTES) {
    exception(env, "M has invalid size");
  }
  M_jb = (*env)->GetByteArrayElements(env, M_, NULL);
  M = (char*) M_jb;

  const char *sks=NULL;
  jbyte *sks_jb=NULL;

  if(sks_!=NULL) {
    if((*env)->GetArrayLength(env, sks_)!=crypto_scalarmult_SCALARBYTES) {
      exception(env, "skS has invalid size");
    }
    sks_jb = (*env)->GetByteArrayElements(env, sks_, NULL);
    sks = (char*) sks_jb;
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN];
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN];

  int res = opaque_CreateRegistrationResponse(M, sks, sec, pub);

  (*env)->ReleaseByteArrayElements(env, M_, M_jb, JNI_ABORT);
  if(sks_!=NULL) (*env)->ReleaseByteArrayElements(env, sks_, sks_jb, JNI_ABORT);

  if(0!=res) {
    exception(env,"opaque create registration response () failed...");
    return NULL;
  }

  RetVal ret[] = {{.key = "sec", .val = sec, .len = sizeof(sec) },
                  {.key = "pub", .val = pub, .len = sizeof(pub)},
                  { .key = NULL, .val = NULL}};

  return retlist(env, "OpaqueRegResp", ret);
}

static jobject c_createRegResp1(JNIEnv *env, jobject obj, jbyteArray M_) {
  return c_createRegResp(env, obj, M_, NULL);
}

static jobject c_finalizeReg(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray pub_, jobject ids_) {
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

  Opaque_Ids ids = {0};
  IdGC gc;
  getids(env, ids_, &ids, &gc);

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_FinalizeRequest(sec, pub, &ids, rec, export_key)) {
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

static jbyteArray c_storeRec(JNIEnv *env, jobject obj, jbyteArray sec_, jbyteArray recU_) {
  const char *sec=NULL;
  char *recU=NULL;
  jbyte *sec_jb=NULL, *recU_jb = NULL;

  if((*env)->GetArrayLength(env, sec_)<=OPAQUE_REGISTER_USER_SEC_LEN) {
    exception(env, "sec has invalid size");
    return NULL;
  }
  sec_jb = (*env)->GetByteArrayElements(env, sec_, NULL);
  sec = (char*) sec_jb;

  size_t recU_len= (*env)->GetArrayLength(env, recU_);
  if(recU_len<=OPAQUE_REGISTRATION_RECORD_LEN) {
    exception(env, "recU has invalid size");
    return NULL;
  }
  recU_jb = (*env)->GetByteArrayElements(env, recU_, NULL);
  recU = (char*) recU_jb;

  uint8_t rec[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(sec, recU, rec);

  (*env)->ReleaseByteArrayElements(env, sec_, sec_jb, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, recU_, recU_jb, 0);

  jbyteArray rec_ = (*env)->NewByteArray(env, sizeof rec);
  (*env)->SetByteArrayRegion(env, rec_, 0, sizeof rec, rec);

  return rec_;
}


static JNINativeMethod funcs[] = {
  { "c_register", "(Ljava/lang/String;[BLOpaqueIds;)LOpaqueRecExpKey;", (void *)&c_register },
  { "c_register", "(Ljava/lang/String;[B)LOpaqueRecExpKey;", (void *)&c_register_noIds },
  { "c_register", "(Ljava/lang/String;LOpaqueIds;)LOpaqueRecExpKey;", (void *)&c_register_noSks },
  { "c_register", "(Ljava/lang/String;)LOpaqueRecExpKey;", (void *)&c_register1 },
  { "c_createCredReq", "(Ljava/lang/String;)LOpaqueCredReq;", (void *)&c_createCredReq },
  { "c_createCredResp", "([B[BLOpaqueIds;Ljava/lang/String;)LOpaqueCredResp;", (void *)&c_createCredResp },
  { "c_recoverCreds", "([B[BLjava/lang/String;LOpaqueIds;)LOpaqueCreds;", (void *)&c_recoverCredentials },
  { "c_userAuth", "([B[B)Z", (void *)&c_userAuth },
  { "c_createRegReq", "(Ljava/lang/String;)LOpaqueRegReq;", (void *)&c_createRegReq },
  { "c_createRegResp", "([B[B)LOpaqueRegResp;", (void *)&c_createRegResp},
  { "c_createRegResp", "([B)LOpaqueRegResp;", (void *)&c_createRegResp1},
  { "c_finalizeReg", "([B[BLOpaqueIds;)LOpaquePreRecExpKey;", (void *)&c_finalizeReg },
  { "c_storeRec", "([B[B)[B", (void *)&c_storeRec },
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
