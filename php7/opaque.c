/* opaque extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_opaque.h"
#include "opaque.h"
#include "common.h"

/* See src/opaque.c. */
#define OPAQUE_SHARED_SECRETBYTES 32

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

static zval* get_infostr(const zend_array *info_array, const int index) {
  zval *x;
  if (!(x=zend_hash_index_find(info_array, index))) return NULL;
  if (Z_TYPE_P(x) != IS_STRING) {
      php_error_docref(NULL, E_WARNING, "unexpected value type for infos string.");
      return NULL;
  }
  return x;
}

static int get_cfgval(const zend_array *cfg_array, const int index) {
  zval *x;
  if ((x=zend_hash_index_find(cfg_array, index))) {
    if (Z_TYPE_P(x) == IS_LONG) {
      int r = Z_LVAL_P(x);
      if(r<0 || r>2) {
        php_error_docref(NULL, E_WARNING, "invalid value for opaque cfg setting.");
        return -1;
      }
      return r;
    } else {
      php_error_docref(NULL, E_WARNING, "unexpected value type for cfg setting.");
      return -1;
    }
    php_error_docref(NULL, E_WARNING, "missing value for cfg setting.");
    return -1;
  }
}

static int get_cfg(Opaque_PkgConfig *cfg, const zend_array *cfg_array) {
    int r;
    if((r=get_cfgval(cfg_array, 0))==-1) return 1;
    cfg->skU=r;
    if((r=get_cfgval(cfg_array, 1))==-1) return 1;
    cfg->pkU=r;
    if((r=get_cfgval(cfg_array, 2))==-1) return 1;
    cfg->pkS=r;
    if((r=get_cfgval(cfg_array, 3))==-1) return 1;
    cfg->idS=r;
    if((r=get_cfgval(cfg_array, 4))==-1) return 1;
    cfg->idU=r;
    return 0;
}

static Opaque_App_Infos * get_infos(Opaque_App_Infos *infos, const zend_array *infos_array) {
  zval *x;
  Opaque_App_Infos *ret=NULL;
  if(infos_array==NULL) return NULL;

  if((x=get_infostr(infos_array, 0))) {
    infos->info1 = Z_STRVAL(*x);
    infos->info1_len = Z_STRLEN(*x);
    ret = infos;
  }
  if((x=get_infostr(infos_array, 1))) {
    infos->info2 = Z_STRVAL(*x);
    infos->info2_len = Z_STRLEN(*x);
    ret = infos;
  }
  if((x=get_infostr(infos_array, 2))) {
    infos->einfo2 = Z_STRVAL(*x);
    infos->einfo2_len = Z_STRLEN(*x);
    ret = infos;
  }
  if((x=get_infostr(infos_array, 3))) {
    infos->info3 = Z_STRVAL(*x);
    infos->info3_len = Z_STRLEN(*x);
    ret = infos;
  }
  if((x=get_infostr(infos_array, 4))) {
    infos->einfo3 = Z_STRVAL(*x);
    infos->einfo3_len = Z_STRLEN(*x);
    ret = infos;
  }
  return ret;
}

/* {{{ */

PHP_FUNCTION(opaque_register) {
  char *pwdU;
  size_t pwdU_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;

  char *skS=NULL;
  size_t skS_len=0;

  zend_array *cfg_array;

	ZEND_PARSE_PARAMETERS_START(4, 5)
		Z_PARAM_STRING(pwdU, pwdU_len)
		Z_PARAM_STRING(idU, idU_len)
		Z_PARAM_STRING(idS, idS_len)
      Z_PARAM_ARRAY_HT(cfg_array)
	Z_PARAM_OPTIONAL
		Z_PARAM_STRING(skS, skS_len)
	ZEND_PARSE_PARAMETERS_END();

    Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};
    Opaque_PkgConfig cfg;

    if(0!=get_cfg(&cfg, cfg_array)) {
      php_error_docref(NULL, E_WARNING, "invalid cfg array.");
      return;
    }

    if(skS!=NULL && skS_len!=crypto_scalarmult_SCALARBYTES) {
      php_error_docref(NULL, E_WARNING, "invalid skS size, must be 32B.");
      return;
    }

    uint8_t export_key[crypto_hash_sha256_BYTES];
    const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
    uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];

    if(0!=opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,rec, sizeof(rec));
    add_next_index_stringl(&zarr,export_key, sizeof(export_key)); // sensitive

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_credential_request) {
  char *pwdU;
  size_t pwdU_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(pwdU, pwdU_len)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];

    if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sec, sizeof(sec));  // sensitive
    add_next_index_stringl(&zarr,pub, sizeof(pub));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_credential_response) {
  char *pub;
  size_t pub_len;
  char *rec;
  size_t rec_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;
  zend_array *cfg_array;
  zend_array *infos_array=NULL;

	ZEND_PARSE_PARAMETERS_START(5, 6)
		Z_PARAM_STRING(pub, pub_len)
		Z_PARAM_STRING(rec, rec_len)
		Z_PARAM_STRING(idU, idU_len)
		Z_PARAM_STRING(idS, idS_len)
        Z_PARAM_ARRAY_HT(cfg_array)
		Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT(infos_array)
	ZEND_PARSE_PARAMETERS_END();

    if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid pub param.");
      return;
    }

    Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

    Opaque_PkgConfig cfg;
    if(0!=get_cfg(&cfg, cfg_array)) {
      php_error_docref(NULL, E_WARNING, "invalid cfg array.");
      return;
    }

    const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
    if(rec_len!=OPAQUE_USER_RECORD_LEN+envU_len) {
      php_error_docref(NULL, E_WARNING, "invalid rec param.");
      return;
    }

    Opaque_App_Infos infos={0}, *infos_p=get_infos(&infos, infos_array);

    uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
    uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
    uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

    if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, infos_p, resp, sk, sec)) return;

    zend_array *ret = zend_new_array(3);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,resp, sizeof(resp));
    add_next_index_stringl(&zarr,sk, sizeof(sk));      // sensitive
    add_next_index_stringl(&zarr,sec, sizeof(sec));    // sensitive

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_recover_credentials) {
  char *resp;
  size_t resp_len;
  char *sec;
  size_t sec_len;
  char *pkS=NULL;
  size_t pkS_len=0;
  zend_array *cfg_array;
  zend_array *infos_array=NULL;
  char *idU=NULL;
  size_t idU_len=0;
  char *idS=NULL;
  size_t idS_len=0;

	ZEND_PARSE_PARAMETERS_START(3, 7)
		Z_PARAM_STRING(resp, resp_len)
		Z_PARAM_STRING(sec, sec_len)
      Z_PARAM_ARRAY_HT(cfg_array)
   Z_PARAM_OPTIONAL
      Z_PARAM_ARRAY_HT(infos_array)
		Z_PARAM_STRING(pkS, pkS_len)
		Z_PARAM_STRING(idU, idU_len)
		Z_PARAM_STRING(idS, idS_len)
	ZEND_PARSE_PARAMETERS_END();

    if(resp_len<=OPAQUE_SERVER_SESSION_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid resp param.");
      return;
    }

    if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid sec param.");
      return;
    }

    if(pkS && pkS_len!=crypto_scalarmult_BYTES) {
      php_error_docref(NULL, E_WARNING, "invalid pkS param.");
      return;
    }

    Opaque_PkgConfig cfg;
    if(0!=get_cfg(&cfg, cfg_array)) {
      php_error_docref(NULL, E_WARNING, "invalid cfg array.");
      return;
    }

    if (cfg.pkS==NotPackaged && pkS==NULL) {
      php_error_docref(NULL, E_WARNING, "pkS cannot be None if cfg.pkS is NotPackaged.");
      return;
    }

    uint8_t idU1[1024], idS1[1024];
    size_t idU1_len, idS1_len;
    if (cfg.idU==NotPackaged) {
      if (idU==NULL) {
        php_error_docref(NULL, E_WARNING, "idU cannot be NULL if cfg.idU is NotPackaged.");
        return;
      }
      memcpy(idU1, idU, idU_len);
      idU1_len = idU_len;
    } else {
      idU1_len = sizeof(idU1);
    }
    if (cfg.idS==NotPackaged) {
      if (idS==NULL) {
        php_error_docref(NULL, E_WARNING, "idS cannot be NULL if cfg.idS is NotPackaged.");
        return;
      }
      memcpy(idS1, idS, idS_len);
      idS1_len = idS_len;
    } else {
      idS1_len = sizeof(idS1);
    }
    Opaque_Ids ids1={.idU_len=idU1_len,.idU=idU1,.idS_len=idS1_len,.idS=idS1};

    Opaque_App_Infos infos={0}, *infos_p=get_infos(&infos, infos_array);

    uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU[crypto_auth_hmacsha256_BYTES];
    uint8_t export_key[crypto_hash_sha256_BYTES];

    if(0!=opaque_RecoverCredentials(resp, sec, pkS, &cfg, infos_p, &ids1, sk, authU, export_key)) return;

    zend_array *ret = zend_new_array(5);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sk, sizeof(sk));                   // sensitive
    add_next_index_stringl(&zarr,authU, sizeof(authU));             // sensitive
    add_next_index_stringl(&zarr,export_key, sizeof(export_key));   // sensitive
    add_next_index_stringl(&zarr,ids1.idU, ids1.idU_len);
    add_next_index_stringl(&zarr,ids1.idS, ids1.idS_len);

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_user_auth) {
  char *sec;
  size_t sec_len;
  char *authU;
  size_t authU_len;
  zend_array *infos_array=NULL;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STRING(sec, sec_len)
		Z_PARAM_STRING(authU, authU_len)
		Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT(infos_array)
	ZEND_PARSE_PARAMETERS_END();

    if(sec_len!=OPAQUE_SERVER_AUTH_CTX_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid sec param.");
      return;
    }
    if(authU_len!=crypto_auth_hmacsha256_BYTES) {
      php_error_docref(NULL, E_WARNING, "invalid authU param.");
      return;
    }

    Opaque_App_Infos infos={0}, *infos_p=get_infos(&infos, infos_array);

    zval zbool;

    if(0!=opaque_UserAuth(sec, authU, infos_p))
      RETURN_FALSE;
    RETURN_TRUE;
}

PHP_FUNCTION(opaque_create_registration_request) {
  char *pwdU;
  size_t pwdU_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(pwdU, pwdU_len)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    uint8_t M[crypto_core_ristretto255_BYTES];
    uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len];

    if(0!=opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,M, sizeof(M));
    add_next_index_stringl(&zarr,sec, sizeof(sec));       // sensitive

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_registration_response) {
  char *M;
  size_t M_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(M, M_len)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    if(M_len!=crypto_core_ristretto255_BYTES) {
      php_error_docref(NULL, E_WARNING, "invalid M param.");
      return;
    }

    uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];
    if(0!=opaque_CreateRegistrationResponse(M, sec, pub)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sec, sizeof(sec));       // sensitive
    add_next_index_stringl(&zarr,pub, sizeof(pub));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_1k_registration_response) {
  char *M;
  size_t M_len;
  char *pkS;
  size_t pkS_len;

  ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(M, M_len)
    Z_PARAM_STRING(pkS, pkS_len)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  if(M_len!=crypto_core_ristretto255_BYTES) {
    php_error_docref(NULL, E_WARNING, "invalid M param.");
    return;
  }
  if(pkS_len!=crypto_scalarmult_BYTES) {
    php_error_docref(NULL, E_WARNING, "invalid pkS param.");
    return;
  }

  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_Create1kRegistrationResponse(M, pkS, sec, pub)) return;

  zend_array *ret = zend_new_array(2);
  zval zarr;
  ZVAL_ARR(&zarr, ret);
  add_next_index_stringl(&zarr,sec, sizeof(sec)); // sensitive
  add_next_index_stringl(&zarr,pub, sizeof(pub));

  RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_finalize_request) {
  char *sec;
  size_t sec_len;
  char *pub;
  size_t pub_len;
  char *idU;
  size_t idU_len;
  char *idS;
  size_t idS_len;
  zend_array *cfg_array;

	ZEND_PARSE_PARAMETERS_START(5, 5)
		Z_PARAM_STRING(sec, sec_len)
		Z_PARAM_STRING(pub, pub_len)
		Z_PARAM_STRING(idU, idU_len)
		Z_PARAM_STRING(idS, idS_len)
      Z_PARAM_ARRAY_HT(cfg_array)
	Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    if(sec_len<=OPAQUE_REGISTER_USER_SEC_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid sec param.");
      return;
    }
    if(pub_len!=OPAQUE_REGISTER_PUBLIC_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid pub param.");
      return;
    }

    Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};
    Opaque_PkgConfig cfg;
    if(0!=get_cfg(&cfg, cfg_array)) {
      php_error_docref(NULL, E_WARNING, "invalid cfg array.");
      return;
    }

    const uint32_t envU_len = opaque_envelope_len(&cfg, &ids);
    uint8_t rec[OPAQUE_USER_RECORD_LEN+envU_len];
    uint8_t export_key[crypto_hash_sha256_BYTES];
    if(0!=opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,rec, sizeof(rec));
    add_next_index_stringl(&zarr,export_key, sizeof(export_key));       // sensitive

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_store_user_record) {
  char *sec;
  size_t sec_len;
  char *rec;
  size_t rec_len;
  zend_string *retval;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(sec, sec_len)
		Z_PARAM_STRING(rec, rec_len)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid sec param.");
      return;
    }
    if(rec_len<=OPAQUE_USER_RECORD_LEN) {
      php_error_docref(NULL, E_WARNING, "invalid rec param.");
      return;
    }

    opaque_StoreUserRecord(sec, rec);

    retval = zend_string_init(rec, rec_len, 0);
    RETURN_STR(retval);
}

PHP_FUNCTION(opaque_store_1k_user_record) {
  char *sec;
  size_t sec_len;
  char *skS;
  size_t skS_len;
  char *rec;
  size_t rec_len;
  zend_string *retval;

  ZEND_PARSE_PARAMETERS_START(3, 3)
    Z_PARAM_STRING(sec, sec_len)
    Z_PARAM_STRING(skS, skS_len)
    Z_PARAM_STRING(rec, rec_len)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid sec param.");
    return;
  }
  if(skS_len!=crypto_scalarmult_SCALARBYTES) {
    php_error_docref(NULL, E_WARNING, "invalid skS param.");
    return;
  }
  if(rec_len<=OPAQUE_USER_RECORD_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid rec param.");
    return;
  }

  opaque_Store1kUserRecord(sec, skS, rec);

  retval = zend_string_init(rec, rec_len, 0);
  RETURN_STR(retval);
}

PHP_FUNCTION(opaque_create_server_keys) {
  ZEND_PARSE_PARAMETERS_START(0, 0)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  char pkS[crypto_scalarmult_BYTES];
  char skS[crypto_scalarmult_SCALARBYTES];

  randombytes(skS, crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult_base(pkS, skS);

  zend_array *ret = zend_new_array(2);
  zval zarr;
  ZVAL_ARR(&zarr, ret);
  add_next_index_stringl(&zarr, pkS, sizeof(pkS));
  add_next_index_stringl(&zarr, skS, sizeof(skS));

  RETVAL_ARR(ret);
}

/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(opaque)
{
#if defined(ZTS) && defined(COMPILE_DL_OPAQUE)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(opaque)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "opaque support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ arginfo
 */
ZEND_BEGIN_ARG_INFO(arginfo_opaque_register, 0)
	ZEND_ARG_INFO(0, pwdU)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
	ZEND_ARG_INFO(0, cfg_array)
	ZEND_ARG_INFO(0, skS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_credential_request, 0)
	ZEND_ARG_INFO(0, pwdU)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_credential_response, 0)
	ZEND_ARG_INFO(0, pub)
	ZEND_ARG_INFO(0, rec)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
	ZEND_ARG_INFO(0, cfg_array)
	ZEND_ARG_INFO(0, infos_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_recover_credentials, 0)
	ZEND_ARG_INFO(0, resp)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, cfg_array)
	ZEND_ARG_INFO(0, infos_array)
	ZEND_ARG_INFO(0, pkS)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_user_auth, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, authU)
	ZEND_ARG_INFO(0, infos_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_request, 0)
	ZEND_ARG_INFO(0, pwdU)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_response, 0)
	ZEND_ARG_INFO(0, M)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_1k_registration_response, 0)
	ZEND_ARG_INFO(0, M)
	ZEND_ARG_INFO(0, pkS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_finalize_request, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, pub)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
	ZEND_ARG_INFO(0, cfg_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_store_user_record, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, rec)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_store_1k_user_record, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, skS)
	ZEND_ARG_INFO(0, rec)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_server_keys, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ opaque_functions[]
 */
static const zend_function_entry opaque_functions[] = {
	PHP_FE(opaque_register,							arginfo_opaque_register)
	PHP_FE(opaque_create_credential_request,		arginfo_opaque_create_credential_request)
	PHP_FE(opaque_create_credential_response,		arginfo_opaque_create_credential_response)
	PHP_FE(opaque_recover_credentials,				arginfo_opaque_recover_credentials)
	PHP_FE(opaque_user_auth,						arginfo_opaque_user_auth)
	PHP_FE(opaque_create_registration_request,		arginfo_opaque_create_registration_request)
	PHP_FE(opaque_create_registration_response,		arginfo_opaque_create_registration_response)
	PHP_FE(opaque_create_1k_registration_response,		arginfo_opaque_create_1k_registration_response)
	PHP_FE(opaque_finalize_request,					arginfo_opaque_finalize_request)
	PHP_FE(opaque_store_user_record,				arginfo_opaque_store_user_record)
	PHP_FE(opaque_store_1k_user_record,				arginfo_opaque_store_1k_user_record)
	PHP_FE(opaque_create_server_keys,				arginfo_opaque_create_server_keys)
	PHP_FE_END
};
/* }}} */

PHP_MINIT_FUNCTION(opaque)
{
#if defined(ZTS) && defined(COMPILE_DL_TEST)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    REGISTER_LONG_CONSTANT("opaque_NotPackaged", NotPackaged, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("opaque_InSecEnv", InSecEnv, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("opaque_InClrEnv", InClrEnv, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

/* {{{ opaque_module_entry
 */
zend_module_entry opaque_module_entry = {
	STANDARD_MODULE_HEADER,
	"opaque",					/* Extension name */
	opaque_functions,			/* zend_function_entry */
	PHP_MINIT(opaque),			/* PHP_MINIT - Module initialization */
	NULL,						/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(opaque),			/* PHP_RINIT - Request initialization */
	NULL,						/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(opaque),			/* PHP_MINFO - Module info */
	PHP_OPAQUE_VERSION,		  	/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_OPAQUE
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(opaque)
#endif
