/* opaque extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_opaque.h"
#include "opaque.h"

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
        php_error_docref(NULL, E_WARNING, "invalid value for cfg setting.");
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

/* {{{ string opaque_register( [ string $var ] )
 */
PHP_FUNCTION(opaque_register) {

  // register user

  char *pw;
  size_t pwlen;
  char *idU;
  size_t idUlen;
  char *idS;
  size_t idSlen;

  char *key=NULL;
  size_t keylen=0;
  char *sk=NULL;
  size_t sklen=0;

  zend_array *cfg_array;

	ZEND_PARSE_PARAMETERS_START(4, 6)
		Z_PARAM_STRING(pw, pwlen)
		Z_PARAM_STRING(idU, idUlen)
		Z_PARAM_STRING(idS, idSlen)
        Z_PARAM_ARRAY_HT(cfg_array)
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING(key, keylen)
		Z_PARAM_STRING(sk, sklen)
	ZEND_PARSE_PARAMETERS_END();

    Opaque_Ids ids={.idU_len=idUlen,.idU=idU,.idS_len=idSlen,.idS=idS};
    Opaque_PkgConfig cfg={
                          .skU = InSecEnv,
                          .pkU = InSecEnv,
                          .pkS = InSecEnv,
                          .idS = InSecEnv,
                          .idU = InSecEnv,
    };

    int r;
    if((r=get_cfgval(cfg_array, 0))==-1) return;
    cfg.skU=r;
    if((r=get_cfgval(cfg_array, 1))==-1) return;
    cfg.pkU=r;
    if((r=get_cfgval(cfg_array, 2))==-1) return;
    cfg.pkS=r;
    if((r=get_cfgval(cfg_array, 3))==-1) return;
    cfg.idS=r;
    if((r=get_cfgval(cfg_array, 4))==-1) return;
    cfg.idU=r;

    if(sk!=NULL && sklen!=32) {
      php_error_docref(NULL, E_WARNING, "invalid sk size, must be 32B.");
      return;
    }

    uint8_t export_key[crypto_hash_sha256_BYTES];
    const uint16_t ClrEnv_len = opaque_package_len(&cfg, &ids, InClrEnv);
    const uint16_t SecEnv_len = opaque_package_len(&cfg, &ids, InSecEnv);
    const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
    unsigned char rec[OPAQUE_USER_RECORD_LEN+env_len];

    if(0!=opaque_Register(pw, pwlen, key, keylen, sk, &cfg, &ids, rec, export_key)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,rec, sizeof(rec));
    add_next_index_stringl(&zarr,export_key, sizeof(export_key));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_credential_request) {
  // create credential request
  char *pw;
  size_t pwlen;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(pw, pwlen)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN+pwlen], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];

    if(0!=opaque_CreateCredentialRequest(pw, pwlen, sec, pub)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sec, sizeof(sec));
    add_next_index_stringl(&zarr,pub, sizeof(pub));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_credential_response) {
  // create credential request
  char *pub;
  size_t publen;
  char *rec;
  size_t reclen;
  char *idU;
  size_t idUlen;
  char *idS;
  size_t idSlen;
  zend_array *cfg_array;
  zend_array *infos_array=NULL;

	ZEND_PARSE_PARAMETERS_START(5, 6)
		Z_PARAM_STRING(pub, publen)
		Z_PARAM_STRING(rec, reclen)
		Z_PARAM_STRING(idU, idUlen)
		Z_PARAM_STRING(idS, idSlen)
        Z_PARAM_ARRAY_HT(cfg_array)
		Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT(infos_array)
	ZEND_PARSE_PARAMETERS_END();

    Opaque_Ids ids={.idU_len=idUlen,.idU=idU,.idS_len=idSlen,.idS=idS};
    Opaque_PkgConfig cfg={
                          .skU = InSecEnv,
                          .pkU = InSecEnv,
                          .pkS = InSecEnv,
                          .idS = InSecEnv,
                          .idU = InSecEnv,
    };

    int r;
    if((r=get_cfgval(cfg_array, 0))==-1) return;
    cfg.skU=r;
    if((r=get_cfgval(cfg_array, 1))==-1) return;
    cfg.pkU=r;
    if((r=get_cfgval(cfg_array, 2))==-1) return;
    cfg.pkS=r;
    if((r=get_cfgval(cfg_array, 3))==-1) return;
    cfg.idS=r;
    if((r=get_cfgval(cfg_array, 4))==-1) return;
    cfg.idU=r;

    Opaque_App_Infos infos={0}, *infos_p=NULL;
    if(infos_array!=NULL) {
      zval *x;
      if((x=get_infostr(infos_array, 0))) {
        infos.info1 = Z_STRVAL(*x);
        infos.info1_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 1))) {
        infos.info2 = Z_STRVAL(*x);
        infos.info2_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 2))) {
        infos.einfo2 = Z_STRVAL(*x);
        infos.einfo2_len = Z_STRLEN(*x);
      }
    }

    const uint16_t ClrEnv_len = opaque_package_len(&cfg, &ids, InClrEnv);
    const uint16_t SecEnv_len = opaque_package_len(&cfg, &ids, InSecEnv);
    const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
    unsigned char resp[OPAQUE_SERVER_SESSION_LEN+env_len];
    uint8_t sk[32];
    uint8_t ctx[OPAQUE_SERVER_AUTH_CTX_LEN]={0};

    if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, infos_p, resp, sk, ctx)) return;

    zend_array *ret = zend_new_array(3);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,resp, sizeof(resp));
    add_next_index_stringl(&zarr,sk, sizeof(sk));
    add_next_index_stringl(&zarr,ctx, sizeof(ctx));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_recover_credentials) {
  // create credential request
  char *resp;
  size_t resplen;
  char *sec;
  size_t seclen;
  char *key=NULL;
  size_t keylen=0;
  zend_array *cfg_array;
  zend_array *infos_array=NULL;

	ZEND_PARSE_PARAMETERS_START(3, 5)
		Z_PARAM_STRING(resp, resplen)
		Z_PARAM_STRING(sec, seclen)
        Z_PARAM_ARRAY_HT(cfg_array)
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING(key, keylen)
        Z_PARAM_ARRAY_HT(infos_array)
	ZEND_PARSE_PARAMETERS_END();

    unsigned char idU[1024], idS[1024];
    Opaque_Ids ids={.idU_len=sizeof(idU),.idU=idU,.idS_len=sizeof(idS),.idS=idS};

    Opaque_PkgConfig cfg={
                          .skU = InSecEnv,
                          .pkU = InSecEnv,
                          .pkS = InSecEnv,
                          .idS = InSecEnv,
                          .idU = InSecEnv,
    };
    int r;
    if((r=get_cfgval(cfg_array, 0))==-1) return;
    cfg.skU=r;
    if((r=get_cfgval(cfg_array, 1))==-1) return;
    cfg.pkU=r;
    if((r=get_cfgval(cfg_array, 2))==-1) return;
    cfg.pkS=r;
    if((r=get_cfgval(cfg_array, 3))==-1) return;
    cfg.idS=r;
    if((r=get_cfgval(cfg_array, 4))==-1) return;
    cfg.idU=r;

    Opaque_App_Infos infos={0}, *infos_p=NULL;
    if(infos_array!=NULL) {
      zval *x;
      if((x=get_infostr(infos_array, 0))) {
        infos.info1 = Z_STRVAL(*x);
        infos.info1_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 1))) {
        infos.info2 = Z_STRVAL(*x);
        infos.info2_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 2))) {
        infos.einfo2 = Z_STRVAL(*x);
        infos.einfo2_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 3))) {
        infos.info3 = Z_STRVAL(*x);
        infos.info3_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 4))) {
        infos.einfo3 = Z_STRVAL(*x);
        infos.einfo3_len = Z_STRLEN(*x);
      }
    }

    uint8_t sk[32];
    uint8_t authU[crypto_auth_hmacsha256_BYTES];
    uint8_t export_key[crypto_hash_sha256_BYTES];

    if(0!=opaque_RecoverCredentials(resp, sec, key, keylen, &cfg, infos_p, &ids, sk, authU, export_key)) return;

    zend_array *ret = zend_new_array(5);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sk, sizeof(sk));
    add_next_index_stringl(&zarr,authU, sizeof(authU));
    add_next_index_stringl(&zarr,export_key, sizeof(export_key));
    add_next_index_stringl(&zarr,ids.idU, ids.idU_len);
    add_next_index_stringl(&zarr,ids.idS, ids.idS_len);

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_user_auth) {
  // create credential request
  char *ctx;
  size_t ctxlen;
  char *authU;
  size_t authUlen;
  zend_array *infos_array=NULL;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STRING(ctx, ctxlen)
		Z_PARAM_STRING(authU, authUlen)
		Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT(infos_array)
	ZEND_PARSE_PARAMETERS_END();

    Opaque_App_Infos infos={0}, *infos_p=NULL;
    if(infos_array!=NULL) {
      zval *x;
      //if((x=get_infostr(infos_array, 0))) {
      //  infos.info1 = Z_STRVAL(*x);
      //  infos.info1_len = Z_STRLEN(*x);
      //}
      //if((x=get_infostr(infos_array, 1))) {
      //  infos.info2 = Z_STRVAL(*x);
      //  infos.info2_len = Z_STRLEN(*x);
      //}
      //if((x=get_infostr(infos_array, 2))) {
      //  infos.einfo2 = Z_STRVAL(*x);
      //  infos.einfo2_len = Z_STRLEN(*x);
      //}
      if((x=get_infostr(infos_array, 3))) {
        infos.info3 = Z_STRVAL(*x);
        infos.info3_len = Z_STRLEN(*x);
      }
      if((x=get_infostr(infos_array, 4))) {
        infos.einfo3 = Z_STRVAL(*x);
        infos.einfo3_len = Z_STRLEN(*x);
      }
    }

    zval zbool;

    if(0!=opaque_UserAuth(ctx, authU, infos_p))
      RETURN_FALSE;
    RETURN_TRUE;
}

PHP_FUNCTION(opaque_create_registration_request) {
  // register user
  char *pw;
  size_t pwlen;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(pw, pwlen)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    uint8_t alpha[crypto_core_ristretto255_BYTES];
    uint8_t ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwlen];

    if(0!=opaque_CreateRegistrationRequest(pw, pwlen, ctx, alpha)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,alpha, sizeof(alpha));
    add_next_index_stringl(&zarr,ctx, sizeof(ctx));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_create_registration_response) {
  // register user
  char *alpha;
  size_t alphalen;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(alpha, alphalen)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    unsigned char rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
    printf("opaque_CreateRegistrationResponse\n");
    if(0!=opaque_CreateRegistrationResponse(alpha, rsec, rpub)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,rsec, sizeof(rsec));
    add_next_index_stringl(&zarr,rpub, sizeof(rpub));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_finalize_request) {
  // create credential request
  char *ctx;
  size_t ctxlen;
  char *rpub;
  size_t rpublen;
  char *idU;
  size_t idUlen;
  char *idS;
  size_t idSlen;
  zend_array *cfg_array;
  char *key=NULL;
  size_t keylen=0;

	ZEND_PARSE_PARAMETERS_START(5, 6)
		Z_PARAM_STRING(ctx, ctxlen)
		Z_PARAM_STRING(rpub, rpublen)
		Z_PARAM_STRING(idU, idUlen)
		Z_PARAM_STRING(idS, idSlen)
        Z_PARAM_ARRAY_HT(cfg_array)
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING(key, keylen)
	ZEND_PARSE_PARAMETERS_END();

    Opaque_Ids ids={.idU_len=idUlen,.idU=idU,.idS_len=idSlen,.idS=idS};
    Opaque_PkgConfig cfg={
                          .skU = InSecEnv,
                          .pkU = InSecEnv,
                          .pkS = InSecEnv,
                          .idS = InSecEnv,
                          .idU = InSecEnv,
    };

    int r;
    if((r=get_cfgval(cfg_array, 0))==-1) return;
    cfg.skU=r;
    if((r=get_cfgval(cfg_array, 1))==-1) return;
    cfg.pkU=r;
    if((r=get_cfgval(cfg_array, 2))==-1) return;
    cfg.pkS=r;
    if((r=get_cfgval(cfg_array, 3))==-1) return;
    cfg.idS=r;
    if((r=get_cfgval(cfg_array, 4))==-1) return;
    cfg.idU=r;

    const uint16_t ClrEnv_len = opaque_package_len(&cfg, &ids, InClrEnv);
    const uint16_t SecEnv_len = opaque_package_len(&cfg, &ids, InSecEnv);
    const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

    unsigned char rrec[OPAQUE_USER_RECORD_LEN+env_len];
    uint8_t export_key[crypto_hash_sha256_BYTES];
    if(0!=opaque_FinalizeRequest(ctx, rpub, key, keylen, &cfg, &ids, rrec, export_key)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,rrec, sizeof(rrec));
    add_next_index_stringl(&zarr,export_key, sizeof(export_key));

    RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_store_user_record) {
  // register user
  char *rsec;
  size_t rseclen;
  char *rec;
  size_t reclen;
  zend_string *retval;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(rsec, rseclen)
		Z_PARAM_STRING(rec, reclen)
		Z_PARAM_OPTIONAL
	ZEND_PARSE_PARAMETERS_END();

    opaque_StoreUserRecord(rsec, rec);

    retval = zend_string_init(rec, reclen, 0);
    RETURN_STR(retval);
}

/* }}}*/

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
	ZEND_ARG_INFO(0, pw)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
	ZEND_ARG_INFO(0, cfg_array)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, sk)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_credential_request, 0)
	ZEND_ARG_INFO(0, pw)
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
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, infos_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_user_auth, 0)
	ZEND_ARG_INFO(0, ctx)
	ZEND_ARG_INFO(0, authU)
	ZEND_ARG_INFO(0, infos_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_request, 0)
	ZEND_ARG_INFO(0, pw)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_response, 0)
	ZEND_ARG_INFO(0, alpha)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_finalize_request, 0)
	ZEND_ARG_INFO(0, ctx)
	ZEND_ARG_INFO(0, rpub)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
	ZEND_ARG_INFO(0, cfg_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_store_user_record, 0)
	ZEND_ARG_INFO(0, rsec)
	ZEND_ARG_INFO(0, rrec)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ opaque_functions[]
 */
static const zend_function_entry opaque_functions[] = {
	PHP_FE(opaque_register,		arginfo_opaque_register)
	PHP_FE(opaque_create_credential_request,		arginfo_opaque_create_credential_request)
	PHP_FE(opaque_create_credential_response,		arginfo_opaque_create_credential_response)
	PHP_FE(opaque_recover_credentials,				arginfo_opaque_recover_credentials)
	PHP_FE(opaque_user_auth,						arginfo_opaque_user_auth)
	PHP_FE(opaque_create_registration_request,		arginfo_opaque_create_registration_request)
	PHP_FE(opaque_create_registration_response,		arginfo_opaque_create_registration_response)
	PHP_FE(opaque_finalize_request,					arginfo_opaque_finalize_request)
	PHP_FE(opaque_store_user_record,				arginfo_opaque_store_user_record)
	PHP_FE_END
};
/* }}} */

PHP_MINIT_FUNCTION(opaque)
{
#if defined(ZTS) && defined(COMPILE_DL_TEST)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    REGISTER_LONG_CONSTANT("NotPackaged", NotPackaged, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("InSecEnv", InSecEnv, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("InClrEnv", InClrEnv, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("skU", 0, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("pkU", 1, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("pkS", 2, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("idU", 3, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("idS", 4, CONST_CS | CONST_PERSISTENT);

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
