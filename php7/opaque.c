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

/* {{{ */

PHP_FUNCTION(opaque_register) {
  char *pwdU;
  size_t pwdU_len;
  char *idU=NULL;
  size_t idU_len=0;
  char *idS=NULL;
  size_t idS_len=0;

  char *skS=NULL;
  size_t skS_len=0;


  ZEND_PARSE_PARAMETERS_START(1, 4)
    Z_PARAM_STRING(pwdU, pwdU_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(idU, idU_len)
    Z_PARAM_STRING(idS, idS_len)
    Z_PARAM_STRING(skS, skS_len)
  ZEND_PARSE_PARAMETERS_END();

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  if(skS!=NULL && skS_len!=crypto_scalarmult_SCALARBYTES) {
    php_error_docref(NULL, E_WARNING, "invalid skS size, must be 32B.");
    return;
  }

  uint8_t export_key[crypto_hash_sha512_BYTES];
  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  if(0!=opaque_Register(pwdU, pwdU_len, skS, &ids, rec, export_key)) return;

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

  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
          pub[OPAQUE_USER_SESSION_PUBLIC_LEN];

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
  char *context;
  size_t context_len;

  ZEND_PARSE_PARAMETERS_START(3, 5)
    Z_PARAM_STRING(pub, pub_len)
    Z_PARAM_STRING(rec, rec_len)
    Z_PARAM_STRING(context, context_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(idU, idU_len)
    Z_PARAM_STRING(idS, idS_len)
  ZEND_PARSE_PARAMETERS_END();

  if(pub_len!=OPAQUE_USER_SESSION_PUBLIC_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid pub param.");
    return;
  }

  if(rec_len!=OPAQUE_USER_RECORD_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid rec param.");
    return;
  }

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};

  uint8_t resp[OPAQUE_SERVER_SESSION_LEN];
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t sec[crypto_auth_hmacsha512_BYTES]={0};

  if(0!=opaque_CreateCredentialResponse(pub, rec, &ids, context, context_len, resp, sk, sec)) return;

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
  char *idU=NULL;
  size_t idU_len=0;
  char *idS=NULL;
  size_t idS_len=0;
  char *context=NULL;
  size_t context_len=0;

  ZEND_PARSE_PARAMETERS_START(3, 5)
    Z_PARAM_STRING(resp, resp_len)
    Z_PARAM_STRING(sec, sec_len)
    Z_PARAM_STRING(context, context_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(idU, idU_len)
    Z_PARAM_STRING(idS, idS_len)
  ZEND_PARSE_PARAMETERS_END();

  if(resp_len!=OPAQUE_SERVER_SESSION_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid resp param.");
    return;
  }

  if(sec_len<=OPAQUE_USER_SESSION_SECRET_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid sec param.");
    return;
  }

  Opaque_Ids ids={.idU_len=idU_len,.idU=idU,.idS_len=idS_len,.idS=idS};


  uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
  uint8_t authU[crypto_auth_hmacsha512_BYTES];
  uint8_t export_key[crypto_hash_sha512_BYTES];

  if(0!=opaque_RecoverCredentials(resp, sec, context, context_len, &ids, sk, authU, export_key)) return;

  zend_array *ret = zend_new_array(3);
  zval zarr;
  ZVAL_ARR(&zarr, ret);
  add_next_index_stringl(&zarr,sk, sizeof(sk));                   // sensitive
  add_next_index_stringl(&zarr,authU, sizeof(authU));             // sensitive
  add_next_index_stringl(&zarr,export_key, sizeof(export_key));   // sensitive

  RETVAL_ARR(ret);
}

PHP_FUNCTION(opaque_user_auth) {
  char *authU0;
  size_t authU0_len;
  char *authU;
  size_t authU_len;

  ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(authU0, authU0_len)
    Z_PARAM_STRING(authU, authU_len)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  if(authU0_len!=crypto_auth_hmacsha512_BYTES) {
    php_error_docref(NULL, E_WARNING, "invalid authU0 param.");
    return;
  }
  if(authU_len!=crypto_auth_hmacsha512_BYTES) {
    php_error_docref(NULL, E_WARNING, "invalid authU param.");
    return;
  }

  zval zbool;

  if(0!=opaque_UserAuth(authU0, authU))
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
  char *skS=NULL;
  size_t skS_len=0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(M, M_len)
   Z_PARAM_OPTIONAL
      Z_PARAM_STRING(skS, skS_len)
	ZEND_PARSE_PARAMETERS_END();

    if(M_len!=crypto_core_ristretto255_BYTES) {
      php_error_docref(NULL, E_WARNING, "invalid M param.");
      return;
    }

    if(skS != NULL && skS_len!=crypto_scalarmult_BYTES) {
      php_error_docref(NULL, E_WARNING, "invalid skS param.");
      return;
    }

    uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], pub[OPAQUE_REGISTER_PUBLIC_LEN];

    if(0!=opaque_CreateRegistrationResponse(M, skS, sec, pub)) return;

    zend_array *ret = zend_new_array(2);
    zval zarr;
    ZVAL_ARR(&zarr, ret);
    add_next_index_stringl(&zarr,sec, sizeof(sec));       // sensitive
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

  ZEND_PARSE_PARAMETERS_START(4, 4)
    Z_PARAM_STRING(sec, sec_len)
    Z_PARAM_STRING(pub, pub_len)
    Z_PARAM_STRING(idU, idU_len)
    Z_PARAM_STRING(idS, idS_len)
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

  uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN];
  uint8_t export_key[crypto_hash_sha512_BYTES];
  if(0!=opaque_FinalizeRequest(sec, pub, &ids, rec, export_key)) return;

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
  char *recU;
  size_t recU_len;
  zend_string *retval;

  ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(sec, sec_len)
    Z_PARAM_STRING(recU, recU_len)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  if(sec_len!=OPAQUE_REGISTER_SECRET_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid sec param.");
    return;
  }
  if(recU_len!=OPAQUE_REGISTRATION_RECORD_LEN) {
    php_error_docref(NULL, E_WARNING, "invalid rec param.");
    return;
  }

  uint8_t rec[OPAQUE_USER_RECORD_LEN];

  opaque_StoreUserRecord(sec, recU, rec);

  retval = zend_string_init(rec, sizeof rec, 0);
  RETURN_STR(retval);
}

PHP_FUNCTION(opaque_create_server_keys) {
  ZEND_PARSE_PARAMETERS_START(0, 0)
    Z_PARAM_OPTIONAL
  ZEND_PARSE_PARAMETERS_END();

  char pkS[crypto_scalarmult_BYTES];
  char skS[crypto_scalarmult_SCALARBYTES];

  randombytes(skS, crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult_ristretto255_base(pkS, skS);

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
	ZEND_ARG_INFO(0, skS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_credential_request, 0)
	ZEND_ARG_INFO(0, pwdU)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_credential_response, 0)
	ZEND_ARG_INFO(0, pub)
	ZEND_ARG_INFO(0, rec)
	ZEND_ARG_INFO(0, context)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_recover_credentials, 0)
	ZEND_ARG_INFO(0, resp)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, context)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_user_auth, 0)
	ZEND_ARG_INFO(0, authU0)
	ZEND_ARG_INFO(0, authU)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_request, 0)
	ZEND_ARG_INFO(0, pwdU)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_create_registration_response, 0)
	ZEND_ARG_INFO(0, M)
	ZEND_ARG_INFO(0, skS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_finalize_request, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, pub)
	ZEND_ARG_INFO(0, idU)
	ZEND_ARG_INFO(0, idS)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_opaque_store_user_record, 0)
	ZEND_ARG_INFO(0, sec)
	ZEND_ARG_INFO(0, recU)
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
	PHP_FE(opaque_finalize_request,					arginfo_opaque_finalize_request)
	PHP_FE(opaque_store_user_record,				arginfo_opaque_store_user_record)
	PHP_FE(opaque_create_server_keys,				arginfo_opaque_create_server_keys)
	PHP_FE_END
};
/* }}} */

PHP_MINIT_FUNCTION(opaque)
{
#if defined(ZTS) && defined(COMPILE_DL_TEST)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
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
