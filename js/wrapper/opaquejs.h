#ifndef OPAQUEJS_H
#define OPAQUEJS_H

#include <opaque.h>
#include <common.h>

int opaquejs_crypto_auth_hmacsha256_BYTES();

int opaquejs_crypto_core_ristretto255_BYTES();

int opaquejs_crypto_hash_sha256_BYTES();

int opaquejs_crypto_scalarmult_BYTES();

int opaquejs_crypto_scalarmult_SCALARBYTES();

int opaquejs_crypto_secretbox_KEYBYTES();

int opaquejs_OPAQUE_USER_RECORD_LEN();

int opaquejs_OPAQUE_USER_SESSION_PUBLIC_LEN();

int opaquejs_OPAQUE_USER_SESSION_SECRET_LEN();

int opaquejs_OPAQUE_SERVER_SESSION_LEN();

int opaquejs_OPAQUE_REGISTER_USER_SEC_LEN();

int opaquejs_OPAQUE_REGISTER_PUBLIC_LEN();

int opaquejs_OPAQUE_REGISTER_SECRET_LEN();

int opaquejs_OPAQUE_SERVER_AUTH_CTX_LEN();

int opaquejs_GenServerKeyPair(
  uint8_t pkS[crypto_scalarmult_BYTES],
  uint8_t skS[crypto_scalarmult_SCALARBYTES]);

int opaquejs_Register(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  uint8_t export_key[crypto_hash_sha256_BYTES]);

int opaquejs_CreateCredentialRequest(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
  uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);

int opaquejs_CreateCredentialResponse(
  const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
  const uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  const uint8_t *app_info1
  const size_t app_info_len,
  const uint8_t *app_einfo,
  const size_t app_einfo_len,
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN /*+envU_len*/],
  uint8_t sk[crypto_secretbox_KEYBYTES],
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);

int opaquejs_RecoverCredentials(
  const uint8_t resp[OPAQUE_SERVER_SESSION_LEN /*+envU_len*/],
  const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN /*+pwdU_len*/],
  const uint8_t pkS[crypto_scalarmult_BYTES],
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  const uint8_t *app_info,
  const size_t app_info_len,
  const uint8_t *app_einfo,
  const size_t app_einfo_len,
  uint8_t **ids_idU,
  uint16_t *ids_idU_len,
  uint8_t **ids_idS,
  uint16_t *ids_idS_len,
  uint8_t *sk,
  uint8_t authU[crypto_auth_hmacsha256_BYTES],
  uint8_t export_key[crypto_hash_sha256_BYTES]);

int opaquejs_UserAuth(
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN],
  const uint8_t authU[crypto_auth_hmacsha256_BYTES]);

int opaquejs_CreateRegistrationRequest(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
  uint8_t M[crypto_core_ristretto255_BYTES]);

int opaquejs_CreateRegistrationResponse(
  const uint8_t M[crypto_core_ristretto255_BYTES],
  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

int opaquejs_Create1kRegistrationResponse(
  const uint8_t M[crypto_core_ristretto255_BYTES],
  const uint8_t pkS[crypto_scalarmult_BYTES],
  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

int opaquejs_FinalizeRequest(
  const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN /*+pwdU_len*/],
  const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  uint8_t export_key[crypto_hash_sha256_BYTES]);

void opaquejs_StoreUserRecord(
  const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/]);

void opaquejs_Store1kUserRecord(
  const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/]);

int opaquejs_envelope_len(
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint32_t *envU_len);

void opaquejs_server_public_key_from_user_record(
  const uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  uint8_t pkS[crypto_scalarmult_BYTES]);

#endif // OPAQUEJS_H
