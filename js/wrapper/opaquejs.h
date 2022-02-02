#ifndef OPAQUEJS_H
#define OPAQUEJS_H

#include <opaque.h>
#include <common.h>

int opaquejs_crypto_auth_hmacsha512_BYTES();

int opaquejs_crypto_core_ristretto255_BYTES();

int opaquejs_crypto_hash_sha512_BYTES();

int opaquejs_crypto_scalarmult_BYTES();

int opaquejs_crypto_scalarmult_SCALARBYTES();

int opaquejs_OPAQUE_USER_RECORD_LEN();

int opaquejs_OPAQUE_USER_SESSION_PUBLIC_LEN();

int opaquejs_OPAQUE_USER_SESSION_SECRET_LEN();

int opaquejs_OPAQUE_SERVER_SESSION_LEN();

int opaquejs_OPAQUE_REGISTER_USER_SEC_LEN();

int opaquejs_OPAQUE_REGISTER_PUBLIC_LEN();

int opaquejs_OPAQUE_REGISTER_SECRET_LEN();

int opaquejs_OPAQUE_SHARED_SECRETBYTES();

int opaquejs_OPAQUE_REGISTRATION_RECORD_LEN();

int opaquejs_GenServerKeyPair(
  uint8_t pkS[crypto_scalarmult_BYTES],
  uint8_t skS[crypto_scalarmult_SCALARBYTES]);

int opaquejs_Register(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint8_t rec[OPAQUE_USER_RECORD_LEN],
  uint8_t export_key[crypto_hash_sha512_BYTES]);

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
  const uint8_t *ctx,
  const uint16_t ctx_len,
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
  uint8_t sec[crypto_auth_hmacsha512_BYTES]);

int opaquejs_RecoverCredentials(
  const uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
  const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
  const uint8_t *ctx,
  const uint16_t ctx_len,
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
  uint8_t authU[crypto_auth_hmacsha512_BYTES],
  uint8_t export_key[crypto_hash_sha512_BYTES]);

int opaquejs_UserAuth(
  uint8_t sec[crypto_auth_hmacsha512_BYTES],
  const uint8_t authU[crypto_auth_hmacsha512_BYTES]);

int opaquejs_CreateRegistrationRequest(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
  uint8_t M[crypto_core_ristretto255_BYTES]);

int opaquejs_CreateRegistrationResponse(
  const uint8_t M[crypto_core_ristretto255_BYTES],
  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

int opaquejs_FinalizeRequest(
  const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN /*+pwdU_len*/],
  const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN],
  uint8_t export_key[crypto_hash_sha512_BYTES]);

void opaquejs_StoreUserRecord(
  const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  const uint8_t recU[OPAQUE_REGISTRATION_RECORD_LEN],
  uint8_t rec[OPAQUE_USER_RECORD_LEN]);

#endif // OPAQUEJS_H
