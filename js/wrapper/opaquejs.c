#include <opaque.h>
#include <common.h>

// We copied Opaque_UserRecord's definition from opaque.c since it is not
// defined in opaque.h.
typedef struct {
  uint8_t kU[crypto_core_ristretto255_SCALARBYTES];
  uint8_t skS[crypto_scalarmult_SCALARBYTES];
  uint8_t pkU[crypto_scalarmult_BYTES];
  uint8_t pkS[crypto_scalarmult_BYTES];
  uint32_t envU_len;
  uint8_t envU[];
} __attribute ((packed)) Opaque_UserRecord;


void opaquejs_to_App_Infos(
  const uint8_t *app_info1,
  const size_t app_info1_len,
  const uint8_t *app_info2,
  const size_t app_info2_len,
  const uint8_t *app_einfo2,
  const size_t app_einfo2_len,
  const uint8_t *app_info3,
  const size_t app_info3_len,
  const uint8_t *app_einfo3,
  const size_t app_einfo3_len,
  Opaque_App_Infos **infos_ptr) {

  if (app_info1 || app_info2 || app_einfo2 || app_info3 || app_einfo3) {
    Opaque_App_Infos infos = {
      (uint8_t *)app_info1,  app_info1_len,
      (uint8_t *)app_info2,  app_info2_len,
      (uint8_t *)app_einfo2, app_einfo2_len,
      (uint8_t *)app_info3,  app_info3_len,
      (uint8_t *)app_einfo3, app_einfo3_len
    };
    *infos_ptr = &infos;
  }
}


int opaquejs_to_PkgTarget(
  const uint8_t i,
  Opaque_PkgTarget *target) {

  if (i == 0) {
    *target = NotPackaged;
    return 0;
  }
  if (i == 1) {
    *target = InSecEnv;
    return 0;
  }
  if (i == 2) {
    *target = InClrEnv;
    return 0;
  }
  return 1;
}


int opaquejs_to_PkgConfig(
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  Opaque_PkgConfig *cfg) {

  Opaque_PkgTarget skU;
  Opaque_PkgTarget pkU;
  Opaque_PkgTarget pkS;
  Opaque_PkgTarget idS;
  Opaque_PkgTarget idU;
  if (0 != opaquejs_to_PkgTarget(cfg_skU, &skU)) return 1;
  if (0 != opaquejs_to_PkgTarget(cfg_pkU, &pkU)) return 1;
  if (0 != opaquejs_to_PkgTarget(cfg_pkS, &pkS)) return 1;
  if (0 != opaquejs_to_PkgTarget(cfg_idS, &idS)) return 1;
  if (0 != opaquejs_to_PkgTarget(cfg_idU, &idU)) return 1;
  cfg->skU = skU;
  cfg->pkU = pkU;
  cfg->pkS = pkS;
  cfg->idS = idS;
  cfg->idU = idU;
  return 0;
}


int opaquejs_crypto_auth_hmacsha256_BYTES() {
  return crypto_auth_hmacsha256_BYTES;
}


int opaquejs_crypto_core_ristretto255_BYTES() {
  return crypto_core_ristretto255_BYTES;
}


int opaquejs_crypto_hash_sha256_BYTES() {
  return crypto_hash_sha256_BYTES;
}


int opaquejs_crypto_scalarmult_BYTES() {
  return crypto_scalarmult_BYTES;
}


int opaquejs_crypto_scalarmult_SCALARBYTES() {
  return crypto_scalarmult_SCALARBYTES;
}


int opaquejs_crypto_secretbox_KEYBYTES() {
  // This is 32 bytes. See the following:
  // - https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretbox.h
  // - https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h
  return crypto_secretbox_KEYBYTES;
}


int opaquejs_OPAQUE_USER_RECORD_LEN() {
  return OPAQUE_USER_RECORD_LEN;
}


int opaquejs_OPAQUE_REGISTER_PUBLIC_LEN() {
  return OPAQUE_REGISTER_PUBLIC_LEN;
}


int opaquejs_OPAQUE_REGISTER_SECRET_LEN() {
  return OPAQUE_REGISTER_SECRET_LEN;
}


int opaquejs_OPAQUE_SERVER_SESSION_LEN() {
  return OPAQUE_SERVER_SESSION_LEN;
}


int opaquejs_OPAQUE_REGISTER_USER_SEC_LEN() {
  return OPAQUE_REGISTER_USER_SEC_LEN;
}


int opaquejs_OPAQUE_USER_SESSION_PUBLIC_LEN() {
  return OPAQUE_USER_SESSION_PUBLIC_LEN;
}


int opaquejs_OPAQUE_USER_SESSION_SECRET_LEN() {
  return OPAQUE_USER_SESSION_SECRET_LEN;
}


int opaquejs_OPAQUE_SERVER_AUTH_CTX_LEN() {
  return OPAQUE_SERVER_AUTH_CTX_LEN;
}


int opaquejs_GenServerKeyPair(
  uint8_t pkS[crypto_scalarmult_BYTES],
  uint8_t skS[crypto_scalarmult_SCALARBYTES]) {

  randombytes(skS, crypto_scalarmult_SCALARBYTES);
  return crypto_scalarmult_base(pkS, skS);
}


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
  uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_PkgConfig cfg;
  if (0 != opaquejs_to_PkgConfig(cfg_skU, cfg_pkU, cfg_pkS, cfg_idS, cfg_idU, &cfg)) return 1;
  const Opaque_Ids ids = { ids_idU_len, (uint8_t *)ids_idU, ids_idS_len, (uint8_t *)ids_idS };
  return opaque_Register(pwdU, pwdU_len, skS, &cfg, &ids, rec, export_key);
}


int opaquejs_CreateCredentialRequest(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
  uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]) {

  return opaque_CreateCredentialRequest(pwdU, pwdU_len, sec, pub);
}


int opaquejs_CreateCredentialResponse(
  const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
  const uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  const uint8_t *ids_idU,
  const uint16_t ids_idU_len,
  const uint8_t *ids_idS,
  const uint16_t ids_idS_len,
  const uint8_t *app_info1,
  const size_t app_info1_len,
  const uint8_t *app_info2,
  const size_t app_info2_len,
  const uint8_t *app_einfo2,
  const size_t app_einfo2_len,
  const uint8_t *app_info3,
  const size_t app_info3_len,
  const uint8_t *app_einfo3,
  const size_t app_einfo3_len,
  uint8_t resp[OPAQUE_SERVER_SESSION_LEN /*+envU_len*/],
  uint8_t sk[crypto_secretbox_KEYBYTES],
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]) {

  const Opaque_Ids ids = { ids_idU_len, (uint8_t *)ids_idU, ids_idS_len, (uint8_t *)ids_idS };
  Opaque_App_Infos *infos_ptr = NULL;
  opaquejs_to_App_Infos(app_info1, app_info1_len,
                        app_info2, app_info2_len,
                        app_einfo2, app_einfo2_len,
                        app_info3, app_info3_len,
                        app_einfo3, app_einfo3_len,
                        &infos_ptr);
  return opaque_CreateCredentialResponse(pub, rec, &ids, infos_ptr, resp, sk, sec);
}


int opaquejs_RecoverCredentials(
  const uint8_t resp[OPAQUE_SERVER_SESSION_LEN /*+envU_len*/],
  const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN /*+pwdU_len*/],
  const uint8_t pkS[crypto_scalarmult_BYTES],
  const uint8_t cfg_skU,
  const uint8_t cfg_pkU,
  const uint8_t cfg_pkS,
  const uint8_t cfg_idS,
  const uint8_t cfg_idU,
  const uint8_t *app_info1,
  const size_t app_info1_len,
  const uint8_t *app_info2,
  const size_t app_info2_len,
  const uint8_t *app_einfo2,
  const size_t app_einfo2_len,
  const uint8_t *app_info3,
  const size_t app_info3_len,
  const uint8_t *app_einfo3,
  const size_t app_einfo3_len,
  uint8_t **ids_idU,
  uint16_t *ids_idU_len,
  uint8_t **ids_idS,
  uint16_t *ids_idS_len,
  uint8_t *sk,
  uint8_t authU[crypto_auth_hmacsha256_BYTES],
  uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_PkgConfig cfg;
  if (0 != opaquejs_to_PkgConfig(cfg_skU, cfg_pkU, cfg_pkS, cfg_idS, cfg_idU, &cfg)) return 1;
  Opaque_App_Infos *infos_ptr = NULL;
  opaquejs_to_App_Infos(app_info1, app_info1_len,
                        app_info2, app_info2_len,
                        app_einfo2, app_einfo2_len,
                        app_info3, app_info3_len,
                        app_einfo3, app_einfo3_len,
                        &infos_ptr);
  Opaque_Ids ids1 = { *ids_idU_len, *ids_idU, *ids_idS_len, *ids_idS };
  if (0 != opaque_RecoverCredentials(resp, sec, pkS, &cfg, infos_ptr,
                                     &ids1, sk, authU, export_key))
    return 1;
  *ids_idU = ids1.idU;
  *ids_idU_len = ids1.idU_len;
  *ids_idS = ids1.idS;
  *ids_idS_len = ids1.idS_len;
  return 0;
}


int opaquejs_UserAuth(
  uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN],
  const uint8_t authU[crypto_auth_hmacsha256_BYTES],
  const uint8_t *app_info3,
  const size_t app_info3_len,
  const uint8_t *app_einfo3,
  const size_t app_einfo3_len) {

  Opaque_App_Infos *infos_ptr = NULL;
  opaquejs_to_App_Infos(NULL, 0,
                        NULL, 0,
                        NULL, 0,
                        app_info3, app_info3_len,
                        app_einfo3, app_einfo3_len,
                        &infos_ptr);
  return opaque_UserAuth(sec, authU, infos_ptr);
}


int opaquejs_CreateRegistrationRequest(
  const uint8_t *pwdU,
  const uint16_t pwdU_len,
  uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
  uint8_t M[crypto_core_ristretto255_BYTES]) {

  return opaque_CreateRegistrationRequest(pwdU, pwdU_len, sec, M);
}


int opaquejs_CreateRegistrationResponse(
  const uint8_t M[crypto_core_ristretto255_BYTES],
  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]) {

  return opaque_CreateRegistrationResponse(M, sec, pub);
}


int opaquejs_Create1kRegistrationResponse(
  const uint8_t M[crypto_core_ristretto255_BYTES],
  const uint8_t pkS[crypto_scalarmult_BYTES],
  uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]) {

  return opaque_Create1kRegistrationResponse(M, pkS, sec, pub);
}


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
  uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_PkgConfig cfg;
  if (0 != opaquejs_to_PkgConfig(cfg_skU, cfg_pkU, cfg_pkS, cfg_idS, cfg_idU, &cfg)) return 1;
  const Opaque_Ids ids = { ids_idU_len, (uint8_t *)ids_idU, ids_idS_len, (uint8_t *)ids_idS };
  return opaque_FinalizeRequest(sec, pub, &cfg, &ids, rec, export_key);
}


void opaquejs_StoreUserRecord(
  const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/]) {

  opaque_StoreUserRecord(sec, rec);
}


void opaquejs_Store1kUserRecord(
  const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
  const uint8_t skS[crypto_scalarmult_SCALARBYTES],
  uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/]) {

  opaque_Store1kUserRecord(sec, skS, rec);
}


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
  uint32_t *envU_len) {

  Opaque_PkgConfig cfg;
  if (0 != opaquejs_to_PkgConfig(cfg_skU, cfg_pkU, cfg_pkS, cfg_idS, cfg_idU, &cfg)) return 1;
  const Opaque_Ids ids = { ids_idU_len, (uint8_t *)ids_idU, ids_idS_len, (uint8_t *)ids_idS };
  *envU_len = opaque_envelope_len(&cfg, &ids);
  return 0;
}


void opaquejs_server_public_key_from_user_record(
  const uint8_t rec[OPAQUE_USER_RECORD_LEN /*+envU_len*/],
  uint8_t pkS[crypto_scalarmult_BYTES]) {

  Opaque_UserRecord *_rec = (Opaque_UserRecord *)&rec;
  memcpy(pkS, _rec->pkS, crypto_scalarmult_BYTES);
}
