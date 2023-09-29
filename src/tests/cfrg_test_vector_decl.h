#ifndef cfrg_test_vector_decl_h
#define cfrg_test_vector_decl_h

#include <stdint.h>

#define ke1_len 96
extern const uint8_t ke1[ke1_len];

#define ke2_len 320
extern const uint8_t ke2[ke2_len];

#define ke3_len 64
extern const uint8_t ke3[ke3_len];

#define export_key_len 64
extern const uint8_t export_key[export_key_len];

#define registration_request_len 32
extern const uint8_t registration_request[registration_request_len];

#define registration_response_len 64
extern const uint8_t registration_response[registration_response_len];

#define registration_upload_len 192
extern const uint8_t registration_upload[registration_upload_len];

#define session_key_len 64
extern const uint8_t session_key[session_key_len];

#define auth_key_len 64
extern const uint8_t auth_key[auth_key_len];

#define client_mac_key_len 64
extern const uint8_t client_mac_key[client_mac_key_len];

#define client_public_key_len 32
extern const uint8_t client_public_key[client_public_key_len];

#define envelope_len 96
extern const uint8_t envelope[envelope_len];

#define handshake_secret_len 64
extern const uint8_t handshake_secret[handshake_secret_len];

#define masking_key_len 64
extern const uint8_t masking_key[masking_key_len];

#define oprf_key_len 32
extern const uint8_t oprf_key[oprf_key_len];

#define randomized_pwd_len 64
extern const uint8_t randomized_pwd[randomized_pwd_len];

#define server_mac_key_len 64
extern const uint8_t server_mac_key[server_mac_key_len];

#define blind_login_len 32
extern const uint8_t blind_login[blind_login_len];

#define blind_registration_len 32
extern const uint8_t blind_registration[blind_registration_len];

#define client_keyshare_len 32
extern const uint8_t client_keyshare[client_keyshare_len];

#define client_nonce_len 32
extern const uint8_t client_nonce[client_nonce_len];

#define client_keyshare_seed_len 32
extern const uint8_t client_keyshare_seed[client_keyshare_seed_len];

#define server_keyshare_seed_len 32
extern const uint8_t server_keyshare_seed[client_keyshare_seed_len];

#define credential_identifier_len 4
extern const uint8_t credential_identifier[credential_identifier_len];

#define envelope_nonce_len 32
extern const uint8_t envelope_nonce[envelope_nonce_len];

#define masking_nonce_len 32
extern const uint8_t masking_nonce[masking_nonce_len];

#define oprf_seed_len 64
extern const uint8_t oprf_seed[oprf_seed_len];

#define password_len 25
extern const uint8_t password[password_len];

#define server_keyshare_len 32
extern const uint8_t server_keyshare[server_keyshare_len];

#define server_nonce_len 32
extern const uint8_t server_nonce[server_nonce_len];

#define server_private_key_len 32
extern const uint8_t server_private_key[server_private_key_len];

#define server_private_keyshare_len 32
extern const uint8_t server_private_keyshare[server_private_keyshare_len];

#define server_public_key_len 32
extern const uint8_t server_public_key[server_public_key_len];

#endif
