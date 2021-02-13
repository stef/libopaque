/**
 *  @file opaque.h
 */

#ifndef opaque_h
#define opaque_h

#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

/**
 * sk is a shared secret. In opaque.h, we do not report its byte size in functions
 * like opaque_CreateCredentialResponse. We centralize its size here so that if
 * the algorithm to calculate sk changes, we can just change it in one place.
 */
#define OPAQUE_SHARED_SECRETBYTES 32
#define OPAQUE_HANDSHAKE_SECRETBYTES 32
#define OPAQUE_NONCE_BYTES 32
#define OPAQUE_ENVELOPE_NONCEBYTES 32

#define OPAQUE_ENVELOPE_META_LEN (                     \
  /* envU nonce */ OPAQUE_ENVELOPE_NONCEBYTES+         \
  /* SecEnv_len */ sizeof(uint16_t)+                   \
  /* ClrEnv_len */ sizeof(uint16_t)+                   \
  /* auth tag */ crypto_hash_sha256_BYTES)

#define OPAQUE_USER_RECORD_LEN (                       \
   /* kU */ crypto_core_ristretto255_SCALARBYTES+      \
   /* skS */ crypto_scalarmult_SCALARBYTES+            \
   /* pkU */ crypto_scalarmult_BYTES+                  \
   /* pkS */ crypto_scalarmult_BYTES+                  \
   /* envU_len */ sizeof(uint32_t))

#define OPAQUE_USER_SESSION_PUBLIC_LEN (               \
   /* M */ crypto_core_ristretto255_BYTES+             \
   /* X_u */ crypto_scalarmult_BYTES+                  \
   /* nonceU */ OPAQUE_NONCE_BYTES)

#define OPAQUE_USER_SESSION_SECRET_LEN (               \
   /* r */ crypto_core_ristretto255_SCALARBYTES+       \
   /* x_u */ crypto_scalarmult_SCALARBYTES+            \
   /* nonceU */ OPAQUE_NONCE_BYTES+                    \
   /* M */  crypto_core_ristretto255_BYTES+            \
   /* pwdU_len */ sizeof(uint16_t))

#define OPAQUE_SERVER_SESSION_LEN (                    \
   /* Z */ crypto_core_ristretto255_BYTES+             \
   /* X_s */ crypto_scalarmult_BYTES+                  \
   /* nonceS */ OPAQUE_NONCE_BYTES+                    \
   /* auth */ crypto_auth_hmacsha256_BYTES+            \
   /* envU_len */ sizeof(uint32_t))

#define OPAQUE_REGISTER_USER_SEC_LEN (                 \
   /* r */ crypto_core_ristretto255_SCALARBYTES+       \
   /* pwdU_len */ sizeof(uint16_t))

#define OPAQUE_REGISTER_PUBLIC_LEN (                   \
   /* Z */ crypto_core_ristretto255_BYTES+             \
   /* pkS */ crypto_scalarmult_BYTES)

#define OPAQUE_REGISTER_SECRET_LEN (                   \
   /* skS */ crypto_scalarmult_SCALARBYTES+            \
   /* kU */ crypto_core_ristretto255_SCALARBYTES)

#define OPAQUE_SERVER_AUTH_CTX_LEN (                   \
   /* km3 */ crypto_auth_hmacsha256_KEYBYTES+          \
   /* xcript_state */ sizeof(crypto_hash_sha256_state))

typedef enum {
   Base = 1,
   CustomID = 2
} __attribute((packed)) Opaque_IETF_EnvelopeMode;

#define OPAQUE_ENVELOPE_BASE_MODE_LEN (               \
   /* mode */sizeof(Opaque_IETF_EnvelopeMode)+        \
   /* nonce */ OPAQUE_NONCE_BYTES+                    \
   /* skU_len */ sizeof(uint16_t)+                    \
   /* skU */ crypto_scalarmult_SCALARBYTES+           \
   /* pkS_len */ sizeof(uint16_t)+                    \
   /* pkS */ crypto_scalarmult_BYTES)


#define OPAQUE_ENVELOPE_CUSTOMID_MODE_LEN (           \
   OPAQUE_ENVELOPE_BASE_MODE_LEN +                    \
  /* idU_len */ sizeof(uint16_t) +                    \
  /* idS_len */ sizeof(uint16_t))

/**
   struct to store the IDs of the user/server.
 */
typedef struct {
  uint16_t idU_len;    /**< length of idU, most useful if idU is binary */
  uint8_t *idU;        /**< pointer to the id of the user/client in the opaque protocol */
  uint16_t idS_len;    /**< length of idS, needed for binary ids */
  uint8_t *idS;        /**< pointer to the id of the server in the opaque protocol */
} Opaque_Ids;

/**
   struct to store various extra protocol information.

   This is defined by the RFC to be used to bind extra
   session-specific parameters to the current session.
*/
typedef struct {
  uint8_t *info;
  size_t info_len;
  uint8_t *einfo;
  size_t einfo_len;
} Opaque_App_Infos;

/**
 * enum to define the handling of various fields packed in the opaque envelope
 */
typedef enum {
  NotPackaged = 0,
  InSecEnv = 1,     /**< field is encrypted */
  InClrEnv = 2      /**< field is plaintext, but authenticated */
} __attribute((packed)) Opaque_PkgTarget;

/**
 * configuration of the opaque envelope fields
 */
typedef struct {
  Opaque_PkgTarget skU : 2;  /**< users secret key - must not be
                                InClrEnv, if it is NotPackaged then
                                rwdU is used to seed a keygen() via
                                hkdf-expand() */
  Opaque_PkgTarget pkU : 2;  /**< users public key - if not included
                                it can be derived from the private
                                key */
  Opaque_PkgTarget pkS : 2;  /**< servers public key - currently this
                                is not allowed to set to NotPackaged -
                                TODO if set to NotPackaged allow to
                                specify the pubkey explicitly as a
                                param to the functions that require
                                this info */
  Opaque_PkgTarget idU : 2;  /**< id of the user - the RFC specifies
                                this to be possible to pack into the
                                envelope */
  Opaque_PkgTarget idS : 2;  /**< id of the server - the RFC specifies
                                this to be possible to pack into the
                                envelope */
} __attribute((packed)) Opaque_PkgConfig;

extern const Opaque_PkgConfig IETF_BaseCfg;
extern const Opaque_PkgConfig IETF_CustomIDCfg;

/**
   This function implements the storePwdFile function from the paper
   it is not specified by the RFC. This function runs on the server
   and creates a new output record rec of secret key material. The
   server needs to implement the storage of this record and any
   binding to user names or as the paper suggests sid.

   @param [in] pwdU - the users password
   @param [in] pwdU_len - length of the users password
   @param [in] skS - in case of global server keys this is the servers
        private key, should be set to NULL if per/user keys are to be
        generated
   @param [in] cfg - configuration of the opaque envelope, see
        Opaque_PkgConfig
   @param [in] ids - the ids of the user and server, see Opaque_Ids
   @param [out] rec - the opaque record the server needs to
        store. this is a pointer to memory allocated by the caller,
        and must be large enough to hold the record and take into
        account the variable length of idU and idS in case these are
        included in the envelope.
   @param [out] export_key - optional pointer to pre-allocated (and
        protected) memory for an extra_key that can be used to
        encrypt/authenticate additional data.
   @return the function returns 0 if everything is correct
 */
int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len, const uint8_t skS[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   This function initiates a new OPAQUE session, is the same as the
   function defined in the paper with the name usrSession.

   @param [in] pwdU - users input password
   @param [in] pwdU_len - length of the users password
   @param [out] sec - private context, it is essential that the memory
        allocate for this buffer be **OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len**.
        The User should protect the sec value (e.g. with sodium_mlock())
        until opaque_RecoverCredentials.
   @param [out] pub - the message to be sent to the server
   @return the function returns 0 if everything is correct
 */
int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);

/**
   This is the same function as defined in the paper with name
   srvSession name. This function runs on the server and
   receives the output pub from the user running opaque_CreateCredentialRequest(),
   furthermore the server needs to load the user record created when
   registering the user with opaque_Register() or
   opaque_StoreUserRecord(). These input parameters are
   transformed into a secret/shared session key sk and a response resp
   to be sent back to the user.
   @param [in] pub - the pub output of the opaque_CreateCredentialRequest()
   @param [in] rec - the recorded created during "registration" and stored by the server
   @param [in] ids - the id if the client and server
   @param [in] infos - various extra (unspecified) protocol information as recommended by the rfc.
   @param [out] resp - servers response to be sent to the client where
   it is used as input into opaque_RecoverCredentials() - caller must allocate including envU_len: e.g.:
   uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
   @param [out] sk - the shared secret established between the user & server
   @param [out] sec - the current context necessary for the explicit
   authentication of the user in opaque_UserAuth(). This
   param is optional if no explicit user auth is necessary it can be
   set to NULL
   @return the function returns 0 if everything is correct
 */
int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], uint8_t *sk, uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);

/**
   This is the same function as defined in the paper with the
   usrSessionEnd name. It is run by the user and receives as input the
   response from the previous server opaque_CreateCredentialResponse()
   function as well as the sec value from running the
   opaque_CreateCredentialRequest() function that initiated this
   instantiation of this protocol, All these input parameters are
   transformed into a shared/secret session key pk, which should be
   the same as the one calculated by the
   opaque_CreateCredentialResponse() function.

   @param [in] resp - the response sent from the server running opaque_CreateCredentialResponse()
   @param [in] sec - the private sec output of the client initiating
   this instantiation of this protocol using opaque_CreateCredentialRequest()
   @param [in] pkS - if cfg.pkS == NotPackaged pkS *must* be supplied here, otherwise it must be NULL
   @param [in] cfg - the configuration of the envelope secret and cleartext part
   @param [in] infos - various extra (unspecified) protocol information
   as recommended by the rfc
   @param [in/out] ids - if ids were packed in the envelope - as given by
   the cfg param -, they are returned in this struct - if either
   cfg.idS or cfg.idU is NotPackaged, then the according value must be
   set in this struct before calling opaque_RecoverCredentials
   @param [out] sk - the shared secret established between the user & server
   @param [out] authU - the authentication code to be sent to the server
   in case explicit user authentication is required
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope
   @return the function returns 0 if the protocol is executed correctly
*/
int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/], const uint8_t pkS[crypto_scalarmult_BYTES], const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t *sk, uint8_t authU[crypto_auth_hmacsha256_BYTES], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   Explicit User Authentication.

   This is a function not explicitly specified in the original paper. In the
   ietf cfrg draft authentication is done using a hmac of the session
   transcript with different keys coming out of a hkdf after the key
   exchange.

   @param [in] sec - the context returned by opaque_CreateCredentialResponse()
   @param [in] authU is the authentication token sent by the user.
   @return the function returns 0 if the hmac verifies correctly.
 */
int opaque_UserAuth(const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES]);

/**
   Alternative user initialization, user registration as specified by the RFC

   The paper originally proposes a very simple 1 shot interface for
   registering a new "user", however this has the drawback that in
   that case the users secrets and its password are exposed in
   cleartext at registration to the server. There is an alternative 4
   message registration protocol specified by the rfc, which avoids
   the exposure of the secrets and the password to the server which
   can be instantiated by following for registration functions.
 */


/**
   Initial step to start registering a new user/client with the server.
   The user inputs its password pwdU, and receives a secret context sec
   and a blinded value M as output. sec should be protected until
   step 3 of this registration protocol and the value M should be
   passed to the server.
   @param [in] pwdU - the users password
   @param [in] pwdU_len - length of the users password
   @param [out] sec - a secret context needed for the 3rd step in this
   registration protocol - this needs to be protected and sanitized
   after usage.
   @param [out] M - the blinded hashed password as per the OPRF,
   this needs to be sent to the server together with any other
   important and implementation specific info such as user/client id,
   envelope configuration etc.
   @return the function returns 0 if everything is correct.
 */
int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t M[crypto_core_ristretto255_BYTES]);

/**
   Server evaluates OPRF and creates a user-specific public/private keypair

   The server receives M from the users invocation of its
   opaque_CreateRegistrationRequest() function, it outputs a value sec
   which needs to be protected until step 4 by the server. This
   function also outputs a value pub which needs to be passed to the
   user.
   @param [in] M - the blinded password as per the OPRF.
   @param [out] sec - the private key and the OPRF secret of the server.
   @param [out] pub - the evaluated OPRF and pubkey of the server to
   be passed to the client into opaque_FinalizeRequest()
   @return the function returns 0 if everything is correct.
 */
int opaque_CreateRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   2nd step of registration: Server evaluates OPRF - Global Server Key Version

   This function is essentially the same as
   opaque_CreateRegistrationResponse(), except this function does not
   generate a per-user long-term key, but instead expects the servers
   to supply a long-term pubkey as a parameter, this might be one
   unique global key, or it might be a per-user key derived from a
   server secret.

   This function is called CreateRegistrationResponse in the rfc.
   The server receives M from the users invocation of its
   opaque_CreateRegistrationRequest() function, it outputs a value sec
   which needs to be protected until step 4 by the server. This
   function also outputs a value pub which needs to be passed to the
   user.
   @param [in] M - the blinded password as per the OPRF.
   @param [in] pkS - the servers long-term pubkey
   @param [out] sec - the private key and the OPRF secret of the server.
   @param [out] pub - the evaluated OPRF and pubkey of the server to
   be passed to the client into opaque_FinalizeRequest()
   @return the function returns 0 if everything is correct.
 */
int opaque_Create1kRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   Client finalizes registration by concluding the OPRF, generating
   its own keys and enveloping it all.

   This function is called FinalizeRequest in the rfc.  This function
   is run by the user, taking as input the context sec that was an
   output of the user running opaque_CreateRegistrationRequest(), and the
   output pub from the server of opaque_CreateRegistrationResponse().

   @param [in] sec - output from opaque_CreateRegistrationRequest(),
   should be sanitized after usage.
   @param [in] pub - response from the server running
   opaque_CreateRegistrationResponse()
   @param [in] cfg - the configuration of the envelope secret and cleartext part
   @param [in] ids - if ids are to be packed in the envelope - as given by
   the cfg param
   @param [out] rec - the opaque record to be stored at the server
   this is a pointer to memory allocated by the caller, and must be
   large enough to hold the record and take into account the variable
   length of idU and idS in case these are included in the envelope.
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope

   @return the function returns 0 if everything is correct.
 */
int opaque_FinalizeRequest(const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   Final Registration step - server adds own info to the record to be stored.

   The rfc does not explicitly specify this function.
   The server combines the sec value from its run of its
   opaque_CreateRegistrationResponse() function with the rec output of
   the users opaque_FinalizeRequest() function, creating the
   final record, which should be the same as the output of the 1-step
   storePwdFile() init function of the paper. The server should save
   this record in combination with a user id and/or sid value as
   suggested in the paper.

   @param [in] sec - the private value of the server running
   opaque_CreateRegistrationResponse() in step 2 of the registration
   protocol
   @param [in/out] rec - input the record from the client running
   opaque_FinalizeRequest() - output the final record to be
   stored by the server this is a pointer to memory allocated by the
   caller, and must be large enough to hold the record and take into
   account the variable length of idU and idS in case these are
   included in the envelope.
 */
void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);

/**
   Final Registration step Global Server Key Version - server adds own info to the record to be stored.

   this function essentially does the same as
   opaque_StoreUserRecord() except that it expects the server
   to provide its secret key. This server secret key might be one
   global secret key used for all users, or it might be a per-user
   unique key derived from a secret server seed.

   The rfc does not explicitly specify this function.
   The server combines the sec value from its run of its
   opaque_CreateRegistrationResponse() function with the rec output of
   the users opaque_FinalizeRequest() function, creating the
   final record, which should be the same as the output of the 1-step
   storePwdFile() init function of the paper. The server should save
   this record in combination with a user id and/or sid value as
   suggested in the paper.

   @param [in] sec - the private value of the server running
   opaque_CreateRegistrationResponse() in step 2 of the registration
   protocol
   @param [in] skS - the servers long-term private key
   @param [in/out] rec - input the record from the client running
   opaque_FinalizeRequest() - output the final record to be
   stored by the server this is a pointer to memory allocated by the
   caller, and must be large enough to hold the record and take into
   account the variable length of idU and idS in case these are
   included in the envelope.
 */
void opaque_Store1kUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);

/**
   This helper function calculates the length of the envelope in bytes.

   The returned size should be OPAQUE_ENVELOPE_META_LEN + SecEnv_len +
   ClrEnv_len.

   @param [in] cfg - the configuration of the envelope's secret and cleartext
   parts
   @param [in] ids - the IDs of the user and server that are only needed if we
   pack one of the IDs into the envelope as given by the cfg param

   @return the function returns the size of the envelope.
 */
size_t opaque_envelope_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids);

#endif // opaque_h
