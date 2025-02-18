/**
 *  @file opaque.h
 */

#ifndef opaque_h
#define opaque_h
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>
#include <oprf/toprf.h>

/**
 * sk is a shared secret. In opaque.h, we do not report its byte size in functions
 * like opaque_CreateCredentialResponse. We centralize its size here so that if
 * the algorithm to calculate sk changes, we can just change it in one place.
 */
#define OPAQUE_SHARED_SECRETBYTES 64
#define OPAQUE_ENVELOPE_NONCEBYTES 32
#define OPAQUE_NONCE_BYTES 32

#define OPAQUE_REGISTRATION_RECORD_LEN (               \
   /* client_public_key */ crypto_scalarmult_BYTES+    \
   /* masking_key */       crypto_hash_sha512_BYTES+   \
   /* envelope nonce */    OPAQUE_ENVELOPE_NONCEBYTES+ \
   /* envelope mac */      crypto_auth_hmacsha512_BYTES)

#define OPAQUE_USER_RECORD_LEN (                       \
   /* kU */ crypto_core_ristretto255_SCALARBYTES+      \
   /* skS */ crypto_scalarmult_SCALARBYTES+            \
   OPAQUE_REGISTRATION_RECORD_LEN)

#define OPAQUE_USER_SESSION_PUBLIC_LEN (               \
   /* blinded */ crypto_core_ristretto255_BYTES+       \
   /* X_u */ crypto_scalarmult_BYTES+                  \
   /* nonceU */ OPAQUE_NONCE_BYTES)

#define OPAQUE_USER_SESSION_SECRET_LEN (               \
   /* r */ crypto_core_ristretto255_SCALARBYTES+       \
   /* x_u */ crypto_scalarmult_SCALARBYTES+            \
   /* nonceU */ OPAQUE_NONCE_BYTES+                    \
   /* blinded */  crypto_core_ristretto255_BYTES+      \
   /* ke1 */ OPAQUE_USER_SESSION_PUBLIC_LEN+           \
   /* pwdU_len */ sizeof(uint16_t))

#define OPAQUE_SERVER_SESSION_LEN (                    \
   /* Z */ crypto_core_ristretto255_BYTES+             \
   /* masking_nonce */ 32+                             \
   /* server_public_key */ crypto_scalarmult_BYTES+    \
   /* nonceS */ OPAQUE_NONCE_BYTES+                    \
   /* X_s */ crypto_scalarmult_BYTES+                  \
   /* auth */ crypto_auth_hmacsha512_BYTES+            \
   /* envelope nonce */    OPAQUE_ENVELOPE_NONCEBYTES+ \
   /* envelope mac */      crypto_auth_hmacsha512_BYTES)

#define OPAQUE_REGISTER_USER_SEC_LEN (                 \
   /* r */ crypto_core_ristretto255_SCALARBYTES+       \
   /* pwdU_len */ sizeof(uint16_t))

#define OPAQUE_REGISTER_PUBLIC_LEN (                   \
   /* Z */ crypto_core_ristretto255_BYTES+             \
   /* pkS */ crypto_scalarmult_BYTES)

#define OPAQUE_REGISTER_SECRET_LEN (                   \
   /* skS */ crypto_scalarmult_SCALARBYTES+            \
   /* kU */ crypto_core_ristretto255_SCALARBYTES)

/**
   struct to store the IDs of the user/server.

   If the ids are the default, then set these values to NULL/0.  The
   defaults are always the long-term public keys of the respective
   party. If your system needs different user ids, like for example
   the server DNS host name or the users email addres, then provide
   them via this struct. If only one is "custom" and the other is
   default, that is also ok.
 */
typedef struct {
  uint16_t idU_len;    /**< length of idU, most useful if idU is binary */
  uint8_t *idU;        /**< pointer to the id of the user/client in the opaque protocol */
  uint16_t idS_len;    /**< length of idS, needed for binary ids */
  uint8_t *idS;        /**< pointer to the id of the server in the opaque protocol */
} Opaque_Ids;

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
int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len,
                    const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                    const Opaque_Ids *ids,
                    uint8_t rec[OPAQUE_USER_RECORD_LEN],
                    uint8_t export_key[crypto_hash_sha512_BYTES]);

/**
   This function initiates a new OPAQUE session, is the same as the
   function defined in the paper with the name usrSession.

   @param [in] pwdU - users input password
   @param [in] pwdU_len - length of the users password
   @param [out] sec - private context, it is essential that the memory
        allocate for this buffer be **OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len**.
        The User should protect the sec value (e.g. with sodium_mlock())
        until opaque_RecoverCredentials.
   @param [out] ke1 - the message to be sent to the server
   @return the function returns 0 if everything is correct
 */
int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len,
#ifdef __cplusplus
                                   uint8_t *sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
#else
                                   uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
#endif

                                   uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN]);

/**
   This function implements the OPRF part of the first step of the
   OPAQUE protocol, it is used by opaque_CreateCredentialRequest()

   For the explanations of the parameters and return values see the
   description of opaque_CreateCredentialRequest()

   This Function is split out from the original
   opaque_CreateCredentialRequest() to facilitate the usage of OPAQUE
   in a threshold setting.
 */
int opaque_CreateCredentialRequest_oprf(const uint8_t *pwdU,
                                        const uint16_t pwdU_len,
#ifdef __cplusplus
                                        uint8_t *sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
#else
                                        uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
#endif
                                        uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN]);
/**
   This function implements the AKE part of the first step of the
   OPAQUE protocol, it is used by opaque_CreateCredentialRequest()

   For the explanations of the parameters and return values see the
   description of opaque_CreateCredentialRequest()

   This Function is split out from the original
   opaque_CreateCredentialRequest() to facilitate the usage of OPAQUE
   in a threshold setting.
 */
int opaque_CreateCredentialRequest_ake(const uint16_t pwdU_len,
#ifdef __cplusplus
                                       uint8_t *sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
#else
                                       uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
#endif
                                       uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN]);

/**
   This is the same function as defined in the paper with name
   srvSession name. This function runs on the server and
   receives the output pub from the user running opaque_CreateCredentialRequest(),
   furthermore the server needs to load the user record created when
   registering the user with opaque_Register() or
   opaque_StoreUserRecord(). These input parameters are
   transformed into a secret/shared session key sk and a response resp
   to be sent back to the user.
   @param [in] ke1 - the pub output of the opaque_CreateCredentialRequest()
   @param [in] rec - the record created during "registration" and stored by the server
   @param [in] ids - the id of the client and server
   @param [in] ctx - a context of this instantiation of this protocol, e.g. "AppABCv12.34"
   @param [in] ctx_len - a context of this instantiation of this protocol
   @param [out] ke2 - servers response to be sent to the client where
   it is used as input into opaque_RecoverCredentials()
   @param [out] sk - the shared secret established between the user & server
   @param [out] sec - the current context necessary for the explicit
   authentication of the user in opaque_UserAuth(). This
   param is optional if no explicit user auth is necessary it can be
   set to NULL
   @return the function returns 0 if everything is correct
 */
int opaque_CreateCredentialResponse(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN],
                                    const uint8_t rec[OPAQUE_USER_RECORD_LEN],
                                    const Opaque_Ids *ids,
                                    const uint8_t *ctx, const uint16_t ctx_len,
                                    uint8_t ke2[OPAQUE_SERVER_SESSION_LEN],
                                    uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
                                    uint8_t authU[crypto_auth_hmacsha512_BYTES]);

/**
   This is the core of opaque_CreateCredentialResponse() but it
   accepts 3 additional parameters enabling the use of 3hashTDH for a
   threshold instantiation of OPAQUE

   see description for other parameters parameters above for
   opaque_CreateCredentialResponse()

   @param [in] zero: a TOPRF_Share_BYTES long byte-array containing a
          SSS sharing of the value zero.
   @param [in] ssid_S: a sub-session ID which all the participating
          servers agree on.
   @param [in] ssid_S_len: the length of the ssid_S value
 */
int opaque_CreateCredentialResponse_core(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN],
                                         const uint8_t _rec[OPAQUE_USER_RECORD_LEN],
                                         const Opaque_Ids *ids,
                                         const uint8_t *ctx,
                                         const uint16_t ctx_len,
                                         const uint8_t zero[TOPRF_Share_BYTES],
                                         const uint8_t *ssid_S, const uint16_t ssid_S_len,
                                         // output
                                         uint8_t ke2[OPAQUE_SERVER_SESSION_LEN],
                                         uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
                                         uint8_t authU[crypto_auth_hmacsha512_BYTES]);

/**
   This function combines the shares during a threshold OPAQUE
   session setup into the evaluated blinded OPRF element beta.

   During a threshold OPAQUE setssion seutp the servers respond each
   with the blinded OPRF element evaluated with their share. This
   function takes all responses, combines the evaluated shares into
   beta, and replaces the blinded shares with beta in the responses.

   This function must be called before opaque_RecoversCredentials() in
   case of a threshold OPAQUE registration. It takes the response from
   opaque_CreateCredentialResponse()

   @param [in] t: the threshold.
   @param [in] n: the number of items in indexes and ke2s.
   @param [in] indexes: the indexes of the shares in the ke2s array.
   @param [in] ke2s: all responses from all servers.
   @param [out] beta: the threshold combined beta

   @return 0 on success.
 */
int opaque_CombineCredentialResponses(const uint8_t t, const uint8_t n,
                                      const uint8_t indexes[n],
                                      const uint8_t ke2s[n][OPAQUE_SERVER_SESSION_LEN],
                                      uint8_t beta[crypto_scalarmult_ristretto255_BYTES]);

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
   @param [in] ctx - a context of this instantiation of this protocol, e.g. "AppABCv12.34"
   @param [in] ctx_len - a context of this instantiation of this protocol
   @param [in] ids - The ids of the server/client in case they are not the default.
   @param [out] sk - the shared secret established between the user & server
   @param [out] authU - the authentication code to be sent to the
   server in case explicit user authentication is required, optional
   set to NULL if not needed
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope
   @return the function returns 0 if the protocol is executed correctly
*/
int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
                              const uint8_t *sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
                              const uint8_t *ctx, const uint16_t ctx_len,
                              const Opaque_Ids *ids,
                              uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
                              uint8_t authU[crypto_auth_hmacsha512_BYTES],
                              uint8_t export_key[crypto_hash_sha512_BYTES]);

/**
   This is the same function as opaque_RecoverCredentials() except is
   has one additional parameter for an externally supplied OPRF evaluated element.

   This allows the implementation of a threshold OPAQUE where the OPRF
   evaluated element is recovered from the responses and combined into
   a final beta value. This is usually done by calling
   opaque_CombineCredentialResponses()

   For the explanations of the parameters and return values see the
   description of opaque_CreateCredentialRequest(). The extra parameters are:

   @param [in] beta: the externally calculated beta value.
   @param [in] unlink_masking_key: a pointer to an array, if not NULL, will
   make the masking key unique by running PRF(pkS, masking_key), this makes
   user records unique on all threshold servers, otherwise the masking_key will
   make these records linkable.
   @param [in] umk_len: the length of the array pointed at by unlink_masking_key.
 */
int opaque_RecoverCredentials_extBeta(const uint8_t ke2[OPAQUE_SERVER_SESSION_LEN],
                              const uint8_t *_sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
                              const uint8_t *ctx, const uint16_t ctx_len,
                              const Opaque_Ids *ids0,
                              const uint8_t beta[crypto_scalarmult_ristretto255_BYTES],
										const uint8_t *unlink_masking_key, const size_t umk_len,
                              uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
                              uint8_t authU[crypto_auth_hmacsha512_BYTES], // aka ke3
                              uint8_t export_key[crypto_hash_sha512_BYTES]);


/**
   Explicit User Authentication.

   This is a function not explicitly specified in the original paper. In the
   irtf cfrg draft authentication is done using a hmac of the session
   transcript with different keys coming out of a hkdf after the key
   exchange.

   @param [in] authU0 - the authU value returned by opaque_CreateCredentialResponse()
   @param [in] authU is the authentication token sent by the user.
   @return the function returns 0 if the hmac verifies correctly.
 */
int opaque_UserAuth(const uint8_t authU0[crypto_auth_hmacsha512_BYTES],
                    const uint8_t authU[crypto_auth_hmacsha512_BYTES]);

/**
   Alternative user initialization, user registration as specified by the RFC
 */


/**
   Initial step to start registering a new user/client with the server.
   The user inputs its password pwdU, and receives a secret context sec
   and a blinded value blinded as output. sec should be protected until
   step 3 of this registration protocol and the value blinded should be
   passed to the server.
   @param [in] pwdU - the users password
   @param [in] pwdU_len - length of the users password
   @param [out] sec - a secret context needed for the 3rd step in this
   registration protocol - this needs to be protected and sanitized
   after usage.
   @param [out] request - the blinded hashed password as per the OPRF,
   this needs to be sent to the server together with any other
   important and implementation specific info such as user/client id,
   envelope configuration etc.
   @return the function returns 0 if everything is correct.
 */
int opaque_CreateRegistrationRequest(const uint8_t *pwdU,
                                     const uint16_t pwdU_len,
#ifdef __cplusplus
                                     uint8_t *sec/*[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len]*/,
#else
                                     uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
#endif
                                     uint8_t request[crypto_core_ristretto255_BYTES]);

/**
   2nd step of registration: Server evaluates OPRF - Global Server Key Version

   This function is essentially the same as
   opaque_CreateRegistrationResponse(), except this function does not
   generate a per-user long-term key, but instead expects the servers
   to supply a long-term pubkey as a parameter, this might be one
   unique global key, or it might be a per-user key derived from a
   server secret.

   This function is called CreateRegistrationResponse in the rfc.
   The server receives blinded from the users invocation of its
   opaque_CreateRegistrationRequest() function, it outputs a value sec
   which needs to be protected until step 4 by the server. This
   function also outputs a value pub which needs to be passed to the
   user.
   @param [in] request - the blinded password as per the OPRF.
   @param [in] skS - the servers long-term private key, optional, set
   to NULL if you want this implementation to generate a unique key
   for this record.
   @param [out] sec - the private key and the OPRF secret of the server.
   @param [out] pub - the evaluated OPRF and pubkey of the server to
   be passed to the client into opaque_FinalizeRequest()
   @return the function returns 0 if everything is correct.
 */
int opaque_CreateRegistrationResponse(const uint8_t request[crypto_core_ristretto255_BYTES],
                                      const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                                      uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
                                      uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   Same as opaque_CreateRegistrationResponse() - except this takes
   additionally a function pointer and a context for this function.

   the keygen() is a function returning a new oprf seed, this is
   needed for engaging in a distributed key generation procedure for
   threshold OPAQUE. Of course this can also be *dangerously* abused
   to tap into different sources of entropy instead of the default
   sodium_randombytes() which is carefully designed to use the best
   entropy available on a given OS.

   parameters: see description for opaque_CreateRegistrationResponse()

   @param [in] keygen: function pointer to
          `int (*)(const void* ctx, uint8_t k[crypto_core_ristretto255_SCALARBYTES])`
   @param [in] ctx: a void pointer to extra data neded for the keygen
          function to operate.
 */
int opaque_CreateRegistrationResponse_extKeygen(const uint8_t blinded[crypto_core_ristretto255_BYTES],
                                                const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                                                const toprf_keygencb keygen,
                                                void* keygen_ctx,
                                                uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN],
                                                uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]);


/**
   Same as opaque_CreateRegistrationResponse_extKeygen() - except this takes
   additional parameters to enable 3hashTDH-based threshold-OPAQUE.

   other parameters parameters: see description for
   opaque_CreateRegistrationResponse() and
   opaque_CreateRegistrationResponse_extKeygen()

   @param [in] zero: a TOPRF_Share_BYTES long byte-array containing a
          SSS sharing of the value zero.
   @param [in] ssid_S: a sub-session ID which all the participating
          servers agree on.
   @param [in] ssid_S_len: the length of the ssid_S value

 */
int opaque_CreateRegistrationResponse_core(const uint8_t blinded[crypto_core_ristretto255_BYTES],
                                           const uint8_t skS[crypto_scalarmult_SCALARBYTES],
                                           const toprf_keygencb keygen,
                                           void* keygen_ctx,
                                           const uint8_t zero[TOPRF_Share_BYTES],
                                           const uint8_t *ssid_S, const uint16_t ssid_S_len,
                                           uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN],
                                           uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   This function combines the shares during a threshold OPAQUE
   registration into the evaluated blinded OPRF element beta.

   During a threshold OPAQUE registration the servers respond each
   with the blinded OPRF element evaluated with their share. This
   function takes all responses, combines the evaluated shares into
   beta, and replaces the blinded shares with beta in the responses.

   This function must be called before opaque_FinalizeRequest() in
   case of a threshold OPAQUE registration. It takes the response from
   opaque_CreateRegistrationResponse()

   @param [in] t: the threshold
   @param [in] n: the number of total shares
   @param [inout] pubs: all responses from all servers.

   @return 0 on success.
 */
int opaque_CombineRegistrationResponses(const uint8_t t, const uint8_t n,
                                        const uint8_t _pubs[n][OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   Client finalizes registration by concluding the OPRF, generating
   its own keys and enveloping it all.

   This is an extended variant of the function called FinalizeRequest in the
   rfc. It adds an additonal pointer to an array and a size of this array as
   parameter that can be used to make user records unlinkable across servers in
   a threshold setup.

   This function is run by the user, taking as input the context sec that was
   an output of the user running opaque_CreateRegistrationRequest(), and the
   output pub from the server of opaque_CreateRegistrationResponse().

   @param [in] sec - output from opaque_CreateRegistrationRequest(),
   should be sanitized after usage.
   @param [in] pub - response from the server running
   opaque_CreateRegistrationResponse()
   @param [in] ids - if ids are not the default value
   @param [in] unlink_masking_key: a pointer to an array, if not NULL, will
   make the masking key unique by running PRF(pkS, masking_key), this makes
   user records unique on all threshold servers, otherwise the masking_key will
   make these records linkable.
   @param [in] umk_len: the length of the array pointed at by unlink_masking_key.
   @param [out] reg_rec - the opaque registration record containing
   the users data.
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope. Optional, if not
   needed set to NULL.

   @return the function returns 0 if everything is correct.
 */
int opaque_FinalizeRequest_core(const uint8_t *sec/*[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len]*/,
                                const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
                                const Opaque_Ids *ids,
                                const uint8_t *unlink_masking_key, const size_t umk_len,
                                uint8_t reg_rec[OPAQUE_REGISTRATION_RECORD_LEN],
                                uint8_t export_key[crypto_hash_sha512_BYTES]);

/**
   Client finalizes registration by concluding the OPRF, generating
   its own keys and enveloping it all.

   This function is called FinalizeRequest in the rfc.  This function
   is run by the user, taking as input the context sec that was an
   output of the user running opaque_CreateRegistrationRequest(), and the
   output pub from the server of opaque_CreateRegistrationResponse().

   for parameters see opaque_FinalizeRequest() description.
 */
int opaque_FinalizeRequest(const uint8_t *sec/*[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len]*/,
                           const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
                           const Opaque_Ids *ids,
                           uint8_t reg_rec[OPAQUE_REGISTRATION_RECORD_LEN],
                           uint8_t export_key[crypto_hash_sha512_BYTES]);

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
   @param [in] reg_rec - the registration record from the client running
   opaque_FinalizeRequest()
   @param [out] rec - the final record to be stored by the server.
 */
void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
                            const uint8_t recU[OPAQUE_REGISTRATION_RECORD_LEN],
                            uint8_t rec[OPAQUE_USER_RECORD_LEN]);
#ifdef __cplusplus
}
#endif
#endif // opaque_h
