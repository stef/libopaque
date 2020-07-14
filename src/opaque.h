#ifndef opaque_h
#define opaque_h

#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#define OPAQUE_NONCE_BYTES 24
#define OPAQUE_BLOB_LEN (crypto_hash_sha256_BYTES+crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES+crypto_scalarmult_BYTES+crypto_secretbox_MACBYTES)
#define OPAQUE_USER_RECORD_LEN (crypto_core_ristretto255_SCALARBYTES+crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES+crypto_scalarmult_BYTES+32+sizeof(uint64_t)+OPAQUE_BLOB_LEN)
#define OPAQUE_USER_SESSION_PUBLIC_LEN (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES+OPAQUE_NONCE_BYTES)
#define OPAQUE_USER_SESSION_SECRET_LEN (crypto_core_ristretto255_SCALARBYTES+crypto_scalarmult_SCALARBYTES+OPAQUE_NONCE_BYTES+crypto_core_ristretto255_BYTES)
#define OPAQUE_SERVER_SESSION_LEN (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES+crypto_auth_hmacsha256_BYTES+OPAQUE_NONCE_BYTES+32+sizeof(uint64_t)+OPAQUE_BLOB_LEN)
#define OPAQUE_REGISTER_PUBLIC_LEN (crypto_core_ristretto255_BYTES+crypto_scalarmult_BYTES)
#define OPAQUE_REGISTER_SECRET_LEN (crypto_scalarmult_SCALARBYTES+crypto_core_ristretto255_SCALARBYTES)
#define OPAQUE_MAX_EXTRA_BYTES 1024*1024 // 1 MB should be enough for even most PQ params

typedef struct {
  const size_t idU_len;
  const uint8_t *idU;
  const size_t idS_len;
  const uint8_t *idS;
} Opaque_Ids;

typedef struct {
  uint8_t *info1;
  size_t info1_len;
  uint8_t *info2;
  size_t info2_len;
  uint8_t *einfo2;
  size_t einfo2_len;
  uint8_t *info3;
  size_t info3_len;
  uint8_t *einfo3;
  size_t einfo3_len;
} Opaque_App_Infos;

/*
   This function implements the storePwdFile function from the
   paper. This function runs on the server and creates a new output
   record rec of secret key material and optional extra data partly
   encrypted with a key derived from the input password pw. The server
   needs to implement the storage of this record and any binding to
   user names or as the paper suggests sid.  *Attention* the size of
   rec depends on the size of extra data provided.
 */
int opaque_init_srv(const uint8_t *pw, const size_t pwlen, const uint8_t *extra, const uint64_t extra_len, const uint8_t *key, const uint64_t key_len, uint8_t rec[OPAQUE_USER_RECORD_LEN]);

/*
  This function initiates a new OPAQUE session, is the same as the
  function defined in the paper with the usrSession name. The User
  initiates a new session by providing its input password pw, and
  receving a private sec and a "public" pub output parameter. The User
  should protect the sec value until later in the protocol and send
  the pub value over to the Server.
 */
int opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);

/*
  This is the same function as defined in the paper with the
  srvSession name. It runs on the server and receives the output pub
  from the user running usrSession(), futhermore the server needs to
  load the user record created when registering the user with the
  opaque_init_srv() function. These input parameters are transformed
  into a secret/shared session key sk and a response resp to be sent
  back to the user. *Attention* rec and resp have variable length
  depending on any extra data stored.
 */
int opaque_session_srv(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[crypto_secretbox_KEYBYTES], uint8_t km3[crypto_auth_hmacsha256_KEYBYTES], crypto_hash_sha256_state *state);

/*
 This is the same function as defined in the paper with the
 usrSessionEnd name. It is run by the user, and recieves as input the
 response from the previous server opaque_session_srv() function as
 well as the sec value from running the opaque_session_usr_start()
 function that initiated this protocol, the user password pw is also
 needed as an input to this final step. All these input parameters are
 transformed into a shared/secret session key pk, which should be the
 same as the one calculated by the opaque_session_srv()
 function. *Attention* resp has a length depending on extra data. If
 rwd is not NULL it is returned - this enables to run the sphinx
 protocol in the opaque protocol.
*/
int opaque_session_usr_finish(const uint8_t *pw, const size_t pwlen, const uint8_t resp[OPAQUE_SERVER_SESSION_LEN], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], const uint8_t *key, const uint64_t key_len, const Opaque_Ids *ids, Opaque_App_Infos *infos, uint8_t *sk, uint8_t *extra, uint8_t rwd[crypto_secretbox_KEYBYTES], uint8_t auth[crypto_auth_hmacsha256_BYTES]);

/*
 This is a function not in the original paper, it comes from the
 ietf cfrg draft where authentication is done using a hmac of the
 session transcript with different keys coming out of a hkdf after
 the key exchange. km3 is the key for the hmac authenticating the
 user. state is a pointer to a sha256 state containing the
 transcript up to (and including) the response sent to the user by
 the server, so that the server only needs to add the optional info3
 and einfo3 values to this hash. authU is the authentication hmac
 sent by the user. infos is a pointer to a struct containing the
 info* /einfo* values used during the protocol instantiation (only
 info3/einfo3 is needed)
 the function returns 0 if the hmac verifies correctly.
 */
int opaque_session_server_auth(const uint8_t km3[crypto_auth_hmacsha256_KEYBYTES], crypto_hash_sha256_state *state, const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos);

/* Alternative user initialization
 *
 * The paper originally proposes a very simple 1 shot interface for
 * registering a new "user", however this has the drawback that in
 * that case the users secrets and its password are exposed in
 * cleartext at registration to the server. There is a much less
 * efficient 4 message registration protocol which avoids the exposure
 * of the secrets and the password to the server which can be
 * instantiated by the following for registration functions:
 */


/*
 * The user inputs its password pw, and receives an ephemeral secret r
 * and a blinded value alpha as output. r should be protected until
 * step 3 of this registration protocol and the value alpha should be
 * passed to the server.
 */
int opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha);

/*
 * The server receives alpha from the users invocation of its
 * opaque_private_init_usr_start() function, it outputs a value sec
 * which needs to be protected until step 4 by the server. This
 * function also outputs a value pub which needs to be passed to the
 * user.
 */
int opaque_private_init_srv_respond(const uint8_t *alpha, uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/*
 * This function is run by the user, taking as input the users
 * password pw, the ephemeral secret r that was an output of the user
 * running opaque_private_init_usr_start(), and the output pub from
 * the servers run of opaque_private_init_srv_respond(). Futhermore
 * the extra/extra_len parameter can be used to store additional data
 * in the encrypted user record. The key parameter can be used as an extra
 * contribution to the derivation of the rwd by means of being used as a key to
 * the final hash. The result of this is the value rec which should be
 * passed for the last step to the server. *Attention* the size of rec
 * depends on extra data length. If rwd is not NULL it * is returned -
 * this enables to run the sphinx protocol in the opaque protocol.
 */
int opaque_private_init_usr_respond(const uint8_t *pw, const size_t pwlen, const uint8_t *r, const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const uint8_t *extra, const uint64_t extra_len, const uint8_t *key, const uint64_t key_len, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t rwd[crypto_secretbox_KEYBYTES]);

/*
 * The server combines the sec value from its run of its
 * opaque_private_init_srv_respond() function with the rec output of
 * the users opaque_private_init_usr_respond() function, creating the
 * final record, which should be the same as the output of the 1-step
 * storePwdFile() init function of the paper. The server should save
 * this record in combination with a user id and/or sid value as
 * suggested in the paper.  *Attention* the size of rec depends on
 * extra data length.
 */
//
void opaque_private_init_srv_finish(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);

#endif // opaque_h
