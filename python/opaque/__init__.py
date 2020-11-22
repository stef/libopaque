"""Wrapper for libopaque library

   Copyright (c) 2018, Marsiske Stefan.
   All rights reserved.

   This file is part of libopaque.

   libopaque is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   libopaque is distributed in the hope that it will be
   useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with libopaque. If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.util
from ctypes import sizeof, c_uint16, c_uint8, c_size_t, c_uint32

opaquelib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('opaque') or ctypes.util.find_library('libopaque'))

if not opaquelib._name:
    raise ValueError('Unable to find libopaque')

from pysodium import (crypto_core_ristretto255_SCALARBYTES, crypto_scalarmult_SCALARBYTES, crypto_scalarmult_BYTES,
                      crypto_core_ristretto255_BYTES, crypto_auth_hmacsha256_BYTES, crypto_hash_sha256_STATEBYTES,
                      crypto_hash_sha256_BYTES, sodium_version_check)
if sodium_version_check(1,0,19):
    from pysodium import crypto_auth_hmacsha256_KEYBYTES
else:
    from pysodium import crypto_auth_hmacsha256_BYTES as crypto_auth_hmacsha256_KEYBYTES

OPAQUE_NONCE_BYTES = 32
OPAQUE_ENVELOPE_META_LEN = (2*crypto_hash_sha256_BYTES + 2*sizeof(c_uint16))
OPAQUE_USER_RECORD_LEN = (
    crypto_core_ristretto255_SCALARBYTES+     # k_s
    crypto_scalarmult_SCALARBYTES+            # p_s
    crypto_scalarmult_BYTES+                  # P_u
    crypto_scalarmult_BYTES+                  # P_s
    sizeof(c_uint32))                         # env_len
OPAQUE_USER_SESSION_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+           # alpha
    crypto_scalarmult_BYTES+                  # X_u
    OPAQUE_NONCE_BYTES)                       # nonceU
OPAQUE_USER_SESSION_SECRET_LEN = (
    crypto_core_ristretto255_SCALARBYTES+     # r
    crypto_scalarmult_SCALARBYTES+            # x_u
    OPAQUE_NONCE_BYTES+                       # nonceU
    crypto_core_ristretto255_BYTES+           # alpha
    sizeof(c_uint16))                         # pw_len
OPAQUE_SERVER_SESSION_LEN = (
    crypto_core_ristretto255_BYTES+           # beta
    crypto_scalarmult_BYTES+                  # X_s
    OPAQUE_NONCE_BYTES+                       # nonceS
    crypto_auth_hmacsha256_BYTES+             # auth
    sizeof(c_uint32))                         # env_len
OPAQUE_REGISTER_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+           # beta
    crypto_scalarmult_BYTES)                  # P_s
OPAQUE_REGISTER_SECRET_LEN = (
    crypto_scalarmult_SCALARBYTES+            # p_s
    crypto_core_ristretto255_SCALARBYTES)     # k_s
OPAQUE_REGISTER_USER_SEC_LEN = (
    crypto_scalarmult_BYTES+                  # r
    sizeof(c_size_t))
OPAQUE_SERVER_AUTH_CTX_LEN = (
    crypto_auth_hmacsha256_KEYBYTES +
    crypto_hash_sha256_STATEBYTES)

def __check(code):
    if code != 0:
        raise ValueError

# struct to store the IDs of the user/server.
class Ids(ctypes.Structure):
    _fields_ = [('idU_len', c_uint16),              # length of idU, most useful if idU is binary
                ('idU', ctypes.c_char_p),           # pointer to the id of the user/client in the opaque protocol
                ('idS_len', c_uint16),              # length of idS, needed for binary ids
                ('idS', ctypes.c_char_p)]           # pointer to the id of the server in the opaque protocol

    def __init__(self, ids=None, idu=None):
        super().__init__()
        if idu:
            self.idU=idu.encode("utf8")
            self.idU_len=len(self.idU)
        if ids:
            self.idS=ids.encode('utf8')
            self.idS_len=len(self.idS)

#   struct to store various extra protocol information.
#
#   This is defined by the RFC to be used to bind extra
#   session-specific parameters to the current session.
class App_Infos(ctypes.Structure):
    _fields_ = [
        ('info1',ctypes.c_char_p),
        ('info1_len', c_size_t),
        ('info2',ctypes.c_char_p),
        ('info2_len', c_size_t),
        ('einfo2',ctypes.c_char_p),
        ('einfo2_len', c_size_t),
        ('info3',ctypes.c_char_p),
        ('info3_len', c_size_t),
        ('einfo3',ctypes.c_char_p),
        ('einfo3_len', c_size_t),
    ]

    def __init__(self, info1=None, info2=None, einfo2=None, info3=None, einfo3=None):
        super().__init__()
        if info1:
            self.info1=info1.encode("utf8")
            self.info1_len=len(self.info1)
        else:
            self.info1=None
            self.info1_len=0
        if info2:
            self.info2=info2.encode("utf8")
            self.info2_len=len(self.info2)
        else:
            self.info2=None
            self.info2_len=0
        if einfo2:
            self.einfo2=einfo2.encode("utf8")
            self.einfo2_len=len(self.einfo2)
        else:
            self.einfo2=None
            self.einfo2_len=0
        if info3:
            self.info3=info3.encode("utf8")
            self.info3_len=len(self.info3)
        else:
            self.info3=None
            self.info3_len=0
        if einfo3:
            self.einfo3=einfo3.encode("utf8")
            self.einfo3_len=len(self.einfo3)
        else:
            self.einfo3=None
            self.einfo3_len=0

# enum to define the handling of various fields packed in the opaque envelope
NotPackaged = 0,
InSecEnv = 1      # field is encrypted
InClrEnv = 2      # field is plaintext, but authenticated

# configuration of the opaque envelope fields
class PkgConfig(ctypes.Structure):
    _fields_ = [
        ('skU', c_uint8, 2), # users secret key - must not be
                             # InClrEnv, if it is NotPackaged then
                             # rwdU is used to seed a keygen() via
                             # hkdf-expand()
        ('pkU', c_uint8, 2), # users public key - if not included it
                             # can be derived from the private key
        ('pkS', c_uint8, 2), # servers public key - currently this is
                             # not allowed to set to NotPackaged -
                             # TODO if set to NotPackaged allow to
                             # specify the pubkey explicitly as a
                             # param to the functions that require
                             # this info
        ('idU', c_uint8, 2), # id of the user - the RFC specifies this
                             # to be possible to pack into the
                             # envelope
        ('idS', c_uint8, 2), # id of the server - the RFC specifies
                             # this to be possible to pack into the
                             # envelope
    ]

#  helper function calculating the length of the two parts of the envelope
#
#  based on the config and the length of the id[U|S] returns the size
#  for the SecEnv or the ClrEnv portion of the envelope
#
#  @param [in] cfg - the configuration of the envelope secret and cleartext part
#  @param [in] ids - if ids are to be packed in the envelope - as given by
#  the cfg param
#  @param [in] type - InSecEnv|InClrEnv - calling with NotPackaged is useless
#
#  @return the function returns the size of the envelope part specified in the param type.
#size_t package_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, const Opaque_PkgTarget type);
def package_len(cfg, ids, type):
    return opaquelib.opaque_package_len(ctypes.pointer(cfg), ctypes.pointer(ids), type)

def get_envlen(cfg, ids):
    ClrEnv_len = package_len(cfg, ids, InClrEnv)
    SecEnv_len = package_len(cfg, ids, InSecEnv)
    return OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len

#  This function implements the storePwdFile function from the paper
#  it is not specified by the RFC. This function runs on the server
#  and creates a new output record rec of secret key material. The
#  server needs to implement the storage of this record and any
#  binding to user names or as the paper suggests sid.
#
#  @param [in] pw - the users password
#  @param [in] pwlen - length of the users password
#  @param [in] key - a key to be used for domain separation in the
#       final hash of the OPRF. if set to NULL then the default is
#       "RFCXXXX" - TODO set XXXX to the real value when the rfc is
#       published.
#  @param [in] key_len - length of the key, ignored if key is NULL
#  @param [in] sk - in case of global server keys this is the servers
#       private key, should be set to NULL if per/user keys are to be
#       generated
#  @param [in] cfg - configuration of the opaque envelope, see
#       Opaque_PkgConfig
#  @param [in] ids - the ids of the user and server, see Opaque_Ids
#  @param [out] rec - the opaque record the server needs to
#       store. this is a pointer to memory allocated by the caller,
#       and must be large enough to hold the record and take into
#       account the variable length of idU and idS in case these are
#       included in the envelope.
#  @param [out] export_key - optional pointer to pre-allocated (and
#       protected) memory for an extra_key that can be used to
#       encrypt/authenticate additional data.
#  @return the function returns 0 if everything is correct
#int opaque_Register(const uint8_t *pw, const uint16_t pwlen, const uint8_t *key, const uint16_t key_len, const uint8_t sk[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t export_key[crypto_hash_sha256_BYTES]);
def Register(pwd, cfg, ids, key=None, sk=None):
    if not pwd:
        raise ValueError("invalid parameter")

    env_len = get_envlen(cfg, ids)

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+env_len)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)

    __check(opaquelib.opaque_Register(pwd, len(pwd), key, len(key) if key else 0, sk, ctypes.pointer(cfg), ctypes.pointer(ids), rec, export_key))
    return (rec.raw, export_key.raw)

#  This function initiates a new OPAQUE session, is the same as the
#  function defined in the paper with the name usrSession.
#
#  @param [in] pw - users input password
#  @param [in] pwlen - length of the users password
#  @param [out] sec - private context, The User should protect the sec
#       value (e.g. with sodium_mlock()) until
#  @param [out] pub - the message to be sent to the server
#  @return the function returns 0 if everything is correct
#int opaque_CreateCredentialRequest(const uint8_t *pw, const uint16_t pwlen, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
def CreateCredentialRequest(pwd):
    if not pwd:
        raise ValueError("invalid parameter")
    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN+len(pwd))
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    opaquelib.opaque_CreateCredentialRequest(pwd, len(pwd), sec, pub)
    return pub.raw, sec.raw

#  This is the same function as defined in the paper with name
#  srvSession name. This function runs on the server and
#  receives the output pub from the user running usrSession(),
#  furthermore the server needs to load the user record created when
#  registering the user with opaque_init_srv() or
#  opaque_private_init_srv_finish(). These input parameters are
#  transformed into a secret/shared session key sk and a response resp
#  to be sent back to the user.
#
#  @param [in] pub - the pub output of the opaque_session_user_start()
#  @param [in] rec - the recorded created during "registration" and stored by the server
#  @param [in] ids - the id if the client and server
#  @param [in] infos - various extra (unspecified) protocol information as recommended by the rfc.
#  @param [out] resp - servers response to be sent to the client where
#  it is used as input into opaque_session_usr_finish()
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] _ctx - the current context necessary for the explicit
#  authentication of the user in opaque_session_server_auth(). This
#  param is optional if no explicit user auth is necessary it can be
#  set to NULL
#  @return the function returns 0 if everything is correct
#int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[crypto_secretbox_KEYBYTES], uint8_t _ctx[OPAQUE_SERVER_AUTH_CTX_LEN]);
def CreateCredentialResponse(pub, rec, cfg, ids, infos):
    if None in (pub, rec):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_USER_SESSION_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) <= OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    env_len = get_envlen(cfg, ids)
    resp = ctypes.create_string_buffer(OPAQUE_SERVER_SESSION_LEN+env_len)
    sk = ctypes.create_string_buffer(32)
    ctx = ctypes.create_string_buffer(OPAQUE_SERVER_AUTH_CTX_LEN)
    __check(opaquelib.opaque_CreateCredentialResponse(pub, rec, ctypes.pointer(ids), ctypes.pointer(infos) if infos else None, resp, sk, ctx))
    return resp.raw, sk.raw, ctx.raw


#  This is the same function as defined in the paper with the
#  usrSessionEnd name. It is run by
#  the user and receives as input the response from the previous server
#  opaque_session_srv() function as well as the sec value from running
#  the opaque_session_usr_start() function that initiated this
#  instantiation of this protocol, All these input parameters are
#  transformed into a shared/secret session key pk, which should be the
#  same as the one calculated by the opaque_session_srv() function.
#
#  @param [in] resp - the response sent from the server running opaque_session_srv()
#  @param [in] sec - the private sec output of the client initiating
#  this instantiation of this protocol using opaque_session_usr_start()
#  @param [in] key - an value to be used as key during the final hashing
#  of the OPRF, the rfc specifies this as 'RFCXXXX' but can be any other
#  local secret amending the password typed in in the first step.
#  @param [in] key_len - the length of the previous param key
#  @param [in] cfg - the configuration of the envelope secret and cleartext part
#  @param [in] infos - various extra (unspecified) protocol information
#  as recommended by the rfc
#  @param [out] ids - if ids were packed in the envelope - as given by
#  the cfg param -, they are returned in this struct
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] auth - the authentication code to be sent to the server
#  in case explicit user authentication is required
#  @param [out] export_key - key used to encrypt/authenticate extra
#  material not stored directly in the envelope
#  @return the function returns 0 if the protocol is executed correctly
#int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], const uint8_t *key, const uint16_t key_len, const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t *sk, uint8_t auth[crypto_auth_hmacsha256_BYTES], uint8_t export_key[crypto_hash_sha256_BYTES]);
def RecoverCredentials(resp, sec, cfg, infos, key=None):
    if None in (resp, sec):
        raise ValueError("invalid parameter")
    if len(resp) <= OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid resp param")
    if len(sec) <= OPAQUE_USER_SESSION_SECRET_LEN: raise ValueError("invalid sec param")

    sk = ctypes.create_string_buffer(32)
    auth = ctypes.create_string_buffer(crypto_auth_hmacsha256_BYTES)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)

    ids = Ids()
    ids.idU = ctypes.cast(ctypes.create_string_buffer(1024), ctypes.c_char_p)
    ids.idU_len=1024
    ids.idS = ctypes.cast(ctypes.create_string_buffer(1024), ctypes.c_char_p)
    ids.idS_len=1024

    __check(opaquelib.opaque_RecoverCredentials(resp, sec, key, len(key) if key else 0, ctypes.pointer(cfg), ctypes.pointer(infos) if infos else None, ctypes.pointer(ids), sk, auth, export_key))
    return sk.raw, auth.raw, export_key.raw, ids

#  Explicit User Authentication.
#
#  This is a function not explicitly in the original paper. In the
#  ietf cfrg draft authentication is done using a hmac of the session
#  transcript with different keys coming out of a hkdf after the key
#  exchange.
#
#  @param [in] ctx - the context returned by opaque_session_srv()
#  @param [in] authU is the authentication token sent by the user.
#  @param [in] infos is a pointer to a struct containing the
#  info* /einfo* values used during the protocol instantiation (only
#  info3/einfo3 is needed - the rest is already cached in ctx)
#  @return the function returns 0 if the hmac verifies correctly.
#int opaque_UserAuth(uint8_t _ctx[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos);
def UserAuth(ctx, auth, infos):
    if None in (ctx, auth):
        raise ValueError("invalid parameter")

    __check(opaquelib.opaque_UserAuth(ctx, auth, ctypes.pointer(infos) if infos else None))

#  Alternative user initialization

#  The paper originally proposes a very simple 1 shot interface for
#  registering a new "user", however this has the drawback that in
#  that case the users secrets and its password are exposed in
#  cleartext at registration to the server. There is an alternative 4
#  message registration protocol specified by the rfc, which avoids
#  the exposure of the secrets and the password to the server which
#  can be instantiated by following for registration functions.


#  Initial step to start registering a new user/client with the server.
#
#  This function is called CreateRegistrationRequest in the rfc.
#  The user inputs its password pw, and receives a secret context ctx
#  and a blinded value alpha as output. ctx should be protected until
#  step 3 of this registration protocol and the value alpha should be
#  passed to the server.
#
#  @param [in] pw - the users password
#  @param [in] pwlen - length of the users password
#  @param [out] ctx - a secret context needed for the 3rd step in this
#  registration protocol - this needs to be protected and sanitized
#  after usage.
#  @param [out] alpha - the blinded hashed password as per the OPRF,
#  this needs to be sent to the server together with any other
#  important and implementation specific info such as user/client id,
#  envelope configuration etc.
#  @return the function returns 0 if everything is correct.
# int opaque_CreateRegistrationRequest(const uint8_t *pw, const uint16_t pwlen, uint8_t ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwlen], uint8_t *alpha);
def CreateRegistrationRequest(pwd):
    if not pwd:
        raise ValueError("invalid parameter")

    ctx = ctypes.create_string_buffer(OPAQUE_REGISTER_USER_SEC_LEN+len(pwd))
    alpha = ctypes.create_string_buffer(32)
    opaquelib.opaque_CreateRegistrationRequest(pwd, len(pwd), ctx, alpha)
    return ctx.raw, alpha.raw

#  Server evaluates OPRF and creates a user-specific public/private keypair
#
#  This function is called CreateRegistrationResponse in the rfc.
#  The server receives alpha from the users invocation of its
#  opaque_private_init_usr_start() function, it outputs a value sec
#  which needs to be protected until step 4 by the server. This
#  function also outputs a value pub which needs to be passed to the
#  user.
#
#  @param [in] alpha - the blinded password as per the OPRF.
#  @param [out] sec - the private key and the OPRF secret of the server.
#  @param [out] pub - the evaluated OPRF and pubkey of the server to
#  be passed to the client into opaque_private_init_usr_respond()
#  @return the function returns 0 if everything is correct.
#int opaque_CreateRegistrationResponse(const uint8_t *alpha, uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def CreateRegistrationResponse(alpha):
    if not alpha:
        raise ValueError("invalid parameter")
    if len(alpha) != 32: raise ValueError("invalid alpha param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(opaquelib.opaque_CreateRegistrationResponse(alpha, sec, pub))
    return sec.raw, pub.raw
#  This function is essentially the same as
#  CreateRegistrationResponse(), except this function does not
#  generate a per-user long-term key, but instead expects the servers
#  to supply a long-term pubkey as a parameter, this might be one
#  unique global key, or it might be a per-user key derived from a
#  server secret.
#int opaque_Create1kRegistrationResponse(const uint8_t *alpha, const uint8_t pk[crypto_scalarmult_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def Create1kRegistrationResponse(alpha, pk):
    if None in  (alpha, pk):
        raise ValueError("invalid parameter")
    if len(alpha) != 32: raise ValueError("invalid alpha param")
    if len(pk) != pk: raise ValueError("invalid pk param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(opaquelib.opaque_Create1kRegistrationResponse(alpha, pk, sec, pub))
    return sec.raw, pub.raw

#  Client finalizes registration by concluding the OPRF, generating
#  its own keys and enveloping it all.
#
#  This function is called FinalizeRequest in the rfc.  This function
#  is run by the user, taking as input the context ctx that was an
#  output of the user running opaque_private_init_usr_start(), and the
#  output pub from the server of opaque_private_init_srv_respond().
#  The key parameter can be used as an extra contribution to the
#  derivation of the rwd by means of being used as a key to the final
#  hash, if not specified it uses the value specified by the rfc. The
#  result of this is the value rec which should be passed for the last
#  step to the server.
#
#  @param [in] ctx - output from opaque_private_init_usr_start(),
#  should be sanitized after usage.
#  @param [in] pub - response from the server running
#  opaque_private_init_srv_respond()
#  @param [in] key - an value to be used as key during the final hashing
#  of the OPRF, the rfc specifies this as 'RFCXXXX' but can be any other
#  local secret amending the password typed in in the first step.
#  @param [in] key_len - the length of the previous param key
#  @param [in] cfg - the configuration of the envelope secret and cleartext part
#  @param [in] ids - if ids are to be packed in the envelope - as given by
#  the cfg param
#  @param [out] rec - the opaque record to be stored at the server
#  this is a pointer to memory allocated by the caller, and must be
#  large enough to hold the record and take into account the variable
#  length of idU and idS in case these are included in the envelope.
#  @param [out] export_key - key used to encrypt/authenticate extra
#  material not stored directly in the envelope
#
#  @return the function returns 0 if everything is correct.
#int opaque_FinalizeRequest(const uint8_t *ctx, const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const uint8_t *key, const uint16_t key_len, const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t export_key[crypto_hash_sha256_BYTES]);
def FinalizeRequest(ctx, pub, cfg, ids, key=None):
    if None in (ctx, pub, cfg, ids):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(ctx) <= OPAQUE_REGISTER_USER_SEC_LEN: raise ValueError("invalid ctx param")

    env_len = get_envlen(cfg, ids)
    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+env_len)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)
    __check(opaquelib.opaque_FinalizeRequest(ctx, pub, key, len(key) if key else 0, ctypes.pointer(cfg), ctypes.pointer(ids), rec, export_key))
    return rec.raw, export_key.raw


#  Final Registration step - server adds own info to the record to be stored.
#
#  The rfc does not explicitly specify this function.
#  The server combines the sec value from its run of its
#  opaque_private_init_srv_respond() function with the rec output of
#  the users opaque_private_init_usr_respond() function, creating the
#  final record, which should be the same as the output of the 1-step
#  storePwdFile() init function of the paper. The server should save
#  this record in combination with a user id and/or sid value as
#  suggested in the paper.
#
#  @param [in] sec - the private value of the server running
#  opaque_private_init_srv_respond() in step 2 of the registration
#  protocol
#  @param [in/out] rec - input the record from the client running
#  opaque_private_init_usr_respond() - output the final record to be
#  stored by the server this is a pointer to memory allocated by the
#  caller, and must be large enough to hold the record and take into
#  account the variable length of idU and idS in case these are
#  included in the envelope.
#void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);
def StoreUserRecord(sec, rec):
    if None in (sec, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(rec) <= OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    opaquelib.opaque_StoreUserRecord(sec, rec)
    return rec


#  this function essentially does the same as
#  StoreUserRecord() except that it expects the server
#  to provide its secret key. This server secret key might be one
#  global secret key used for all users, or it might be a per-user
#  unique key derived from a secret server seed.
#void opaque_Store1kUserRecord(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t sk[crypto_scalarmult_SCALARBYTES], uint8_t _rec[OPAQUE_USER_RECORD_LEN]);
def Store1kUserRecord(sec, sk, rec):
    if None in (sec, sk, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(sk) != crypto_scalarmult_SCALARBYTES: raise ValueError("invalid sk param")
    if len(rec) <= OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    opaquelib.opaque_StoreUserRecord(sec, sk, rec)
    return rec
