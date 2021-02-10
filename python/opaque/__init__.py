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

OPAQUE_SHARED_SECRETBYTES = 32
OPAQUE_NONCE_BYTES = 32
OPAQUE_ENVELOPE_META_LEN = (2*crypto_hash_sha256_BYTES + 2*sizeof(c_uint16))
OPAQUE_USER_RECORD_LEN = (
    crypto_core_ristretto255_SCALARBYTES+     # kU
    crypto_scalarmult_SCALARBYTES+            # skS
    crypto_scalarmult_BYTES+                  # pkU
    crypto_scalarmult_BYTES+                  # pkS
    sizeof(c_uint32))                         # envU_len
OPAQUE_USER_SESSION_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+           # M
    crypto_scalarmult_BYTES+                  # X_u
    OPAQUE_NONCE_BYTES)                       # nonceU
OPAQUE_USER_SESSION_SECRET_LEN = (
    crypto_core_ristretto255_SCALARBYTES+     # r
    crypto_scalarmult_SCALARBYTES+            # x_u
    OPAQUE_NONCE_BYTES+                       # nonceU
    crypto_core_ristretto255_BYTES+           # M
    sizeof(c_uint16))                         # pwdU_len
OPAQUE_SERVER_SESSION_LEN = (
    crypto_core_ristretto255_BYTES+           # Z
    crypto_scalarmult_BYTES+                  # X_s
    OPAQUE_NONCE_BYTES+                       # nonceS
    crypto_auth_hmacsha256_BYTES+             # auth
    sizeof(c_uint32))                         # envU_len
OPAQUE_REGISTER_USER_SEC_LEN = (
    crypto_core_ristretto255_SCALARBYTES+     # r
    sizeof(c_uint16))                         # pwdU_len
OPAQUE_REGISTER_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+           # Z
    crypto_scalarmult_BYTES)                  # pkS
OPAQUE_REGISTER_SECRET_LEN = (
    crypto_scalarmult_SCALARBYTES+            # skS
    crypto_core_ristretto255_SCALARBYTES)     # kU
OPAQUE_SERVER_AUTH_CTX_LEN = (
    crypto_auth_hmacsha256_KEYBYTES +         # km3
    crypto_hash_sha256_STATEBYTES)            # xcript_state

def __check(code):
    if code != 0:
        raise ValueError

# struct to store the IDs of the user/server.
class Ids(ctypes.Structure):
    _fields_ = [('idU_len', c_uint16),              # length of idU, most useful if idU is binary
                ('idU', ctypes.c_char_p),           # pointer to the id of the user/client in the opaque protocol
                ('idS_len', c_uint16),              # length of idS, needed for binary ids
                ('idS', ctypes.c_char_p)]           # pointer to the id of the server in the opaque protocol

    def __init__(self, idu=None, ids=None):
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
NotPackaged = 0
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

#  This function implements the storePwdFile function from the paper
#  it is not specified by the RFC. This function runs on the server
#  and creates a new output record rec of secret key material. The
#  server needs to implement the storage of this record and any
#  binding to user names or as the paper suggests sid.
#
#  @param [in] pwdU - the users password
#  @param [in] pwdU_len - length of the users password
#  @param [in] skS - in case of global server keys this is the servers
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
# int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len, const uint8_t skS[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);
def Register(pwdU, cfg, ids, skS=None):
    if not pwdU:
        raise ValueError("invalid parameter")

    envU_len = envelope_len(cfg, ids)
    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+envU_len)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)
    __check(opaquelib.opaque_Register(pwdU, len(pwdU), skS, ctypes.pointer(cfg), ctypes.pointer(ids), rec, export_key))
    return rec.raw, export_key.raw

#  This function initiates a new OPAQUE session, is the same as the
#  function defined in the paper with the name usrSession.
#
#  @param [in] pwdU - users input password
#  @param [in] pwdU_len - length of the users password
#  @param [out] sec - private context, it is essential that the memory
#       allocate for this buffer be **OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len**.
#       The User should protect the sec value (e.g. with sodium_mlock())
#       until opaque_RecoverCredentials.
#  @param [out] pub - the message to be sent to the server
#  @return the function returns 0 if everything is correct
#int opaque_CreateCredentialRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);
def CreateCredentialRequest(pwdU):
    if not pwdU:
        raise ValueError("invalid parameter")

    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN+len(pwdU))
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    opaquelib.opaque_CreateCredentialRequest(pwdU, len(pwdU), sec, pub)
    return pub.raw, sec.raw

#  This is the same function as defined in the paper with name
#  srvSession name. This function runs on the server and
#  receives the output pub from the user running opaque_CreateCredentialRequest(),
#  furthermore the server needs to load the user record created when
#  registering the user with opaque_Register() or
#  opaque_StoreUserRecord(). These input parameters are
#  transformed into a secret/shared session key sk and a response resp
#  to be sent back to the user.
#  @param [in] pub - the pub output of the opaque_CreateCredentialRequest()
#  @param [in] rec - the recorded created during "registration" and stored by the server
#  @param [in] ids - the id if the client and server
#  @param [in] infos - various extra (unspecified) protocol information as recommended by the rfc.
#  @param [out] resp - servers response to be sent to the client where
#  it is used as input into opaque_RecoverCredentials() - caller must allocate including envU_len: e.g.:
#  uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] sec - the current context necessary for the explicit
#  authentication of the user in opaque_UserAuth(). This
#  param is optional if no explicit user auth is necessary it can be
#  set to NULL
#  @return the function returns 0 if everything is correct
#int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], uint8_t *sk, uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);
def CreateCredentialResponse(pub, rec, cfg, ids, infos):
    if None in (pub, rec):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_USER_SESSION_PUBLIC_LEN: raise ValueError("invalid pub param")
    envU_len = envelope_len(cfg, ids)
    if len(rec) != OPAQUE_USER_RECORD_LEN+envU_len: raise ValueError("invalid rec param")

    resp = ctypes.create_string_buffer(OPAQUE_SERVER_SESSION_LEN+envU_len)
    sk = ctypes.create_string_buffer(OPAQUE_SHARED_SECRETBYTES)
    sec = ctypes.create_string_buffer(OPAQUE_SERVER_AUTH_CTX_LEN)
    __check(opaquelib.opaque_CreateCredentialResponse(pub, rec, ctypes.pointer(ids), ctypes.pointer(infos) if infos else None, resp, sk, sec))
    return resp.raw, sk.raw, sec.raw

#  This is the same function as defined in the paper with the
#  usrSessionEnd name. It is run by the user and receives as input the
#  response from the previous server opaque_CreateCredentialResponse()
#  function as well as the sec value from running the
#  opaque_CreateCredentialRequest() function that initiated this
#  instantiation of this protocol, All these input parameters are
#  transformed into a shared/secret session key pk, which should be
#  the same as the one calculated by the
#  opaque_CreateCredentialResponse() function.
#
#  @param [in] resp - the response sent from the server running opaque_CreateCredentialResponse()
#  @param [in] sec - the private sec output of the client initiating
#  this instantiation of this protocol using opaque_CreateCredentialRequest()
#  @param [in] pkS - if cfg.pkS == NotPackaged pkS *must* be supplied here, otherwise it must be NULL
#  @param [in] cfg - the configuration of the envelope secret and cleartext part
#  @param [in] infos - various extra (unspecified) protocol information
#  as recommended by the rfc
#  @param [in/out] ids - if ids were packed in the envelope - as given by
#  the cfg param -, they are returned in this struct - if either
#  cfg.idS or cfg.idU is NotPackaged, then the according value must be
#  set in this struct before calling opaque_RecoverCredentials
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] authU - the authentication code to be sent to the server
#  in case explicit user authentication is required
#  @param [out] export_key - key used to encrypt/authenticate extra
#  material not stored directly in the envelope
#  @return the function returns 0 if the protocol is executed correctly
#int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/], const uint8_t pkS[crypto_scalarmult_BYTES], const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t *sk, uint8_t authU[crypto_auth_hmacsha256_BYTES], uint8_t export_key[crypto_hash_sha256_BYTES]);
def RecoverCredentials(resp, sec, cfg, infos, pkS=None, ids=None):
    if None in (resp, sec):
        raise ValueError("invalid parameter")
    if len(resp) <= OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid resp param")
    if len(sec) <= OPAQUE_USER_SESSION_SECRET_LEN: raise ValueError("invalid sec param")

    sk = ctypes.create_string_buffer(OPAQUE_SHARED_SECRETBYTES)
    authU = ctypes.create_string_buffer(crypto_auth_hmacsha256_BYTES)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)

    if cfg.pkS == NotPackaged and not pkS:
        raise ValueError("pkS cannot be None if cfg.pkS is NotPackaged.")

    ids1 = Ids()
    if cfg.idU == NotPackaged:
        if not ids:
            raise ValueError("ids cannot be None if cfg.idU is NotPackaged.")
        if not ids.idU:
            raise ValueError("ids.idU cannot be None if cfg.idU is NotPackaged.")
        ids1.idU=ids.idU
        ids1.idU_len=ids.idU_len
    else:
        ids1.idU=ctypes.cast(ctypes.create_string_buffer(1024), ctypes.c_char_p)
        ids1.idU_len=1024

    if cfg.idS == NotPackaged:
        if not ids:
            raise ValueError("ids cannot be None if cfg.idS is NotPackaged.")
        if not ids.idS:
            raise ValueError("ids.idU cannot be None if cfg.idS is NotPackaged.")
        ids1.idS=ids.idS
        ids1.idS_len=ids.idS_len
    else:
        ids1.idS=ctypes.cast(ctypes.create_string_buffer(1024), ctypes.c_char_p)
        ids1.idS_len=1024

    __check(opaquelib.opaque_RecoverCredentials(resp, sec, pkS, ctypes.pointer(cfg), ctypes.pointer(infos) if infos else None, ctypes.pointer(ids1), sk, authU, export_key))
    return sk.raw, authU.raw, export_key.raw, ids1

#  Explicit User Authentication.
#
#  This is a function not explicitly specified in the original paper. In the
#  ietf cfrg draft authentication is done using a hmac of the session
#  transcript with different keys coming out of a hkdf after the key
#  exchange.
#
#  @param [in] sec - the context returned by opaque_CreateCredentialResponse()
#  @param [in] authU is the authentication token sent by the user.
#  @return the function returns 0 if the hmac verifies correctly.
#int opaque_UserAuth(const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos);
def UserAuth(sec, authU):
    if None in (sec, authU):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_SERVER_AUTH_CTX_LEN: raise ValueError("invalid sec param")
    if len(authU) != crypto_auth_hmacsha256_BYTES: raise ValueError("invalid authU param")

    __check(opaquelib.opaque_UserAuth(sec, authU))

#  Alternative user initialization, user registration as specified by the RFC

#  The paper originally proposes a very simple 1 shot interface for
#  registering a new "user", however this has the drawback that in
#  that case the users secrets and its password are exposed in
#  cleartext at registration to the server. There is an alternative 4
#  message registration protocol specified by the rfc, which avoids
#  the exposure of the secrets and the password to the server which
#  can be instantiated by following for registration functions.


#  Initial step to start registering a new user/client with the server.
#  The user inputs its password pwdU, and receives a secret context sec
#  and a blinded value M as output. sec should be protected until
#  step 3 of this registration protocol and the value M should be
#  passed to the server.
#  @param [in] pwdU - the users password
#  @param [in] pwdU_len - length of the users password
#  @param [out] sec - a secret context needed for the 3rd step in this
#  registration protocol - this needs to be protected and sanitized
#  after usage.
#  @param [out] M - the blinded hashed password as per the OPRF,
#  this needs to be sent to the server together with any other
#  important and implementation specific info such as user/client id,
#  envelope configuration etc.
#  @return the function returns 0 if everything is correct.
#int opaque_CreateRegistrationRequest(const uint8_t *pwdU, const uint16_t pwdU_len, uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len], uint8_t M[crypto_core_ristretto255_BYTES]);
def CreateRegistrationRequest(pwdU):
    if not pwdU:
        raise ValueError("invalid parameter")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_USER_SEC_LEN+len(pwdU))
    M = ctypes.create_string_buffer(crypto_core_ristretto255_BYTES)
    opaquelib.opaque_CreateRegistrationRequest(pwdU, len(pwdU), sec, M)
    return sec.raw, M.raw

#  Server evaluates OPRF and creates a user-specific public/private keypair
#
#  The server receives M from the users invocation of its
#  opaque_CreateRegistrationRequest() function, it outputs a value sec
#  which needs to be protected until step 4 by the server. This
#  function also outputs a value pub which needs to be passed to the
#  user.
#  @param [in] M - the blinded password as per the OPRF.
#  @param [out] sec - the private key and the OPRF secret of the server.
#  @param [out] pub - the evaluated OPRF and pubkey of the server to
#  be passed to the client into opaque_FinalizeRequest()
#  @return the function returns 0 if everything is correct.
#int opaque_CreateRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def CreateRegistrationResponse(M):
    if not M:
        raise ValueError("invalid parameter")
    if len(M) != crypto_core_ristretto255_BYTES: raise ValueError("invalid M param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(opaquelib.opaque_CreateRegistrationResponse(M, sec, pub))
    return sec.raw, pub.raw

#  2nd step of registration: Server evaluates OPRF - Global Server Key Version
#
#  This function is essentially the same as
#  opaque_CreateRegistrationResponse(), except this function does not
#  generate a per-user long-term key, but instead expects the servers
#  to supply a long-term pubkey as a parameter, this might be one
#  unique global key, or it might be a per-user key derived from a
#  server secret.
#
#  This function is called CreateRegistrationResponse in the rfc.
#  The server receives M from the users invocation of its
#  opaque_CreateRegistrationRequest() function, it outputs a value sec
#  which needs to be protected until step 4 by the server. This
#  function also outputs a value pub which needs to be passed to the
#  user.
#  @param [in] M - the blinded password as per the OPRF.
#  @param [in] pkS - the servers long-term pubkey
#  @param [out] sec - the private key and the OPRF secret of the server.
#  @param [out] pub - the evaluated OPRF and pubkey of the server to
#  be passed to the client into opaque_FinalizeRequest()
#  @return the function returns 0 if everything is correct.
#int opaque_Create1kRegistrationResponse(const uint8_t M[crypto_core_ristretto255_BYTES], const uint8_t pkS[crypto_scalarmult_BYTES], uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def Create1kRegistrationResponse(M, pkS):
    if None in  (M, pkS):
        raise ValueError("invalid parameter")
    if len(M) != crypto_core_ristretto255_BYTES: raise ValueError("invalid M param")
    if len(pkS) != crypto_scalarmult_BYTES: raise ValueError("invalid pkS param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(opaquelib.opaque_Create1kRegistrationResponse(M, pkS, sec, pub))
    return sec.raw, pub.raw

#  Client finalizes registration by concluding the OPRF, generating
#  its own keys and enveloping it all.
#
#  This function is called FinalizeRequest in the rfc.  This function
#  is run by the user, taking as input the context sec that was an
#  output of the user running opaque_CreateRegistrationRequest(), and the
#  output pub from the server of opaque_CreateRegistrationResponse().
#
#  @param [in] sec - output from opaque_CreateRegistrationRequest(),
#  should be sanitized after usage.
#  @param [in] pub - response from the server running
#  opaque_CreateRegistrationResponse()
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
#int opaque_FinalizeRequest(const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/], const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/], uint8_t export_key[crypto_hash_sha256_BYTES]);
def FinalizeRequest(sec, pub, cfg, ids):
    if None in (sec, pub, cfg, ids):
        raise ValueError("invalid parameter")
    if len(sec) <= OPAQUE_REGISTER_USER_SEC_LEN: raise ValueError("invalid sec param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")

    envU_len = envelope_len(cfg, ids)
    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN+envU_len)
    export_key = ctypes.create_string_buffer(crypto_hash_sha256_BYTES)
    __check(opaquelib.opaque_FinalizeRequest(sec, pub, ctypes.pointer(cfg), ctypes.pointer(ids), rec, export_key))
    return rec.raw, export_key.raw

#  Final Registration step - server adds own info to the record to be stored.
#
#  The rfc does not explicitly specify this function.
#  The server combines the sec value from its run of its
#  opaque_CreateRegistrationResponse() function with the rec output of
#  the users opaque_FinalizeRequest() function, creating the
#  final record, which should be the same as the output of the 1-step
#  storePwdFile() init function of the paper. The server should save
#  this record in combination with a user id and/or sid value as
#  suggested in the paper.
#
#  @param [in] sec - the private value of the server running
#  opaque_CreateRegistrationResponse() in step 2 of the registration
#  protocol
#  @param [in/out] rec - input the record from the client running
#  opaque_FinalizeRequest() - output the final record to be
#  stored by the server this is a pointer to memory allocated by the
#  caller, and must be large enough to hold the record and take into
#  account the variable length of idU and idS in case these are
#  included in the envelope.
#void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
def StoreUserRecord(sec, rec):
    if None in (sec, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(rec) <= OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    opaquelib.opaque_StoreUserRecord(sec, rec)
    return rec

#  Final Registration step Global Server Key Version - server adds own info to the record to be stored.
#
#  this function essentially does the same as
#  opaque_StoreUserRecord() except that it expects the server
#  to provide its secret key. This server secret key might be one
#  global secret key used for all users, or it might be a per-user
#  unique key derived from a secret server seed.
#
#  The rfc does not explicitly specify this function.
#  The server combines the sec value from its run of its
#  opaque_CreateRegistrationResponse() function with the rec output of
#  the users opaque_FinalizeRequest() function, creating the
#  final record, which should be the same as the output of the 1-step
#  storePwdFile() init function of the paper. The server should save
#  this record in combination with a user id and/or sid value as
#  suggested in the paper.
#
#  @param [in] sec - the private value of the server running
#  opaque_CreateRegistrationResponse() in step 2 of the registration
#  protocol
#  @param [in] skS - the servers long-term private key
#  @param [in/out] rec - input the record from the client running
#  opaque_FinalizeRequest() - output the final record to be
#  stored by the server this is a pointer to memory allocated by the
#  caller, and must be large enough to hold the record and take into
#  account the variable length of idU and idS in case these are
#  included in the envelope.
#void opaque_Store1kUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t skS[crypto_scalarmult_SCALARBYTES], uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
def Store1kUserRecord(sec, skS, rec):
    if None in (sec, skS, rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(skS) != crypto_scalarmult_SCALARBYTES: raise ValueError("invalid skS param")
    if len(rec) <= OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    opaquelib.opaque_Store1kUserRecord(sec, skS, rec)
    return rec

#  This helper function calculates the length of one part, either the secret
#  part (SecEnv) or the cleartext part (ClrEnv), of the envelope in bytes.
#
#  @param [in] cfg - the configuration of the envelope's secret and cleartext
#  parts
#  @param [in] ids - the IDs of the user and server that are only needed if we
#  pack one of the IDs into the envelope as given by the cfg param
#  @param [in] type - InSecEnv|InClrEnv - NotPackaged is useless
#
#  @return the function returns the size of the envelope part specified by the
#  type param in bytes.
#size_t opaque_package_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, const Opaque_PkgTarget type);
def package_len(cfg, ids, type):
    return opaquelib.opaque_package_len(ctypes.pointer(cfg), ctypes.pointer(ids), type)

#  This helper function calculates the length of the envelope in bytes.
#
#  The returned size should be OPAQUE_ENVELOPE_META_LEN + SecEnv_len +
#  ClrEnv_len.
#
#  @param [in] cfg - the configuration of the envelope's secret and cleartext
#  parts
#  @param [in] ids - the IDs of the user and server that are only needed if we
#  pack one of the IDs into the envelope as given by the cfg param
#
#  @return the function returns the size of the envelope.
#size_t opaque_envelope_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids);
def envelope_len(cfg, ids):
    return opaquelib.opaque_envelope_len(ctypes.pointer(cfg), ctypes.pointer(ids))
