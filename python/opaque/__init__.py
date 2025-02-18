"""Wrapper for libopaque library

   SPDX-FileCopyrightText: 2018-21, Marsiske Stefan
   SPDX-License-Identifier: LGPL-3.0-or-later

   Copyright (c) 2018-2021, Marsiske Stefan.
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
from ctypes import c_uint16

opaquelib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('opaque') or ctypes.util.find_library('libopaque'))

if not opaquelib._name:
    raise ValueError('Unable to find libopaque')

from pysodium import (crypto_core_ristretto255_SCALARBYTES, crypto_scalarmult_SCALARBYTES,
                      crypto_core_ristretto255_BYTES, crypto_scalarmult_BYTES,
                      crypto_core_ristretto255_BYTES, crypto_hash_sha512_BYTES,
                      sodium_version_check)
# todo what is this?
if sodium_version_check(1,0,18):
    from pysodium import crypto_auth_hmacsha512_BYTES
else:
    crypto_auth_hmacsha512_BYTES = 64

OPAQUE_SHARED_SECRETBYTES = 64
OPAQUE_NONCE_BYTES = 32
OPAQUE_ENVELOPE_NONCEBYTES = 32

OPAQUE_REGISTRATION_RECORD_LEN = (
    crypto_scalarmult_BYTES+                   # client_public_key
    crypto_hash_sha512_BYTES+                  # masking_key
    OPAQUE_ENVELOPE_NONCEBYTES+                # envelope nonce
    crypto_auth_hmacsha512_BYTES)              # envelope mac

OPAQUE_USER_RECORD_LEN = (
    crypto_core_ristretto255_SCALARBYTES+      # kU
    crypto_scalarmult_SCALARBYTES+             # skS
    OPAQUE_REGISTRATION_RECORD_LEN)

OPAQUE_USER_SESSION_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+            # blinded
    crypto_scalarmult_BYTES+                   # X_u
    OPAQUE_NONCE_BYTES)                        # nonceU

OPAQUE_USER_SESSION_SECRET_LEN = (
    crypto_core_ristretto255_SCALARBYTES+      # r
    crypto_scalarmult_SCALARBYTES+             # x_u
    OPAQUE_NONCE_BYTES+                        # nonceU
    crypto_core_ristretto255_BYTES+            # blinded
    OPAQUE_USER_SESSION_PUBLIC_LEN+            # ke1
    2)                                         # pwdU_len

OPAQUE_SERVER_SESSION_LEN = (
    crypto_core_ristretto255_BYTES+            # Z
    32+                                        # masking_nonce
    crypto_scalarmult_BYTES+                   # server_public_key
    OPAQUE_NONCE_BYTES+                        # nonceS
    crypto_scalarmult_BYTES+                   # X_s
    crypto_auth_hmacsha512_BYTES+              # auth
    OPAQUE_ENVELOPE_NONCEBYTES+                # envelope nonce
    crypto_auth_hmacsha512_BYTES)              # envelope mac

OPAQUE_REGISTER_USER_SEC_LEN = (
    crypto_core_ristretto255_SCALARBYTES+      # r
    2)                                         # pwdU_len

OPAQUE_REGISTER_PUBLIC_LEN = (
    crypto_core_ristretto255_BYTES+            # Z
    crypto_scalarmult_BYTES)                   # pkS

OPAQUE_REGISTER_SECRET_LEN = (
    crypto_scalarmult_SCALARBYTES+             # skS
    crypto_core_ristretto255_SCALARBYTES)      # kU


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
            self.idU=idu.encode("utf8") if isinstance(idu,str) else idu
            self.idU_len=len(self.idU)
        if ids:
            self.idS=ids.encode('utf8') if isinstance(ids,str) else ids
            self.idS_len=len(self.idS)

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
#  @param [in] ids - the ids of the user and server, see Opaque_Ids
#  @param [in] unlink masking key either None or an array, which is
#       is used to make the masking key unique among threshold servers
#  @param [in] the length of the unlink_masking_key array.
#  @param [out] rec - the opaque record the server needs to
#       store. this is a pointer to memory allocated by the caller,
#       and must be large enough to hold the record and take into
#       account the variable length of idU and idS in case these are
#       included in the envelope.
#  @param [out] export_key - optional pointer to pre-allocated (and
#       protected) memory for an extra_key that can be used to
#       encrypt/authenticate additional data.
#  @return the function returns 0 if everything is correct
#int opaque_Register(const uint8_t *pwdU, const uint16_t pwdU_len,
#                    const uint8_t skS[crypto_scalarmult_SCALARBYTES],
#                    const Opaque_Ids *ids,
#                    uint8_t rec[OPAQUE_USER_RECORD_LEN],
#                    uint8_t export_key[crypto_hash_sha512_BYTES]);
def Register(pwdU, ids, skS=None, unlink_masking_key=None):
    if not pwdU:
        raise ValueError("invalid parameter")
    if skS and len(skS) != crypto_scalarmult_SCALARBYTES:
        raise ValueError("invalid skS param")

    pwdU=pwdU.encode("utf8") if isinstance(pwdU,str) else pwdU
    umk_len = len(unlink_masking_key) if unlink_masking_key is not None else 0

    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN)
    export_key = ctypes.create_string_buffer(crypto_hash_sha512_BYTES)
    __check(opaquelib.opaque_Register_core(pwdU, len(pwdU),
                                           skS, ctypes.pointer(ids),
                                           unlink_masking_key, umk_len,
                                           rec, export_key))
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
    pwdU=pwdU.encode("utf8") if isinstance(pwdU,str) else pwdU

    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN+len(pwdU))
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    opaquelib.opaque_CreateCredentialRequest(pwdU, len(pwdU), sec, pub)
    return pub.raw, sec.raw

def CreateCredentialRequest_oprf(pwdU):
    if not pwdU:
        raise ValueError("invalid parameter")
    pwdU=pwdU.encode("utf8") if isinstance(pwdU,str) else pwdU

    sec = ctypes.create_string_buffer(OPAQUE_USER_SESSION_SECRET_LEN+len(pwdU))
    pub = ctypes.create_string_buffer(OPAQUE_USER_SESSION_PUBLIC_LEN)
    opaquelib.opaque_CreateCredentialRequest_oprf(pwdU, len(pwdU), sec, pub)
    return pub.raw, sec.raw

def CreateCredentialRequest_ake(pwdU, sec, pub):
    if not pwdU:
        raise ValueError("invalid parameter")
    pwdU=pwdU.encode("utf8") if isinstance(pwdU,str) else pwdU

    sec = ctypes.create_string_buffer(sec, len(sec))
    pub = ctypes.create_string_buffer(pub, len(pub))
    opaquelib.opaque_CreateCredentialRequest_ake(len(pwdU), sec, pub)
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
#  @param [in] ctx - a context of this instantiation of this protocol, e.g. "AppABCv12.34"
#  @param [in] ctx_len - a context of this instantiation of this protocol
#  @param [out] resp - servers response to be sent to the client where
#  it is used as input into opaque_RecoverCredentials()
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] sec - the current context necessary for the explicit
#  authentication of the user in opaque_UserAuth(). This
#  param is optional if no explicit user auth is necessary it can be
#  set to NULL
#  @return the function returns 0 if everything is correct
#int opaque_CreateCredentialResponse(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
#                                    const uint8_t rec[OPAQUE_USER_RECORD_LEN],
#                                    const Opaque_Ids *ids,
#                                    const uint8_t *ctx, const uint16_t ctx_len,
#                                    uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
#                                    uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
#                                    uint8_t authU[crypto_auth_hmacsha512_BYTES]);
def CreateCredentialResponse(pub, rec, ids, ctx):
    if None in (pub, rec):
        raise ValueError("invalid parameter")
    if len(pub) != OPAQUE_USER_SESSION_PUBLIC_LEN: raise ValueError("invalid pub param")
    if len(rec) != OPAQUE_USER_RECORD_LEN: raise ValueError("invalid rec param")

    ctx=ctx.encode("utf8") if isinstance(ctx,str) else ctx

    resp = ctypes.create_string_buffer(OPAQUE_SERVER_SESSION_LEN)
    sk = ctypes.create_string_buffer(OPAQUE_SHARED_SECRETBYTES)
    sec = ctypes.create_string_buffer(crypto_auth_hmacsha512_BYTES)
    __check(opaquelib.opaque_CreateCredentialResponse(pub, rec, ctypes.pointer(ids), ctx, len(ctx), resp, sk, sec))
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
#  @param [in] infos - various extra (unspecified) protocol information
#  as recommended by the rfc
#  @param [in] ctx - a context of this instantiation of this protocol, e.g. "AppABCv12.34"
#  @param [in] ctx_len - a context of this instantiation of this protocol
#  @param [in] ids - The ids of the server/client in case they are not the default.
#  @param [out] sk - the shared secret established between the user & server
#  @param [out] authU - the authentication code to be sent to the server
#  in case explicit user authentication is required
#  @param [out] export_key - key used to encrypt/authenticate extra
#  material not stored directly in the envelope
#  @return the function returns 0 if the protocol is executed correctly
#int opaque_RecoverCredentials(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
#                              const uint8_t *sec/*[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len]*/,
#                              const uint8_t *ctx, const uint16_t ctx_len,
#                              const Opaque_Ids *ids,
#                              uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
#                              uint8_t authU[crypto_auth_hmacsha512_BYTES],
#                              uint8_t export_key[crypto_hash_sha512_BYTES]);

def RecoverCredentials(resp, sec, ctx, ids=None, beta=None, unlink_masking_key=None):
    if None in (resp, sec):
        raise ValueError("invalid parameter")
    if len(resp) != OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid resp param")
    if len(sec) <= OPAQUE_USER_SESSION_SECRET_LEN: raise ValueError("invalid sec param")
    if beta is not None and len(beta) != crypto_core_ristretto255_BYTES: raise ValueError("invalid beta parameter")

    ctx=ctx.encode("utf8") if isinstance(ctx,str) else ctx

    sk = ctypes.create_string_buffer(OPAQUE_SHARED_SECRETBYTES)
    authU = ctypes.create_string_buffer(crypto_auth_hmacsha512_BYTES)
    export_key = ctypes.create_string_buffer(crypto_hash_sha512_BYTES)

    if ids is None: ids = Ids()
    umk_len = len(unlink_masking_key) if unlink_masking_key is not None else 0

    __check(opaquelib.opaque_RecoverCredentials_extBeta(resp, sec,
                                                        ctx, len(ctx),
                                                        ctypes.pointer(ids),
                                                        beta,
                                                        unlink_masking_key, umk_len,
                                                        sk, authU, export_key))
    return sk.raw, authU.raw, export_key.raw

#int opaque_CombineCredentialResponses(const uint8_t t, const uint8_t n,
#                                      const uint8_t ke2s[n][OPAQUE_SERVER_SESSION_LEN],
#                                      uint8_t beta[crypto_scalarmult_ristretto255_BYTES]);
def CombineCredentialResponses(t, n, indexes, ke2s):
    if len(ke2s) != n * OPAQUE_SERVER_SESSION_LEN: raise ValueError("invalid ke2s size")
    if t<2: raise ValueError("invalid t, must be greater than 1")
    if t>127: raise ValueError("invalid t, must be less than 128")
    if n<t: raise ValueError("invalid n, must be greater than t")
    if n>128: raise ValueError("invalid n, must be less than 129")

    beta = ctypes.create_string_buffer(crypto_core_ristretto255_BYTES)
    __check(opaquelib.opaque_CombineCredentialResponses(t, n, indexes, ke2s, beta))
    return beta.raw

#  Explicit User Authentication.
#
#  This is a function not explicitly specified in the original paper. In the
#  irtf cfrg draft authentication is done using a hmac of the session
#  transcript with different keys coming out of a hkdf after the key
#  exchange.
#
#  @param [in] authU0 - the authU value returned by opaque_CreateCredentialResponse()
#  @param [in] authU is the authentication token sent by the user.
#  @return the function returns 0 if the hmac verifies correctly.
#int opaque_UserAuth(const uint8_t authU0[crypto_auth_hmacsha512_BYTES], const uint8_t authU[crypto_auth_hmacsha512_BYTES]);
def UserAuth(authU0, authU):
    if None in (authU0, authU):
        raise ValueError("invalid parameter")
    if len(authU0) != crypto_auth_hmacsha512_BYTES: raise ValueError("invalid authU0 param")
    if len(authU) != crypto_auth_hmacsha512_BYTES: raise ValueError("invalid authU param")

    __check(opaquelib.opaque_UserAuth(authU0, authU))

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
#  @param [out] request - the blinded hashed password as per the OPRF,
#  this needs to be sent to the server together with any other
#  important and implementation specific info such as user/client id,
#  envelope configuration etc.
#  @return the function returns 0 if everything is correct.
#int opaque_CreateRegistrationRequest(const uint8_t *pwdU,
#                                     const uint16_t pwdU_len,
#                                     uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
#                                     uint8_t request[crypto_core_ristretto255_BYTES]);
def CreateRegistrationRequest(pwdU):
    if not pwdU:
        raise ValueError("invalid parameter")

    pwdU=pwdU.encode("utf8") if isinstance(pwdU,str) else pwdU

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_USER_SEC_LEN+len(pwdU))
    request = ctypes.create_string_buffer(crypto_core_ristretto255_BYTES)
    __check(opaquelib.opaque_CreateRegistrationRequest(pwdU, len(pwdU), sec, request))
    return sec.raw, request.raw

#  Server evaluates OPRF and creates a user-specific public/private keypair
#
#  The server receives M from the users invocation of its
#  opaque_CreateRegistrationRequest() function, it outputs a value sec
#  which needs to be protected until step 4 by the server. This
#  function also outputs a value pub which needs to be passed to the
#  user.
#  @param [in] request - the blinded password as per the OPRF.
#  @param [in] skS - the servers long-term private key, optional, set
#  to NULL if you want this implementation to generate a unique key
#  for this record.
#  @param [out] sec - the private key and the OPRF secret of the server.
#  @param [out] pub - the evaluated OPRF and pubkey of the server to
#  be passed to the client into opaque_FinalizeRequest()
#  @return the function returns 0 if everything is correct.
#int opaque_CreateRegistrationResponse(const uint8_t request[crypto_core_ristretto255_BYTES],
#                                      const uint8_t skS[crypto_scalarmult_SCALARBYTES],
#                                      uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
#                                      uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
def CreateRegistrationResponse(request, skS=None):
    if not request:
        raise ValueError("invalid parameter")
    if len(request) != crypto_core_ristretto255_BYTES: raise ValueError("invalid request param")
    if skS is not None and len(skS) != crypto_scalarmult_SCALARBYTES: raise ValueError("invalid skS param")

    sec = ctypes.create_string_buffer(OPAQUE_REGISTER_SECRET_LEN)
    pub = ctypes.create_string_buffer(OPAQUE_REGISTER_PUBLIC_LEN)
    __check(opaquelib.opaque_CreateRegistrationResponse(request, skS, sec, pub))
    return sec.raw, pub.raw

#int opaque_CombineRegistrationResponses(const uint8_t t, const uint8_t n,
#                                         const uint8_t _pubs[n][OPAQUE_REGISTER_PUBLIC_LEN],
#                                         uint8_t beta[crypto_scalarmult_ristretto255_BYTES]) {
def CombineRegistrationResponses(t, n, pubs):
    if len(pubs) != n * OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pubs size")
    if t<2: raise ValueError("invalid t, must be greater than 1")
    if t>127: raise ValueError("invalid t, must be less than 128")
    if n<=t: raise ValueError("invalid n, must be greater than t")
    if n>128: raise ValueError("invalid n, must be less than 129")
    __check(opaquelib.opaque_CombineRegistrationResponses(t, n, pubs))

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
#  @param [in] ids
#  @param [out] reg_ rec - the opaque registration record containing
#  the users data.
#  @param [out] export_key - key used to encrypt/authenticate extra
#  material not stored directly in the envelope
#
#  @return the function returns 0 if everything is correct.
#int opaque_FinalizeRequest(const uint8_t *sec/*[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len]*/,
#                           const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
#                           const Opaque_Ids *ids,
#                           const uint8_t *unlink_masking_key, const size_t umk_len,
#                           uint8_t reg_rec[OPAQUE_REGISTRATION_RECORD_LEN],
#                           uint8_t export_key[crypto_hash_sha512_BYTES]);
def FinalizeRequest(sec, pub, ids, unlink_masking_key=None):
    if None in (sec, pub, ids):
        raise ValueError("invalid parameter")
    if len(sec) <= OPAQUE_REGISTER_USER_SEC_LEN: raise ValueError("invalid sec param")
    if len(pub) != OPAQUE_REGISTER_PUBLIC_LEN: raise ValueError("invalid pub param")

    umk_len = len(unlink_masking_key) if unlink_masking_key is not None else 0

    rec = ctypes.create_string_buffer(OPAQUE_REGISTRATION_RECORD_LEN)
    export_key = ctypes.create_string_buffer(crypto_hash_sha512_BYTES)
    __check(opaquelib.opaque_FinalizeRequest_core(sec, pub, ctypes.pointer(ids),
                                                  unlink_masking_key, umk_len,
                                                  rec, export_key))
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
#  @param [in] reg_rec - the registration record from the client running
#  opaque_FinalizeRequest()
#  @param [out] rec - the final record to be stored by the server.
#void opaque_StoreUserRecord(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
#                            const uint8_t recU[OPAQUE_REGISTRATION_RECORD_LEN],
#                            uint8_t rec[OPAQUE_USER_RECORD_LEN]);
def StoreUserRecord(sec, reg_rec):
    if None in (sec, reg_rec):
        raise ValueError("invalid parameter")
    if len(sec) != OPAQUE_REGISTER_SECRET_LEN: raise ValueError("invalid sec param")
    if len(reg_rec) != OPAQUE_REGISTRATION_RECORD_LEN: raise ValueError("invalid reg_rec param")
    rec = ctypes.create_string_buffer(OPAQUE_USER_RECORD_LEN)
    opaquelib.opaque_StoreUserRecord(sec, reg_rec, rec)
    return rec.raw
