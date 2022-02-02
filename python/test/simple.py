#!/usr/bin/env python

import opaque
import pysodium
from pysodium import (crypto_scalarmult_SCALARBYTES)

pwdU=b"simple guessable dictionary password"

# wrap the IDs into an opaque.Ids struct:
ids=opaque.Ids("user", "server")

context = "pyopaque-v0.2.0"

# one step registration - only specified in the original paper, not
# specified by ietf cfrg draft has the benefit that the supplied
# password can be checked on the server for password rules
# (e.g. occurence in common password lists), has the drawback that the
# password is exposed to the server.
rec, export_key = opaque.Register(pwdU, ids, skS=None)
# user initiates a credential request
pub, secU = opaque.CreateCredentialRequest(pwdU)

# server responds to credential request
resp, sk, authU0 = opaque.CreateCredentialResponse(pub, rec, ids, context)

# user recovers its credentials from the servers response
sk1, authU, export_key1 = opaque.RecoverCredentials(resp, secU, context, ids)

# server authenticates user
opaque.UserAuth(authU0, authU)

assert export_key==export_key1, "export_key must equal export_key1."
assert sk==sk1, "sk must equal sk1."

# registering as specified in the ietf cfrg draft

# user create a registration request
secU, request = opaque.CreateRegistrationRequest(pwdU)

# server responds to the registration request
secS, pub = opaque.CreateRegistrationResponse(request)

# user finalizes the registration using the response from the server
reg_rec, export_key = opaque.FinalizeRequest(secU, pub, ids)

# server finalizes the user record
rec = opaque.StoreUserRecord(secS, reg_rec)

# same steps as above, 1. user initiates credential request
pub, secU = opaque.CreateCredentialRequest(pwdU)

# 2. server responds to credential request
resp, sk, secS = opaque.CreateCredentialResponse(pub, rec, ids, context)

# 3. user recovers its credentials from the server ressponse
sk1, authU, export_key1 = opaque.RecoverCredentials(resp, secU, context, ids)

# 4. server authenicates user
opaque.UserAuth(secS, authU)

assert export_key==export_key1, "export_key must equal export_key1."
assert sk==sk1, "sk must equal sk1."

def register_with_global_server_key():
    pwdU=b"simple guessable dictionary password"
    context = "pyopaque-v0.2.0"
    ids=opaque.Ids("user", "server")
    skS=pysodium.randombytes(crypto_scalarmult_SCALARBYTES)
    # Uncomment the following if you compiled libopaque with -DNORANDOM -DTRACE and
    # want the same output as register_with_global_server_key in
    # src/tests/opaque-test.c. Also see a_randombytes in src/common.c.
    #skS=ctypes.create_string_buffer(crypto_scalarmult_SCALARBYTES)
    #for i in range(0, 32):
    #    ctypes.memset(ctypes.addressof(skS) + i, i, 1)

    secU, M = opaque.CreateRegistrationRequest(pwdU)
    secS, pub = opaque.CreateRegistrationResponse(M, skS)
    rec, export_key = opaque.FinalizeRequest(secU, pub, ids)
    rec = opaque.StoreUserRecord(secS, rec)
    pub, secU = opaque.CreateCredentialRequest(pwdU)
    resp, sk, secS = opaque.CreateCredentialResponse(pub, rec, ids, context)
    sk1, authU, export_key1 = opaque.RecoverCredentials(resp, secU, context, ids)
    opaque.UserAuth(secS, authU)
    assert export_key==export_key1, "export_key must equal export_key1."
    assert sk==sk1, "sk must equal sk1."

register_with_global_server_key()

print("test ok")
