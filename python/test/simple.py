#!/usr/bin/env python

import opaque

pwdU=b"simple guessable dictionary password"

# wrap the IDs into an opaque.Ids struct:
ids=opaque.Ids("user", "server")

# wrap the envelope confing into an opaque PkgConfig struct
cfg=opaque.PkgConfig()
cfg.skU=opaque.InSecEnv
cfg.pkU=opaque.InSecEnv
cfg.pkS=opaque.InSecEnv
cfg.idU=opaque.InSecEnv
cfg.idS=opaque.InSecEnv

# create an App_Infos structure, but we do not use it in our examples
# below, we pass None where infos would be be used
infos=opaque.App_Infos()

# one step registration - only specified in the original paper, not
# specified by ietf cfrg draft has the benefit that the supplied
# password can be checked on the server for password rules
# (e.g. occurence in common password lists), has the drawback that the
# password is exposed to the server.
rec, export_key = opaque.Register(pwdU, cfg, ids, skS=None)

# user initiates a credential request
pub, secU = opaque.CreateCredentialRequest(pwdU)

# server responds to credential request
resp, sk, secS = opaque.CreateCredentialResponse(pub, rec, cfg, ids, None)

# user recovers its credentials from the servers response
sk1, authU, export_key1, ids1 = opaque.RecoverCredentials(resp, secU, cfg, None, pkS=None)

# server authenticates user
opaque.UserAuth(secS, authU, None)

assert ids.idU==ids1.idU, "The recovered user ID (ids1.idU) must equal the registration user ID (ids.idU)."
assert ids.idS==ids1.idS, "The recovered server ID (ids1.idS) must equal the registration server ID (ids.idS)."
assert export_key==export_key1, "export_key must equal export_key1."
assert sk==sk1, "sk must equal sk1."

# registering as specified in the ietf cfrg draft

# user create a registration request
secU, M = opaque.CreateRegistrationRequest(pwdU)

# server responds to the registration request
secS, pub = opaque.CreateRegistrationResponse(M)

# user finalizes the registration using the response from the server
rec, export_key = opaque.FinalizeRequest(secU, pub, cfg, ids)

# server finalizes the user record
rec = opaque.StoreUserRecord(secS, rec)

# same steps as above, 1. user initiates credential request
pub, secU = opaque.CreateCredentialRequest(pwdU)

# 2. server responds to credential request
resp, sk, secS = opaque.CreateCredentialResponse(pub, rec, cfg, ids, None)

# 3. user recovers its credentials from the server ressponse
sk1, authU, export_key1, ids1 = opaque.RecoverCredentials(resp, secU, cfg, None, pkS=None)

# 4. server authenicates user
opaque.UserAuth(secS, authU, None)

assert ids.idU==ids1.idU, "The recovered user ID (ids1.idU) must equal the registration user ID (ids.idU)."
assert ids.idS==ids1.idS, "The recovered server ID (ids1.idS) must equal the registration server ID (ids.idS)."
assert export_key==export_key1, "export_key must equal export_key1."
assert sk==sk1, "sk must equal sk1."

print("test ok")
