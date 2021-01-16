#!/usr/bin/env python

import opaque

pwd=b"simple guessable dictionary password"

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
rec, export_key0 = opaque.Register(pwd,cfg,ids,skS=None)

# user initiates a credential request
pub, sec = opaque.CreateCredentialRequest(pwd)

# server responds to credential request
resp, sks, ctx = opaque.CreateCredentialResponse(pub, rec, cfg, ids, None)

# user recovers its credentials from the servers response
sku, auth, export_key1, ids = opaque.RecoverCredentials(resp, sec, cfg, None, pkS=None)

# server authenticates user
opaque.UserAuth(ctx, auth, None)

# registering as specified in the ietf cfrg draft

# user create a registration request
ctx, alpha = opaque.CreateRegistrationRequest(pwd)

# server responds to the registration request
sec, pub = opaque.CreateRegistrationResponse(alpha)

# user finalizes the registration using the response from the server
rec, export_key3 = opaque.FinalizeRequest(ctx, pub, cfg, ids)

# server finalizes the user record
rec = opaque.StoreUserRecord(sec, rec)

# same steps as above, 1. user initiates credential request
pub, sec = opaque.CreateCredentialRequest(pwd)

# 2. server responds to credential request
resp, sks, ctx = opaque.CreateCredentialResponse(pub, rec, cfg, ids, None)

# 3. user recovers its credentials from the server ressponse
sku, auth, export_key4, ids = opaque.RecoverCredentials(resp, sec, cfg, None, pkS=None)

# 4. server authenicates user
opaque.UserAuth(ctx, auth, None)

print("test ok")
