#!/usr/bin/env ruby

require './opaque.so'

include Opaque

cfg = [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv]
idU = "idU"
idS = "idS"
pwd = "pwd"

# create a record "directly on the server"
rec, export_key = register(pwd, idU, idS, cfg)

# client initiates session
secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, cfg)

# client recovers keys, sets up session
skU, authU, export_keyU, idUc, idSc = recover_credentials(resp, secU, cfg)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU
raise "fail" unless idU == idUc
raise "fail" unless idS == idSc

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)

# start 4 step registration
m, secU = create_registration_request(pwd)

secS, pub = create_registration_response(m)

rec, export_key = finalize_request(secU, pub, idU, idS, cfg)

rec = store_user_record(secS, rec)

secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, cfg)

# client recovers keys, sets up session
skU, authU, export_keyU, idUc, idSc = recover_credentials(resp, secU, cfg)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU
raise "fail" unless idU == idUc
raise "fail" unless idS == idSc

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)

# start 4 step registration with 1k server setup
pkS, skS = create_server_keys()

m, secU = create_registration_request(pwd)

secS, pub = create_1k_registration_response(m, pkS)

rec, export_key = finalize_request(secU, pub, idU, idS, cfg)

rec = store_1k_user_record(secS, skS, rec)

secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, cfg)

# client recovers keys, sets up session
skU, authU, export_keyU, idUc, idSc = recover_credentials(resp, secU, cfg)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU
raise "fail" unless idU == idUc
raise "fail" unless idS == idSc

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)
