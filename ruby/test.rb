#!/usr/bin/env ruby

require './opaque.so'

include Opaque

idU = "idU"
idS = "idS"
pwd = "pwd"
context = "context"

# create a record "directly on the server"
rec, export_key = register(pwd, idU, idS)

# client initiates session
secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, context)

# client recovers keys, sets up session
skU, authU, export_keyU = recover_credentials(resp, secU, context, idU, idS)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)

# start 4 step registration
m, secU = create_registration_request(pwd)

secS, pub = create_registration_response(m)

rec, export_key = finalize_request(secU, pub, idU, idS)

rec = store_user_record(secS, rec)

secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, context)

# client recovers keys, sets up session
skU, authU, export_keyU = recover_credentials(resp, secU, context, idU, idS)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)

# start 4 step registration with 1k server setup
_, skS = create_server_keys()

m, secU = create_registration_request(pwd)

secS, pub = create_registration_response(m, skS)

rec, export_key = finalize_request(secU, pub, idU, idS)

rec = store_user_record(secS, rec)

secU, pub = create_credential_request(pwd)

# server sets up session and responds with record
resp, skS, secS = create_credential_response(pub, rec, idU, idS, context)

# client recovers keys, sets up session
skU, authU, export_keyU = recover_credentials(resp, secU, context, idU, idS)

raise "fail" unless skS == skU
raise "fail" unless export_key == export_keyU

# server authenticates client explicitly
raise "fail" unless user_auth(secS, authU)

print "all ok\n"
