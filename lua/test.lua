#!/usr/bin/env lua5.3

o = require 'opaque'

rec, ek = o.register("asdf", nil, "idU", "idS")
sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, "context", "idU", "idS")
csk, authU, export_key = o.recoverCredentials(resp, sec, "context", "idU", "idS")
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

-- failing
sec, pub = o.createCredentialReq("qwer")
resp, ssk, ssec = o.createCredentialResp(pub, rec, "context", "idU", "idS")
ok, csk, authU, export_key = pcall(o.recoverCredentials, resp, sec, "context", "idU", "idS")
assert(not ok)
print(ok, csk, authU, export_key)

-- registration
sec, msg = o.createRegistrationReq("asdf")
ssec, resp = o.createRegistrationResp(msg, nil)
rec, ek = o.finalizeReq(sec,resp,"idU","idS")
rec = o.storeRec(ssec, rec)

sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, "context", "idU", "idS")
ok, csk, authU, export_key = pcall(o.recoverCredentials, resp, sec, "context", "idU", "idS")
assert(ok)
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

-- 1k variant
sec, msg = o.createRegistrationReq("asdf")
ssec, resp = o.createRegistrationResp(msg, '\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')
rec, ek = o.finalizeReq(sec,resp,"idU","idS")
rec = o.storeRec(ssec, rec)

sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, "context", "idU", "idS")
ok, csk, authU, export_key = pcall(o.recoverCredentials, resp, sec, "context", "idU", "idS")
assert(ok)
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

print("all ok")
