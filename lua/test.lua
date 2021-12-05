#!/usr/bin/env lua5.3

o = require 'opaque'

cfg = {["skU"] = o.InSecEnv,
       ["pkU"] = o.NotPackaged,
       ["pkS"] = o.InSecEnv,
       ["idU"] = o.InSecEnv,
       ["idS"] = o.InClrEnv}

rec, ek = o.register("asdf", nil, cfg, "idU", "idS")
sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, cfg, "idU", "idS", {"info", "einfo"})
csk, authU, export_key = o.recoverCredentials(resp, sec, nil, cfg, {"info", "einfo"}, nil, nil)
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

-- failing
sec, pub = o.createCredentialReq("qwer")
resp, ssk, ssec = o.createCredentialResp(pub, rec, cfg, "idU", "idS", {"info", "einfo"})
ok, csk, authU, export_key = pcall(o.recoverCredentials, resp, sec, nil, cfg, {"info", "einfo"}, nil, nil)
print(ok, csk, authU, export_key)

-- registration
sec, msg = o.createRegistrationReq("asdf")
ssec, resp = o.createRegistrationResp(msg)
rec, ek = o.finalizeReq(sec,resp,cfg,"idU","idS")
rec = o.storeRec(ssec, rec)

sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, cfg, "idU", "idS", {"info", "einfo"})
csk, authU, export_key = o.recoverCredentials(resp, sec, nil, cfg, {"info", "einfo"}, nil, nil)
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

-- 1k variant
sec, msg = o.createRegistrationReq("asdf")
ssec, resp = o.create1kRegistrationResp(msg, '\x8f@\xc5\xad\xb6\x8f%bJ\xe5\xb2\x14\xeavzn\xc9M\x82\x9d={^\x1a\xd1\xbao>!8(_')
rec, ek = o.finalizeReq(sec,resp,cfg,"idU","idS")
rec = o.store1kRec(ssec, '\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f', rec)

sec, pub = o.createCredentialReq("asdf")
resp, ssk, ssec = o.createCredentialResp(pub, rec, cfg, "idU", "idS", {"info", "einfo"})
csk, authU, export_key = o.recoverCredentials(resp, sec, nil, cfg, {"info", "einfo"}, nil, nil)
assert(csk==ssk)
assert(o.userAuth(ssec,authU))

print("all ok")