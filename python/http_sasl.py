#!/usr/bin/env python3

import requests, sys, opaque, binascii

opaque_context=b"SASL OPAQUE Mechanism"

realm="localhost"
url = "http://localhost:8090"

pwdU = b"asdf"
user = "s"
authid = "s"

r = requests.get(url)
if r.status_code != 401:
    print(f'"{url}" did not return 401')
    sys.exit(1)

www_auth = r.headers.get("WWW-Authenticate")
print(f"www-authenticate: {www_auth}")

opaque_req, sec = opaque.CreateCredentialRequest(pwdU)

c2s = binascii.b2a_base64(opaque_req+f"{user}\0{authid}\0".encode("utf8"), newline=False).decode('utf8')
h = {"Authorization": f'SASL c2s="{c2s}",realm="{realm}",mech="OPAQUE"'}
print(h)
r = requests.get(url, headers=h)

print("response status:", r.status_code)
www_auth = r.headers.get("WWW-Authenticate")
print(f"www-authenticate: {www_auth}")
if not www_auth.startswith("SASL "):
    print("bad auth method in 2nd step of opaque sasl auth")
    sys.exit(1)

fields = dict((x.strip() for x in kv.split('=')) for kv in www_auth[5:].split(','))
s2c = binascii.a2b_base64(fields['s2c'])
resp = s2c[:opaque.OPAQUE_SERVER_SESSION_LEN]
idS = s2c[opaque.OPAQUE_SERVER_SESSION_LEN:-1].decode('utf8')
print(idS, resp)

s2s = fields['s2s']

ids=opaque.Ids(user, idS)
sk, authU, export_key = opaque.RecoverCredentials(resp, sec, opaque_context, ids)

c2s = binascii.b2a_base64(authU, newline=False).decode('utf8')
h = {"Authorization": f'SASL c2s="{c2s}",s2s={fields["s2s"]}'}
print(h)
r = requests.get(url, headers=h)

print("response status:", r.status_code)
www_auth = r.headers.get("WWW-Authenticate")
print(f"www-authenticate: {www_auth}")

print(r.text)
