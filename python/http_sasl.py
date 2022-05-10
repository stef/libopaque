#!/usr/bin/env python3

import requests, sys, binascii, sasl

realm="localhost"
url = "http://localhost:8090"
pwdU = "asdf"
user = "s"

r = requests.get(url)
if r.status_code != 401:
    print(f'"{url}" did not return 401')
    sys.exit(1)
www_auth = r.headers.get("WWW-Authenticate")
print(f"www-authenticate: {www_auth}")
if not www_auth.startswith("SASL "):
    print("bad auth method in 2nd step of opaque sasl auth")
    sys.exit(1)

client = sasl.Client()
client.setAttr("username", user)
client.setAttr("password", pwdU)
client.init()
ret, mech, response = client.start('OPAQUE')
if not ret:
    raise Exception(client.getError())

c2s = binascii.b2a_base64(response, newline=False).decode('utf8')
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
s2s = fields['s2s']

ret, response = client.step(s2c)
if not ret:
    raise Exception(client.getError())

c2s = binascii.b2a_base64(response, newline=False).decode('utf8')
h = {"Authorization": f'SASL c2s="{c2s}",s2s={fields["s2s"]}'}
print(h)
r = requests.get(url, headers=h)

print("response status:", r.status_code)
www_auth = r.headers.get("WWW-Authenticate")
print(f"www-authenticate: {www_auth}")

print(r.text)
