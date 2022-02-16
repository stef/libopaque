#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from flask import Flask, request, render_template
from opaque import (CreateRegistrationResponse,
                    StoreUserRecord,
                    CreateCredentialResponse,
                    UserAuth,
                    Register,
                    Ids)
from pysodium import crypto_secretbox, crypto_secretbox_open, randombytes

app = Flask(__name__)
server_key = randombytes(32)
users = {}
fake, _ = Register(hexlify(randombytes(16)), Ids(hexlify(randombytes(16)), hexlify(randombytes(16))))

# the server is stateless apart from the user dict

# between protocol steps the local sensitive context is encrypted and
# sent to the client, who has to send it back for the final server
# step. This is also how you would implement OPAQUE in a
# load-balancing setup without synching protocol state between all
# backend servers.

def seal(data):
   nonce = randombytes(24)
   return nonce+crypto_secretbox(data, nonce, server_key)

def unseal(data):
   nonce = data[:24]
   return crypto_secretbox_open(data[24:],data[:24],server_key)

@app.route("/")
def start():
   return render_template('index.html')

@app.route("/request-creds", methods=['POST'])
def req_creds():
   req = unhexlify(request.form['request'])
   idU = request.form['id']
   rec=users.get(idU, fake)
   # wrap the IDs into an opaque.Ids struct:
   ids=Ids(idU, "demo server")
   # create a context string
   context = b"pyopaque-v0.2.0-demo"
   # server responds to credential request
   resp, _, authU = CreateCredentialResponse(req, rec, ids, context)
   return { "response": resp.hex(), "ctx": seal(authU).hex() }

@app.route("/authenticate", methods=['POST'])
def authenticate():
   authU = unhexlify(request.form['authU'])
   authU0 = unseal(unhexlify(request.form['ctx']))
   # server authenticates user
   try:
       UserAuth(authU0, authU)
   except:
       return { "response": False }
   return { "response": True }

@app.route("/register", methods=['POST'])
def register():
   req = request.form['request']
   sec, resp = CreateRegistrationResponse(unhexlify(req))
   return { 'response': resp.hex(), "ctx": seal(sec).hex() }

@app.route("/store", methods=['POST'])
def store():
   reg_rec = unhexlify(request.form['rec'])
   ctx = unseal(unhexlify(request.form['ctx']))
   idU = request.form['id']
   if idU in users:
       return { "response": False }
   rec = StoreUserRecord(ctx, reg_rec)
   users[idU]=rec
   return { "response": True}

@app.after_request
def add_header(response):
   response.headers['Content-Security-Policy'] = "default-src *; style-src 'self' 'unsafe-inline'; script-src * 'unsafe-inline' 'unsafe-eval'"
   return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=False)
