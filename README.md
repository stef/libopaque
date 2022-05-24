# libopaque

This library implements the OPAQUE protocol as proposed in an early
draft by the IRTF CFRG in
https://github.com/cfrg/draft-irtf-cfrg-opaque. THe draft has been updated
since then and this implementation is now slightly out of sync, but as soon as
the specification gets more stable, it is planned to reach full compliance with
it.

It comes with bindings for js, php7, ruby, java, erlang, lua, python, go and
SASL.  There are also a 3rd party bindings for:
 - [dart](https://github.com/tibotix/opaque-dart)
 - rust [libopaque-sys](https://github.com/dnet/libopaque-sys) + [opaqueoxide](https://github.com/dnet/opaqueoxide/)

Some more information about OPAQUE can be found in a series of blogposts:

 - [OPAQUE](https://www.ctrlc.hu/~stef/blog/posts/opaque.html)
 - [Why and how to use OPAQUE for user authentication](https://www.ctrlc.hu/~stef/blog/posts/Why_and_how_to_use_OPAQUE_for_user_authentication.html)
 - [opaque demo](https://www.ctrlc.hu/~stef/blog/posts/opaque_demo.html)

There is a [live demo](https://ctrlc.hu/opaque/) between a
python/flask backend and a js/html frontend.


## The OPAQUE Protocol

The OPAQUE protocol is an asymmetric password-authenticated
key-exchange. Essentially it allows a client to establish a shared
secret with a server based on only having a password. The client
doesn't need to store any state. The protocol has two phases:

  - In the initialization phase a client registers with the server.
  - In the AKE phase the client and server establish a shared secret.

The initialization only needs to be executed once, the key-exchange
can be executed as many times as necessary.

The following sections provide an abstract overview of the various
steps and their inputs and outputs, this is to provide an
understanding of the protocol. The various language bindings have -
language-specific - slightly different APIs in the way the
input/output parameters are provided to the functions, see details in
the READMEs of the bindings sub-directories.

### Initialization

The original paper and the IRTF CFRG draft differ, in the original
paper a one-step registration is specified which allows the server
during initialization to inspect the password of the client in
cleartext. This allows the server to enforce password sanity rules
(e.g. not being listed in hacked user databases), however this also
implies that the client has to trust the server with this
password. The IRTF CFRG draft doesn't specify this registration,
instead it specifies a four-step protocol which results in exactly the
same result being stored on the server, without the client ever
exposing the password to the server.

#### One-step registration revealing password to server

Before calling the registration function the server should check the
strength of the password by obeying [NIST SP 800-63-3b](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)) and if insufficient reject the registration.

The registration function takes the following parameters:

 - the client password
 - the optional long-term server private key skS
 - the IDs

The result of the registration is a record that the server should
store to be provided to the client in the key-exchange
phase. Additionally an `export_key` is also generated which can be used
to encrypt additional data that can be decrypted by the client in the
key-exchange phase. Where and how this additional `export_key` encrypted
data is stored and how it is retrieved by the client is out of scope
of the protocol, for example this could be used to store additional
keys, personal data, or other sensitive client state.

#### Password Privacy Preserving registration

This registration is a four step protocol which results in exactly the
same outcome as the one-step variant, without the server learning the
client password. It is recommended to have the client do a password
strength according to NIST SP 800-63-3b check before engaging in the
following protocol.

The following steps are executed, starting with the client:

 1. client: sec, req = CreateRegistrationRequest(pwd)

The outputs in the first step are

 - a sensitive client context `sec` that is needed in step 3, this should
   be kept secret as it also contains the plaintext password.
 - and request `req` that should be sent to the server, this request
   does not need to be encrypted (it is already).

 2. server: ssec, resp = CreateRegistrationResponse(req, skS)

In the second step the server takes the request and an optional
long-term server private key skS. In case no skS is supplied a
user-specific long-term server keypair is generated. The output of this step is:

 - a sensitive server context `ssec`, which must be kept secret and secure
   until step 4 of this registration protocol.
 - a response, which needs to be sent back to the client, this
   response does not need to be encrypted (it is already).

 3. client: recU, export_key = FinalizeRequest(sec, resp, ids)

In the third step the client takes its context from step 1, the
servers response from step 2, and the IDs of the server and client to
assemble a record stub `recU` and an `export_key`. In case the client
wishes to (and the server supports it) to encrypt and store additional
data at the server, it uses the `export_key` to encrypt it and sends
it over to the server together with the record stub. The record stub
might or might not be needed to be encrypted, depending on the OPAQUE
envelope configuration.

 4. server: rec = StoreUserRecord(ssec, recU, rec)

In the last - fourth - step of the registration protocol, the server
receives the record stub `recU` from the client step 3, it's own
sensitive context `ssec` from step 2. These parameters are used to
complete the record stub into a full record `rec`, which then the
server must store for later retrieval.

### The key-exchange

The key-exchange is a three-step protocol with an optional fourth step
for explicit client authentication:

  1. client: sec, req = CreateCredentialRequest(pwd)

The client initiates a key-exchange taking the password as input and
outputting a sensitive client context `sec` which should be kept
secret until step 3 of this protocol. This step also produces a
request `req` - which doesn't need to be encrypted (it is already) -
to be passed to the server executing step 2:

  2. server: resp, sk, ssec = CreateCredentialResponse(req, rec, ids, context)

The server receives a request from the client, retrieves record
belonging to the client, the IDs of itself and the client, and
a context string. Based on these inputs the server produces:

 - a response `resp` which needs to be sent to client,
 - its own copy of the shared key produced by the key-exchange, and
 - a sensitive context `ssec` which it needs to protect until the optional step 4.

  3. client: sk, authU, export_key, ids = RecoverCredentials(resp, sec, context, ids)

The client receives the servers response `resp`, and
 - takes its own sensitive context `sec` from step 1.,
 - in case the envelope configuration has set the servers public key
   set to not-packaged the servers public key,
 - a context string,
 - the ids of the server and client.
Processing all these inputs results in:
 - the shared secret key produced by the key exchange, which must be
   the same as what the server has,
 - an authentication token `authU` which can be sent to the server in
   case the optional fourth step of the protocol is needed to
   explicitly authenticate the client to the server.
 - and finally the client also computes the `export_key` which was
   used to encrypt additional data during the registration phase.

  4. optionally server: UserAuth(ssec, authU)

This step is not needed in case the shared key is used for example to
set up an encrypted channel between the server and client. Otherwise
the `authU` token is sent to the server, which using its previously
stored sensitive context `ssec` verifies that the client has indeed
computed the same shared secret as a result of the key-exchange and
thus explicitly authenticating the client.

## Installing

Install `libsodium-dev` and `pkgconf` using your operating system's package
manager.

Building everything should (hopefully) be quite simple afterwards:

```
git submodule update --init --recursive --remote
cd src
make
```

## OPAQUE API

The API is described in the header file:
[`src/opaque.h`](https://github.com/stef/libopaque/blob/master/src/opaque.h).

The library implements the OPAQUE protocol with the following deviations from
the original paper:

0. It does not implement any persistence/lookup functionality.
1. Instead of HMQV (which is patented), it implements a Triple-DH.
2. It implements "user iterated hashing" from page 29 of the paper.
3. It additionally implements a variant where U secrets never hit S
   unprotected.

For more information, see the
[IRTF CFRG specification](https://github.com/cfrg/draft-irtf-cfrg-opaque/blob/master/draft-irtf-cfrg-opaque.md),
the [original paper](https://github.com/stef/libopaque/blob/master/doc/opaque.pdf)
and the
[`src/tests/opaque-test.c`](https://github.com/stef/libopaque/blob/master/src/tests/opaque-test.c)
example file.

## OPAQUE Parameters

Currently all parameters are hardcoded, but there is nothing stopping you from
setting stronger values for the password hash.

### The Curve

This OPAQUE implementation is based on libsodium's ristretto25519 curve. This
means currently all keys are 32 bytes long.

### Other Crypto Building Blocks

This OPAQUE implementation relies on libsodium as a dependency to provide all
other cryptographic primitives:

- `crypto_pwhash`<sup>[1]</sup> uses the Argon2 function with
  `crypto_pwhash_OPSLIMIT_INTERACTIVE` and
  `crypto_pwhash_MEMLIMIT_INTERACTIVE` as security parameters.
- `randombytes` attempts to use the cryptographic random source of
  the underlying operating system<sup>[2]</sup>.

[1]: https://doc.libsodium.org/password_hashing/default_phf
[2]: https://download.libsodium.org/doc/generating_random_data

## Debugging

To aid in debugging and testing, there are two macros available:

| Macro      | Description                                       |
| ---------- | ------------------------------------------------- |
| `TRACE`    | outputs extra information to stderr for debugging |
| `NORANDOM` | removes randomness for deterministic results      |

To use these macros, specify the `DEFINES` Makefile variable when calling
`make`:

```
$ make DEFINES='-DTRACE -DNORANDOM' clean libopaque.so tests
$ LD_LIBRARY_PATH=. ./tests/opaque-test
```

As a shortcut, calling `make debug` also sets these variables. This code block
is equivalent to the one above:

```
$ make clean debug
$ LD_LIBRARY_PATH=. ./tests/opaque-test
```
