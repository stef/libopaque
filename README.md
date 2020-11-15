# libopaque

This library implements OPAQUE protocol as proposed by the IETF CFRG in
https://github.com/cfrg/draft-irtf-cfrg-opaque


## Installing

Install `python`, `libsodium`  and `libsodium-dev` using your operating system provided
package management. 

Building everything should (hopefully) be quite simple afterwards:

```
git submodule update --init --recursive --remote
cd src
make
```

## Library

libopaque builds a library, which you can use to build your
own password manager either in C/C++ or any other language that can
bind to this library.

### OPAQUE API

TODO this section needs updating

The following functions implement the OPAQUE protocol with the following deviations:

 0. does not implement any persistence/lookup functionality.
 1. instead of HMQV (which is patented) it implements a Triple-DH instead.
 2. it implements "user iterated hashing" from page 29 of the paper
 3. additionally implements a variant where U secrets never hit S unprotected

For more information please see the original paper and the
`src/tests/opaque-test.c` example file.

```
int storePwdFile(const uint8_t *pw, Opaque_UserRecord *rec);
```

This function implements the same function from the paper. This
function runs on the server and creates a new output record `rec` of
secret key material partly encrypted with a key derived from the input
password `pw`. The server needs to implement the storage of this
record and any binding to user names or as the paper suggests `sid`.

```
void usrSession(const uint8_t *pw, Opaque_UserSession_Secret *sec, Opaque_UserSession *pub);
```

This function initiates a new OPAQUE session, is the same as the
function defined in the paper with the same name. The User initiates a
new session by providing its input password `pw`, and receving a
private `sec` and a "public" `pub` output parameter. The User should
protect the `sec` value until later in the protocol and send the `pub`
value over to the Server, which process this with the following function:

```
int srvSession(const Opaque_UserSession *pub, const Opaque_UserRecord *rec, Opaque_ServerSession *resp, uint8_t *sk);
```

This is the same function as defined in the paper with the same
name. It runs on the server and receives the output `pub` from the
user running `usrSession()`, futhermore the server needs to load the
user record created when registering the user with the `storePwdFile()`
function. These input parameters are transformed into a secret/shared
session key `sk` and a response `resp` to be sent back to the user to
finish the protocol with the following `userSessionEnd()` function:

```
int userSessionEnd(const Opaque_ServerSession *resp, const Opaque_UserSession_Secret *sec, const uint8_t *pw, uint8_t *pk);
```

This is the same function as defined in the paper with the same
name. It is run by the user, and recieves as input the response from
the previous server `srvSession()` function as well as the `sec` value
from running the `usrSession()` function that initiated this protocol,
the user password `pw` is also needed as an input to this final
step. All these input parameters are transformed into a shared/secret
session key `pk`, which should be the same as the one calculated by
the `srvSession()` function.

#### Alternative registration API

The paper original proposes a very simple 1 shot interface for
registering a new "user", however this has the drawback that in that
case the users secrets and its password are exposed in cleartext at
registration to the server. There is a much less efficient 4 message
registration protocol which avoids the exposure of the secrets and the
password to the server which can be instantiated by the following for
registration functions:

```
void newUser(const uint8_t *pw, uint8_t *r, uint8_t *alpha);
```

The user inputs its password `pw`, and receives an ephemeral secret
`r` and a blinded value `alpha` as output. `r` should be protected
until step 3 of this registration protocol and the value `alpha`
should be passed to the servers `initUser()` function:

```
int initUser(const uint8_t *alpha, Opaque_RegisterSec *sec, Opaque_RegisterPub *pub);
```

The server receives `alpha` from the users invocation of its
`newUser()` function, it outputs a value `sec` which needs to be
protected until step 4 by the server. This function also outputs a
value `pub` which needs to be passed to the user who will use it in
its `registerUser()` function:

```
int registerUser(const uint8_t *pw, const uint8_t *r, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);
```

This function is run by the user, taking as input the users password
`pw`, the ephemeral secret `r` that was an output of the user running
`newUser()`, and the output `pub` from the servers run of
`initUser()`. The result of this is the value `rec` which should be
passed for the last step to the servers `saveUser()` function:

```
void saveUser(const Opaque_RegisterSec *sec, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);
```

The server combines the `sec` value from its run of its `initUser()`
function with the `rec` output of the users `registerUser()` function,
creating the final record, which should be the same as the output of
the 1-step `storePwdFile()` init function of the paper. The server
should save this record in combination with a user id and/or `sid`
value as suggested in the paper.

```
void opaque_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res);
```

This is a simple utility function that can be used to calculate
`f_k(c)`, where `c` is a constant, this is useful if the peers want to
authenticate each other.

If the server wants to authenticate itself to the user it sends the
user the output `auth` of `opaque_f(sk,sizeof sk, 1, auth)`, where
`sk` is the output from `srvSession()`. The user then verifies if this
`auth` is the same as the result of `opaque_f(pk,sizeof pk, 1, auth2)`,
where `pk` is the result from `userSessionEnd()`.

For the other direction, user authenticating to the server, reverse
the operations and use the value 2 for `c` instead of 1:
`opaque_f(pk,sizeof pk, 2, auth)` ->  `opaque_f(sk,sizeof sk, 2, auth2)`
and make sure `auth==auth2`.
