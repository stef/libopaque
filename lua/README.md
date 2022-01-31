# Lua bindings for libopaque

These bindings provide access to libopaque which implements the
[IRTF CFRG RFC draft](https://github.com/cfrg/draft-irtf-cfrg-opaque)
or you can read the [original paper](https://eprint.iacr.org/2018/163).

## Dependencies

These bindings depend on the following:
 - libopaque: https://github.com/stef/libopaque/
 - libsodium

## Building

You need to have libopaque installed, and working (thus also libsodium), then:

```
make
```

## Examples

see test.lua

## API

There is one data structure that is used by libopaque:

### `Ids`

The IDs of the client (idU) and the server (idS) are passed directly
as seperate parameters to functions that need to handle IDs.

## 1-step registration

1-step registration is only specified in the original paper. It is not
specified by the IRTF CFRG draft. 1-step registration has the benefit
that the supplied password (`pwd`) can be checked on the server for
password rules (e.g., occurrence in common password lists, please obey
[NIST SP
800-63-3b](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)). It
has the drawback that the password is exposed to the server.

```lua
rec, export_key = register(pwd, skS, idU, idS);
```

The function expects these paramters:

 - `pwd` is the user's password.
 - `skS` is an optional explicitly specified server long-term key
 - `idU` is the clients ID,
 - `idS` is the servers ID,

This function returns:

 - `rec` should be stored by the server associated with the ID of the user.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

## 4-step registration

Registration as specified in the IRTF CFRG draft consists of the
following 4 steps:

### Step 1: The user creates a registration request.

```lua
sec, req = createRegistrationReq(pwd);
```

- `pwd` is the user's password.

The user should hold on to `sec` securely until step 3 of the
registration process. `req` needs to be passed to the server running
step 2.

### Step 2: The server responds to the registration request.

```lua
sec, resp = createRegistrationResp(req, skS);
```

 - `req` comes from the user running the previous step.
 - `skS` is an optional explicitly specified server long-term private key

The server should hold onto `sec` securely until step 4 of the registration process.
`resp` should be passed to the user running step 3.

### Step 3: The user finalizes the registration using the response from the server.

```lua
rec, export_key = finalizeReq(sec, resp, idU, idS);
```

 - `sec` contains sensitive data and should be disposed securely after usage in this step.
 - `resp` comes from the server running the previous step.
 - `idU` is the clients ID,
 - `idS` is the servers ID,

The function outputs:

 - `rec` should be passed to the server running step 4.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

### Step 4: The server finalizes the user's record.

```lua
rec = storeRec(sec, rec);
```

or alternatively with explicitly specified long-term server private key:

```lua
rec = store1kRec(sec, skS, rec);
```

 - `rec` comes from the client running the previous step.
 - `skS` is an explicitly specified server long-term key
 - `sec` contains sensitive data and should be disposed securely after usage in this step.

The function returns:

 - `rec` should be stored by the server associated with the ID of the user.

**Important Note**: Confusingly this function is called `StoreUserRecord`, yet it
does not do any storage. How you want to store the record (`rec`) is up
to the implementor using this API.

## Establishing an opaque session

After a user has registered with a server, the user can initiate the
AKE and thus request its credentials in the following 3(+1)-step protocol:

### Step 1: The user initiates a credential request.

```lua
sec, req = createCredentialReq(pwd)
```

 - `pwd` is the user's password.

The user should hold onto `sec` securely until step 3 of the protocol.
`pub` needs to be passed to the server running step 2.

### Step 2: The server responds to the credential request.

```lua
resp, sk, sec = createCredentialResp(req, rec, cfg, idU, idS, infos);
```

 - `req` comes from the user running the previous step.
 - `rec` is the user's record stored by the server at the end of the registration protocol.
 - `context` is a string distinguishing this instantiation of the protocol from others, e.g. "MyApp-v0.2"
 - `idU` is the clients ID,
 - `idS` is the servers ID,

This function returns:

 - `resp` needs to be passed to the user running step 3.
 - `sk` is a shared secret, the result of the AKE.
 - `sec` is the servers sensitive context. The server should hold onto
   this values ecurely until the optional step 4 of the protocol, if
   needed. otherwise this value should be discarded securely.

### Step 3: The user recovers its credentials from the server's response.

```lua
sk, authU, export_key = recoverCredentials(resp, sec, context, idU, idS);
```

 - `resp` comes from the server running the previous step.
 - `sec` contains the client sensitive data from the first step and
   should be disposed securely after this step.
 - `context` is a string distinguishing this instantiation of the protocol from others, e.g. "MyApp-v0.2"
 - `idU` is the client ID.
 - `idS` is the server ID.

This function returns:

 - `sk` is a shared secret, the result of the AKE.
 - `authU` is an authentication tag that can be passed in step 4 for
   explicit user authentication.
 - `export_key` can be used to decrypt additional data stored by the server.

### Step 4 (Optional): The server authenticates the user.

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```lua
userAuth(sec, authU);
```

 - `sec` contains the servers sensitive context from the second step
   and should be disposed securely after usage in this step.
 - `authU` comes from the user running the previous step.

The function returns a boolean `false` in case the authentication
failed, otherwise `true`.

