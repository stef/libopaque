# Erlang bindings for libopaque

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

see test.erl

## API

There is one data structure that is used by libopaque:

### `Ids`

The IDs of the client (idU) and the server (idS) are passed as lists
containing two binary items to functions that need to handle IDs.


## 1-step registration

1-step registration is only specified in the original paper. It is not
specified by the IRTF CFRG draft. 1-step registration has the benefit
that the supplied password (`pwd`) can be checked on the server for
password rules (e.g., occurrence in common password lists, please obey
[NIST SP 800-63-3b](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)). It
has the drawback that the password is exposed to the server.

```erlang
{Rec, Export_key} = opaque:register(Pwd, Ids, SkS).
```

The function expects these paramters:

 - `Pwd` is the user's password.
 - `Ids` is a list containing the the clients and the servers ID as binaries.
 - `SkS` is an optional explicitly specified server long-term private-key

This function returns:

 - `Rec` should be stored by the server associated with the ID of the user.
 - `Export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

## 4-step registration

Registration as specified in the IRTF CFRG draft consists of the
following 4 steps:

### Step 1: The user creates a registration request.

```erlang
{Sec, Req} = opaque:create_reg_req(Pwd).
```

- `Pwd` is the user's password.

The user should hold on to `Sec` securely until step 3 of the
registration process. `Req` needs to be passed to the server running
step 2.

### Step 2: The server responds to the registration request.

```erlang
{Sec, Resp} = opaque:create_reg_resp(Req, SkS).
```

 - `Req` comes from the user running the previous step.
 - `SkS` is an optional explicitly specified server long-term private-key

The server should hold onto `Sec` securely until step 4 of the registration process.
`Resp` should be passed to the user running step 3.

### Step 3: The user finalizes the registration using the response from the server.

```erlang
{Rec, Export_key } = opaque:finalize_req(Sec, Resp, Ids).
```

 - `Sec` contains sensitive data and should be disposed securely after usage in this step.
 - `Resp` comes from the server running the previous step.
 - `Ids` is the clients and the servers ID.

The function outputs:

 - `Rec` should be passed to the server running step 4.
 - `Export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

### Step 4: The server finalizes the user's record.

```erlang
Rec = opaque:store_rec(Sec, Sks, Rec).
```

 - `Rec` comes from the client running the previous step.
 - `Sec` contains sensitive data and should be disposed securely after usage in this step.

The function returns:

 - `Rec` should be stored by the server associated with the ID of the user.

**Important Note**: Confusingly this function is called `StoreUserRecord`, yet it
does not do any storage. How you want to store the record (`Rec`) is up
to the implementor using this API.

## Establishing an opaque session

After a user has registered with a server, the user can initiate the
AKE and thus request its credentials in the following 3(+1)-step protocol:

### Step 1: The user initiates a credential request.

```erlang
{Sec, Req} = opaque:create_cred_req(Pwd).
```

 - `Pwd` is the user's password.

The user should hold onto `Sec` securely until step 3 of the protocol.
`Pub` needs to be passed to the server running step 2.

### Step 2: The server responds to the credential request.

```erlang
{Resp, Sk, Sec} = opaque:create_cred_resp(Req, Rec, Ids, Context).
```

 - `Req` comes from the user running the previous step.
 - `Rec` is the user's record stored by the server at the end of the registration protocol.
 - `Ids` is the clients and the servers ID,
 - `Context` is a string distinguishing this instantiation of the
   protocol from others, e.g. "MyApp-v0.2"

This function returns:

 - `Resp` needs to be passed to the user running step 3.
 - `Sk` is a shared secret, the result of the AKE.
 - `Sec` is the servers sensitive context. The server should hold onto
   this valuesecurely until the optional step 4 of the protocol, if
   needed. otherwise this value should be discarded securely.

### Step 3: The user recovers its credentials from the server's response.

```erlang
{Sk, AuthU, Export_key} = opaque:recover_cred(Resp, Sec, Context, Ids).
```

 - `Resp` comes from the server running the previous step.
 - `Sec` contains the client sensitive data from the first step and
   should be disposed securely after this step.
 - `Context` is a string distinguishing this instantiation of the
   protocol from others, e.g. "MyApp-v0.2"
 - `Ids` is an array containing the clients and/or servers ID, these
   must be specified in case they are marked `notPackaged` in `Cfg`.

This function returns:

 - `Sk` is a shared secret, the result of the AKE.
 - `AuthU` is an authentication tag that can be passed in step 4 for
   explicit user authentication.
 - `Export_key` can be used to decrypt additional data stored by the server.

### Step 4 (Optional): The server authenticates the user.

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```erlang
ok = opaque:user_auth(Sec, AuthU).
```

 - `Sec` contains the servers sensitive context from the second step
   and should be disposed securely after usage in this step.
 - `AuthU` comes from the user running the previous step.

The function returns `ok` in case the authentication
succeeded, otherwise `fail`.

