# Ruby bindings for libopaque

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
ruby extconf.rb
make
```

## Examples

see test.rb

## API

There are 3 data structures that are used by libopaque:

### `Ids`

The IDs of the client (idU) and the server (idS) are passed directly
as seperate parameters to functions that need to handle IDs.

### `PkgConfig`

Configuration of the envelope is handled via a simple array.

The items in this array correspond to the envelope fields in this
order: `skU`, `pkU`, `pkS`, `idU`, `idS`. Each item in this array must
be one of the following constants:

 - InSecEnv: the value is encrypted in the envelope,
 - InClrEnv: the value is unencrypted in the envelope,
 - NotPackaged: the value is not present in the envelope.

Important to note is that the first value for the `skU` cannot be
`InClrEnv` since this value is the clients secret key, and thus must
either be encrypted or not packaged at all to be derived. For more
information how `NotPackaged` values are derived see the main
libopaque documentation.

Example:
```
cfg = [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv]
```

### `App_Infos`

The IRTF CFRG draft mentions `info` and `einfo` parameters that can be
used to be bound into the session, these are passed as a simple
two-element array:

```ruby
infos=["some info", "some einfo"];
```

## One-key Server convenience function

For the case that a setup requires externally generated long-term
server keys the ruby bindings provide a convenience function
`create_server_keys()` which can be used to generate a server
key-pair. The function returns `pkS` and `skS` in this order.

## 1-step registration

1-step registration is only specified in the original paper. It is not
specified by the IRTF CFRG draft. 1-step registration has the benefit
that the supplied password (`pwd`) can be checked on the server for
password rules (e.g., occurrence in common password lists, please obey
[NIST SP
800-63-3b](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)). It
has the drawback that the password is exposed to the server.

```ruby
rec, export_key = register(pwd, idU, idS, cfg, skS);
```

The function expects these paramters:

 - `pwd` is the user's password.
 - `idU` is the clients ID,
 - `idS` is the servers ID,
 - `cfg` is an array containing the envelope configuration,
 - `skS` is an optional explicitly specified server long-term key

This function returns:

 - `rec` should be stored by the server associated with the ID of the user.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

## 4-step registration

Registration as specified in the IRTF CFRG draft consists of the
following 4 steps:

### Step 1: The user creates a registration request.

```ruby
req, sec = create_registration_request(pwd);
```

- `pwd` is the user's password.

The user should hold on to `sec` securely until step 3 of the
registration process. `req` needs to be passed to the server running
step 2.

### Step 2: The server responds to the registration request.

```ruby
sec, resp = create_registration_response(req);
```

Alternatively, for explicitly providing the server long term private key:

```ruby
sec, resp = create_1k_registration_response(req, skS);
```

 - `req` comes from the user running the previous step.
 - `skS` is an optional explicitly specified server long-term key

The server should hold onto `sec` securely until step 4 of the registration process.
`resp` should be passed to the user running step 3.

### Step 3: The user finalizes the registration using the response from the server.

```ruby
rec, export_key = finalize_request(sec, resp, idU, idS, cfg);
```

 - `sec` contains sensitive data and should be disposed securely after usage in this step.
 - `resp` comes from the server running the previous step.
 - `idU` is the clients ID,
 - `idS` is the servers ID,
 - `cfg` is an array containing the envelope configuration,

The function outputs:

 - `rec` should be passed to the server running step 4.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

### Step 4: The server finalizes the user's record.

```ruby
rec = store_user_record(sec, rec);
```

or alternatively with explicitly specified long-term server private key:

```ruby
rec = store_1k_user_record(sec, skS, rec);
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

```ruby
sec, req = create_credential_request(pwd)
```

 - `pwd` is the user's password.

The user should hold onto `sec` securely until step 3 of the protocol.
`pub` needs to be passed to the server running step 2.

### Step 2: The server responds to the credential request.

```ruby
resp, sk, sec = create_credential_response(req, rec, idU, idS, cfg, infos);
```

 - `req` comes from the user running the previous step.
 - `rec` is the user's record stored by the server at the end of the registration protocol.
 - `idU` is the clients ID,
 - `idS` is the servers ID,
 - `cfg` is an array containing the envelope configuration,
 - `infos` is an optional array containing two info strings, check the
   IRTF CFRG specification if you need this (probably not) and how to use this.

This function returns:

 - `resp` needs to be passed to the user running step 3.
 - `sk` is a shared secret, the result of the AKE.
 - `sec` is the servers sensitive context. The server should hold onto
   this valuesecurely until the optional step 4 of the protocol, if
   needed. otherwise this value should be discarded securely.

### Step 3: The user recovers its credentials from the server's response.

```ruby
sk, authU, export_key, idU, idS = recover_credentials(resp, sec, cfg, infos, pkS, idU, idS);
```

 - `resp` comes from the server running the previous step.
 - `sec` contains the client sensitive data from the first step and
   should be disposed securely after this step.
 - `cfg` is an array containing the envelope configuration,
 - `infos` is an optional array containing two info strings, check the
   IRTF CFRG specification if you need this (probably not) and how to
   use this.
 - `pkS` is the server's optional public key, this must be specified
   if the 3rd item in cfg is `NotPackaged` otherwise it must be nil
 - `idU` is the clients ID, this must be specified even if just an
   empty string if the 4th element of `cfg` is `NotPackaged`,
   otherwise it must be `nil`.
 - `idS` is the servers ID,t his must be specified even if just an
   empty string if the 5th element of `cfg` is `NotPackaged`,
   otherwise it must be `nil`.

This function returns:

 - `sk` is a shared secret, the result of the AKE.
 - `authU` is an authentication tag that can be passed in step 4 for
   explicit user authentication.
 - `export_key` can be used to decrypt additional data stored by the server.
 - `idU` and `idS` are the IDs of the user and the server, this is
   useful if these are packaged in the envelope.

### Step 4 (Optional): The server authenticates the user.

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```ruby
user_auth(sec, authU);
```

 - `sec` contains the servers sensitive context from the second step
   and should be disposed securely after usage in this step.
 - `authU` comes from the user running the previous step.

The function returns a boolean `false` in case the authentication
failed, otherwise `true`.

