# libopaque Python bindings

These bindings provide access to libopaque which implements the
[IETF CFRG RFC draft](https://github.com/cfrg/draft-irtf-cfrg-opaque)
or you can read the [original paper](https://eprint.iacr.org/2018/163).

## Dependencies

These bindings depend on the following:
 - libopaque: https://github.com/stef/libopaque/
 - libsodium
 - pysodium

## API

There are 3 data structures that are used by libopaque:

### `Ids`
The IDs of the peers are passed around as a struct:
```python
# wrap the IDs into an opaque.Ids struct:
ids=opaque.Ids("user", "server")
```

### `PkgConfig`
Configuration of the envelope is handled via a `PkgConfig` struct:
```python
# Wrap the envelope config into an opaque PkgConfig struct.
cfg=opaque.PkgConfig()
cfg.skU=opaque.InSecEnv        # The user's private key is encrypted.
cfg.pkU=opaque.NotPackaged     # The user's public key is not packaged.
cfg.pkS=opaque.InClrEnv        # The server's public key is plaintext.
cfg.idU=opaque.InSecEnv        # The user's ID is encrypted.
cfg.idS=opaque.InClrEnv        # The server's ID is plaintext.
```

### `App_Infos`
The IETF CFRG draft mentions a bunch of `?info*` parameters that can
be used to be bound into the session:
```python
infos=opaque.App_Infos(info1="1", info2="2", einfo2="e2", info3="3", einfo3="e3")
```

## 1-step registration

1-step registration is only specified in the original paper. It is not specified by the IETF
CFRG draft. 1-step registration has the benefit that the supplied password (`pwdU`) can be checked
on the server for password rules (e.g., occurrence in common password
lists). It has the drawback that the password is exposed to the server.

```python
rec, export_key = opaque.Register(pwdU, cfg, ids, skS)
```

## 4-step registration

Registration as specified in the IETF CFRG draft consists of the
following 4 steps:

### Step 1: The user creates a registration request.

```python
secU, M = opaque.CreateRegistrationRequest(pwdU)
```

- `pwdU` is the user's password.

The user should hold on to `secU` securely until step 3 of the registration process.
`M` needs to be passed to the server running step 2.

### Step 2: The server responds to the registration request.

```python
secS, pub = opaque.CreateRegistrationResponse(M)
```

 - `M` comes from the user running the previous step.

The server should hold onto `secS` securely until step 4 of the registration process.
`pub` should be passed to the user running step 3.

### Step 3: The user finalizes the registration using the response from the server.

```python
rec0, export_key = opaque.FinalizeRequest(secU, pub, cfg, ids)
```

 - `secU` contains sensitive data and should be disposed securely after usage in this step.
 - `pub` comes from the server running the previous step.
 - `cfg` is a `PkgConfig` struct either known or passed by the server.
 - `ids` is an `Ids` struct that contains the IDs of the user and the server.

 - `rec0` should be passed to the server running step 4.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

### Step 4: The server finalizes the user's record.

```python
rec1 = opaque.StoreUserRecord(secS, rec0)
```

 - `rec0` comes from the user running the previous step.
 - `secS` contains sensitive data and should be disposed securely after usage in this step.

 - `rec1` should be stored by the server associated with the ID of the user.

**Important Note**: Confusingly this function is called `StoreUserRecord`, yet it
does not do any storage. How you want to store the record (`rec1`) is up
to the implementor using this API.

## Establishing an opaque session

After a user has registered with a server, the user can initiate the
AKE and thus request its credentials in the following 3(+1)-step protocol:

### Step 1: The user initiates a credential request.

```python
pub, secU = opaque.CreateCredentialRequest(pwdU)
```

 - `pwdU` is the user's password.

The user should hold onto `secU` securely until step 3 of the protocol.
`pub` needs to be passed to the server running step 2.

### Step 2: The server responds to the credential request.

```python
resp, sk, secS = opaque.CreateCredentialResponse(pub, rec, cfg, ids, infos)
```

 - `pub` comes from the user running the previous step.
 - `rec` is the user's record stored by the server at the end of the registration protocol.
 - `cfg` is a `PkgConfig` struct either known or passed by the server.
 - `ids` is an `Ids` struct that contains the IDs of the user and the server.
 - `infos` is an optional `App_Infos` struct.

 - `resp` needs to be passed to the user running step 3.
 - `sk` is a shared secret, the result of the AKE.
 - The server should hold onto `secS` securely until the optional step
   4 of the protocol, if needed. otherwise this value should be
   discarded securely.

### Step 3: The user recovers its credentials from the server's response.

```python
sk, authU, export_key, ids = opaque.RecoverCredentials(resp, secU, cfg, infos, pkS)
```

 - `resp` comes from the server running the previous step.
 - `secU` contains sensitive data and should be disposed securely after usage in this step.
 - `cfg` is a `PkgConfig` struct either known or passed by the server.
 - `infos` is an optional `App_Infos` struct.
 - `pkS` is the server's public key.

 - `sk` is a shared secret, the result of the AKE.
 - `authU` is an authentication tag that can be passed in step 4 for explicit user authentication.
 - `export_key` can be used to decrypt additional data stored by the server.
 - `ids` is an `Ids` struct containing the IDs of the user and the server.

### Step 4 (Optional): The server authenticates the user.

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```python
opaque.UserAuth(secS, authU, infos)
```

 - `secS` contains sensitive data and should be disposed securely after usage in this step.
 - `authU` comes from the user running the previous step.
 - `infos` is an optional `App_Infos` struct.
