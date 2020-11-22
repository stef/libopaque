# libopaque Python bindings

These bindings provide access to libopaque which implements the
IETF CFRG RFC draft: https://github.com/cfrg/draft-irtf-cfrg-opaque,
or you can read the original paper: https://eprint.iacr.org/2018/163

## Depends

depends on
 - libopaque: https://github.com/stef/libopaque/
 - libsodium
 - pysodium

## API

There's 3 data structures that are used by libopaque:

### Ids
Ids of the peers are passed around as a struct:
```python
# wrap the IDs into an opaque.Ids struct:
ids=opaque.Ids("user", "server")
```

### Configuration
configuration of the envelope is handled via a `PkgConfig` struct:
```python
# wrap the envelope confing into an opaque PkgConfig struct
cfg=opaque.PkgConfig()
cfg.skU=opaque.InSecEnv        # user private key is encrypted
cfg.pkU=opaque.NotPackaged     # user pubkey is not packaged
cfg.pkS=opaque.InClrEnv        # servers pubkey is plaintext
cfg.idU=opaque.InSecEnv        # users id is encrypted
cfg.idS=opaque.InClrEnv        # servers id plaintext
```

### App Infos
the ietf cfrg draft mentions a bunch of `?info*` parameters that can
be usesd to be bound into the session:

```python
infos=opaque.App_Infos(info1="1", info2="2", einfo2="e2", info3="3", einfo3="e3")
```

## one step registration

This is only specified in the original paper, not specified by ietf
cfrg draft has the benefit that the supplied password can be checked
on the server for password rules (e.g. occurence in common password
lists), has the drawback that the password is exposed to the server.

```python
rec, export_key = opaque.Register(password, cfg, ids, key)
```

## 4 step registration

registration as specified in the ietf cfrg draft consists of the
following 4 steps:

### step1: user creates a registration request

```python
ctx, alpha = opaque.CreateRegistrationRequest(password)
```

the user should hold on to `ctx` securely until step 3 of the registration process.
`alpha` needs to be passed to the server running step2

### step2: server responds to the registration request

```python
sec, pub = opaque.CreateRegistrationResponse(alpha)
```

 - `alpha` comes from the user running the previous step.
the server should hold onto `sec` securely until step 4 of the registration process.
`pub` should be passed to the user running step 3.

### step3: user finalizes the registration using the response from the server

```python
rec, export_key = opaque.FinalizeRequest(ctx, pub, cfg, ids, key = key)
```

 - `pub` comes from the server running the previous step.
 - `ctx` contains sensitive data and should be disposed securely after usage in this step.
 - `cfg` is a `PkgConfig` struct either known, or passed by the server.
 - `ids` is the App_Ids struct that contains the user Ids of the user and the server.
 - `key` is an optional domain separation value.


 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.
 - `rec` should be passed to the server running step 4.

### step4: server finalizes the user record

```
rec = opaque.StoreUserRecord(sec, urec)
```

 - `urec` comes from the user running the previous step.
 - `sec` contains sensitive data and should be disposed securely after usage in this step.
 - `rec` should be stored by the server associated with the id of the user.

**important note**: confusingly this function is called `StoreUserRecord`, yet it
does not do any storage, how you want to store the `rec` record is up
to the implementor using this API. The name is as specified by the ietf cfrg rfc draft.

## establishing an opaque session

After a user has registered with a server the user can initiate the
AKE and thus request its credentials in the following 3(+1) step protocol:

### step1: user initiates a credential request

```python
pub, sec = opaque.CreateCredentialRequest(password)
```
the user should hold onto `sec` securely until step 3 of the protocol.
`pub` needs to be passed to the server running step2

### step2: server responds to credential request

```python
resp, sks, ctx = opaque.CreateCredentialResponse(pub, rec, cfg, ids, infos)
```

 - `pub` comes from the user running the previous step.
 - `rec` is the users record stored by the server at the end of the registration protocol.
 - `cfg` is a `PkgConfig` struct either known, or passed by the server.
 - `ids` is the App_Ids struct that contains the user Ids of the user and the server.
 - `infos` is an optional App_Infos structure.

 - `sks` is a shared secret, the result of the AKE.
 - the server should hold onto `ctx` securely until the optional step
   4 of the protocol, if needed. otherwise this value should be
   discarded securely.
 - `resp` needs to be passed to the user running step3

### step3: user recovers its credentials from the servers response

```python
sku, auth, export_key, ids = opaque.RecoverCredentials(resp, sec, cfg, infos, key=key)
```

 - `resp` comes from the server running the previous step.
 - `sec` contains sensitive data and should be disposed securely after usage in this step.
 - `cfg` is a `PkgConfig` struct either known, or passed by the server.
 - `infos` is an optional App_Infos structure.
 - `key` is an optional domain separation value, it must be the same as used during registration.

 - `sku` is a shared secret, the result of the AKE.
 - `auth` is an authentication tag, that can be passed in step 4 for explicit user authentication
 - `export_key` is the export_key from the registration, it can be
   used to decrypt additonal data stored by the server.
 - `ids` is a `App_Ids` structure containing the Ids of the user and the server.

### (optional) step4: server authenticates user

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```python
opaque.UserAuth(ctx, auth, infos)
```

 - `auth` comes from the user running the previous step.
 - `ctx` contains sensitive data and should be disposed securely after usage in this step.
 - `infos` is an optional App_Infos structure.
