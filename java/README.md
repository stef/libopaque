# Java JNI bindings for libopaque

These bindings provide access to libopaque which implements the
[IRTF CFRG RFC draft](https://github.com/cfrg/draft-irtf-cfrg-opaque)
or you can read the [original paper](https://eprint.iacr.org/2018/163).

## Dependencies

These bindings depend on the following:
 - java-openjdk-dev
 - libopaque: https://github.com/stef/libopaque/
 - libsodium

## Building

You need to have the dependencies installed, then:

```
make
```

## Examples

see test.java

## API

There are 3 data structures that are used by libopaque:

### `Ids`

The IDs of the client (idU) and the server (idS) are passed using
instances of the `OpaqueIds` class to functions that need to handle
IDs.

example:

```java
OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                              "idS".getBytes(Charset.forName("UTF-8")));
```

### `PkgConfig`

Configuration of the envelope is handled via instances of the
`OpaqueConfig` class.

The parameters passed to the constructor of this class correspond to
the envelope fields in this order: `skU`, `pkU`, `pkS`, `idU`,
`idS`. Each of these parameters must be one of the following
constants:

 - `OpaqueConfig.PkgTarget.InSecEnv`: the value is encrypted in the envelope,
 - `OpaqueConfig.PkgTarget.InClrEnv`: the value is unencrypted in the envelope,
 - `OpaqueConfig.PkgTarget.NotPackaged`: the value is not present in the envelope.

Important to note is that the first value for the `skU` cannot be
`InClrEnv` since this value is the clients secret key, and thus must
either be encrypted or not packaged at all to be derived. For more
information how `NotPackaged` values are derived see the main
libopaque documentation.

Example:
```
OpaqueConfig cfg = new OpaqueConfig(OpaqueConfig.PkgTarget.InSecEnv,
                                    OpaqueConfig.PkgTarget.NotPackaged,
                                    OpaqueConfig.PkgTarget.NotPackaged,
                                    OpaqueConfig.PkgTarget.InSecEnv,
                                    OpaqueConfig.PkgTarget.InSecEnv);
```

### `App_Infos`

The IRTF CFRG draft mentions `info` and `einfo` parameters that can be
used to be bound into the session. Info parameters cannot be passed to
the functions via the java bindings.

## 1-step registration

1-step registration is only specified in the original paper. It is not
specified by the IRTF CFRG draft. 1-step registration has the benefit
that the supplied password (`pwd`) can be checked on the server for
password rules (e.g., occurrence in common password lists, please obey
[NIST SP
800-63-3b](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)). It
has the drawback that the password is exposed to the server.

```java
Opaque o = new Opaque();
OpaqueRecExpKey ret = o.register(pwd, skS, cfg, ids);
```

The function expects these paramters:

 - `pwd` is the user's password,
 - `skS` is an optional explicitly specified server long-term key,
 - `cfg` is an array containing the envelope configuration,
 - `ids` is an `OpaqueIds` instance containing the IDs of the client and server.

This function returns an instance of the `OpaqueRecExpKey` class, this
class has two member variables:

 - `rec` should be stored by the server associated with the ID of the user.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

## 4-step registration

Registration as specified in the IRTF CFRG draft consists of the
following 4 steps:

### Step 1: The user creates a registration request.

```java
OpaqueRegReq regReq = o.createRegReq(pwd);
```

- `pwd` is the user's password.

The function returns an instance of the `OpaqueRegReq` class, which
has two member variables:

  - `sec` The user should hold on to it securely until step 3 of the
    registration process.
  - `M` needs to be passed to the server running step 2.

### Step 2: The server responds to the registration request.

```java
OpaqueRegResp regResp = o.createRegResp(regReq.M, pkS);
```

The input parameters are:
 - `req` comes from the user running the previous step.
 - `pkS` is an optional explicitly specified server long-term public key

The function returns an instance of the `OpaqueRegResp` class, which
has two member variables:

 - `sec`: The server should hold onto `sec` securely until step 4 of
   the registration process.
 - `pub` should be passed to the user running step 3.

### Step 3: The user finalizes the registration using the response from the server.

```java
OpaquePreRecExpKey prerec = o.finalizeReg(regReq.sec, regResp.pub, cfg, ids);
```

The input parameters are:

 - `sec` contains sensitive data and should be disposed securely after usage in this step.
 - `pub` comes from the server running the previous step.
 - `cfg` is an array containing the envelope configuration,
 - `ids` is the an `OpaqueIds` instance containing the clients and servers ID.

The function outputs an instance of the `OpaquePreRecExpKey` class,
which has two member variables:

 - `rec` should be passed to the server running step 4.
 - `export_key` is an extra secret that can be used to encrypt
   additional data that you might want to store on the server next to
   your record.

### Step 4: The server finalizes the user's record.

```java
byte[] rec = o.storeRec(regResp.sec, skS, prerec.rec);
```

The input parameters are:

 - `rec` comes from the client running the previous step.
 - `skS` is an explicitly specified server long-term key
 - `sec` contains sensitive data and should be disposed securely after usage in this step.

The function returns a byte array:

 - `rec` should be stored by the server associated with the ID of the user.

**Important Note**: Confusingly this function is called `StoreUserRecord`, yet it
does not do any storage. How you want to store the record (`rec`) is up
to the implementor using this API.

## Establishing an opaque session

After a user has registered with a server, the user can initiate the
AKE and thus request its credentials in the following 3(+1)-step protocol:

### Step 1: The user initiates a credential request.

```java
OpaqueCredReq creq = o.createCredReq(pwd);
```

 - `pwd` is the user's password.

The output of this function is an instance of the `OpaqueCredReq`
class, which has two member variables:

 - `sec`: The user should hold onto this securely until step 3 of the protocol.
 - `pub` needs to be passed to the server running step 2.

### Step 2: The server responds to the credential request.

```java
OpaqueCredResp cresp = o.createCredResp(creq.pub, rec, cfg, ids);
```

The input parameters:

 - `pub` comes from the user running the previous step.
 - `rec` is the user's record stored by the server at the end of the registration protocol.
 - `cfg` is an array containing the envelope configuration,
 - `ids` is the an `OpaqueIds` instance containing the clients and servers ID.

This function returns an instance of the `OpaqueCredResp` class, which
has three member variables:

 - `resp` needs to be passed to the user running step 3.
 - `sk` is a shared secret, the result of the AKE.
 - `sec` is the servers sensitive context. The server should hold onto
   this valuesecurely until the optional step 4 of the protocol, if
   needed. otherwise this value should be discarded securely.

### Step 3: The user recovers its credentials from the server's response.

```java
OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, pkS, cfg, ids);
```

The input parameters:

 - `pub` comes from the server running the previous step.
 - `sec` contains the client sensitive data from the first step and
   should be disposed securely after this step.
 - `pkS` is the server's optional public key, this must be specified
   if the 3rd item in cfg is `NotPackaged` otherwise it must be nil
 - `cfg` is an array containing the envelope configuration,
 - `ids` is an instance of `OpaqueIds`, `idU` must be specified if the
   `idU` element of `cfg` is `NotPackaged`. Similarly `idS` must be
   specified if the `idU` element of `cfg` is `NotPackaged`.

This function returns an instance of the `OpaqueCreds` class, which
has four member variables:

 - `sk` is a shared secret, the result of the AKE.
 - `authU` is an authentication tag that can be passed in step 4 for
   explicit user authentication.
 - `export_key` can be used to decrypt additional data stored by the server.
 - `ids` is an instance of `OpaqueIds` containing IDs of the user and
   the server, this is useful if these are packaged in the envelope.

### Step 4 (Optional): The server authenticates the user.

This step is only needed if there is no encrypted channel setup
towards the server using the shared secret.

```java
if(!o.userAuth(cresp.sec, creds.authU)) throw new Exception("Authentication failed!");
```

The input parameters are:

 - `sec` contains the servers sensitive context from the second step
   and should be disposed securely after usage in this step.
 - `authU` comes from the user running the previous step.

The function returns a boolean `false` in case the authentication
failed, otherwise `true`.
