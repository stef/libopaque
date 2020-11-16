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

## OPAQUE API

The API is described in the header file: src/opaque.h.

The library implements the OPAQUE protocol with the following deviations:

 0. does not implement any persistence/lookup functionality.
 1. instead of HMQV (which is patented) it implements a Triple-DH instead.
 2. it implements "user iterated hashing" from page 29 of the paper
 3. additionally implements a variant where U secrets never hit S unprotected

For more information please see the IETF CFRG specification at
https://github.com/cfrg/draft-irtf-cfrg-opaque/blob/master/draft-irtf-cfrg-opaque.md
original paper (doc/opaque.pdf) and the `src/tests/opaque-test.c` example file.

## OPAQUE Parameters

Currently all parameters are hardcoded, but there's nothing stoping you
and set stronger values for the password hash.

### The Curve

This OPAQUE implementation is based on libsodiums ristretto25519 curve,
This means currently all keys are 32 byte long.

### Other Crypto building blocks

This OPAQUE implementation relies on libsodium as a dependency to
provide all other cryptographic primitives:

   - crypto_pwhash[1] uses the Argon2 function with
     `crypto_pwhash_OPSLIMIT_INTERACTIVE`,
     `crypto_pwhash_MEMLIMIT_INTERACTIVE` as security parameters.
   - randombytes attempts to use the cryptographic random source of
     the underlying operating system[2]

[1] https://download.libsodium.org/doc/password_hashing/the_argon2i_function
[2] https://download.libsodium.org/doc/generating_random_data
