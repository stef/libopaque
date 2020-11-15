# OPAQUE Parameters

Currently all parameters are hardcoded, but there's nothing stoping you
and set stronger values for the password hash.

## The Curve

This OPAQUE implementation is based on libsodiums ristretto25519 curve,
This means currently all keys are 32 byte long.

## Other Crypto building blocks

This OPAQUE implementation relies on libsodium as a dependency to
provide all other cryptographic primitives:

   - crypto_pwhash[3] uses the Argon2 function with
     `crypto_pwhash_OPSLIMIT_INTERACTIVE`,
     `crypto_pwhash_MEMLIMIT_INTERACTIVE` as security parameters.
   - randombytes attempts to use the cryptographic random source of
     the underlying operating system[4]


[3] https://download.libsodium.org/doc/password_hashing/the_argon2i_function
[4] https://download.libsodium.org/doc/generating_random_data
