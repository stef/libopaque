# libopaque

This library implements the OPAQUE protocol as proposed by the IETF CFRG in
https://github.com/cfrg/draft-irtf-cfrg-opaque.

## Installing

Install `python`, `libsodium` and `libsodium-dev` using your operating system's
package manager.

Building everything should (hopefully) be quite simple afterwards:

```
git submodule update --init --recursive --remote
cd src
make
```

## OPAQUE API

The API is described in the header file:
[`src/opaque.h`](https://github.com/stef/libopaque/blob/master/src/opaque.h).

The library implements the OPAQUE protocol with the following deviations:

0. It does not implement any persistence/lookup functionality.
1. Instead of HMQV (which is patented), it implements a Triple-DH.
2. It implements "user iterated hashing" from page 29 of the paper.
3. It additionally implements a variant where U secrets never hit S
   unprotected.

For more information, see the IETF CFRG specification at
https://github.com/cfrg/draft-irtf-cfrg-opaque/blob/master/draft-irtf-cfrg-opaque.md,
the original paper
([`doc/opaque.pdf`](https://github.com/stef/libopaque/blob/master/doc/opaque.pdf))
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
$ LD_LIBRARY_PATH=. ./tests/opaque
```
