# libopaque.js

The OPAQUE asymmetric password-authenticated key exchange protocol library
([libopaque](https://github.com/stef/libopaque)) compiled to WebAssembly and
pure JavaScript using [Emscripten](https://github.com/kripken/emscripten).

## Overview

libopaque implements the
[OPAQUE protocol](https://github.com/cfrg/draft-irtf-cfrg-opaque) as proposed
by the Internet Research Task Force (IRTF) Crypto Forum Research Group
(CFRG).

The OPAQUE protocol is a secure asymmetric password-authenticated key exchange
(aPAKE) that supports mutual authentication in a client-server setting without
reliance on PKI and with security against pre-computation attacks upon server
compromise. In addition, the protocol provides forward secrecy and the ability
to hide the password from the server, even during password registration.

## Installation

The [`dist`](https://github.com/stef/libopaque/tree/master/js/dist) directory
contains pre-built scripts. Copy one of the files to your application:

- [`libopaque.js`](https://github.com/stef/libopaque/tree/master/js/dist/libopaque.js)
  is a minified single-file script that you can include in webpages.
- [`libopaque.debug.js`](https://github.com/stef/libopaque/tree/master/js/dist/libopaque.debug.js)
  is a non-minified version of `libopaque.js` useful for debugging.

libopaque.js is also available on npm:
[libopaque](https://www.npmjs.com/package/libopaque).

## Usage

On the server side, see
[`demo/app.js`](https://github.com/stef/libopaque/tree/master/js/demo/app.js)
for example usage.

On the client side, see
[`demo/public/index.js`](https://github.com/stef/libopaque/tree/master/js/demo/public/index.js)
and
[`demo/public/index-worker.js`](https://github.com/stef/libopaque/tree/master/js/demo/public/index-worker.js)
for example usage.

## Running the Demo

If you have Node.js installed, here is how to run the demo:

```sh
$ # cd to this directory.
$ cd demo
$ npm install
$ node app.js
$ # Navigate to http://localhost:8080 in a browser.
$ # Type Ctrl+C to terminate.
```

Here is how to run the demo using Docker:

```sh
$ # cd to this directory.
$ docker run -it --publish 8080:8080 --rm \
  --name libopaque-demo \
  --user node \
  --volume "$(pwd)/..":/home/node/src \
  --workdir /home/node/src/js/demo \
  creemama/node-no-yarn:lts-alpine \
  sh -c 'npm install && node app.js'
$ # Navigate to http://localhost:8080 in a browser.
$ docker stop libopaque-demo
```

## Compilation

If you want to compile the files yourself, you need the following dependencies
installed on your system:

- Emscripten
- binaryen
- git
- NodeJS
- make

Running `make` will make `dist\libopaque.js` and `dist\libopaque.debug.js`. The
following is an example build using Docker:

```sh
$ # cd to this directory.
$ docker run -it --rm \
  --volume "$(pwd)/..":/src \
  --workdir /src/js \
  emscripten/emsdk:1.40.1 \
  bash -c 'apt update && apt install pkgconf uncrustify && make'
```
