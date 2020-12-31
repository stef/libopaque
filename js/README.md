# libopaque.js

## Overview

The OPAQUE asymmetric password-authenticated key exchange (PAKE) protocol library
([libopaque](https://github.com/stef/libopaque)) compiled to WebAssembly and
pure JavaScript using [Emscripten](https://github.com/kripken/emscripten).

## Installation

The [dist](https://github.com/stef/libopaque/tree/master/js/dist) directory
contains pre-built scripts. Copy one of the files to your application:

- [libopaque.js](https://github.com/stef/libopaque/tree/master/js/dist/libopaque.js)
  is a minified single-file script that you can include in webpages.
- [libopaque.debug.js](https://github.com/stef/libopaque/tree/master/js/dist/libopaque.debug.js)
  is a non-minified version of `libopaque.js` useful for debuggin.

libopaque.js is also available on npm:

- [libopaque](https://www.npmjs.com/package/libopaque)

### Usage

On the server side, see demo/app.js for example usage.

On the client side, see demo/public/index.js and demo/public/index-worker.js
for example usage.

### Compilation

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
  --volume $(pwd)/..:/src \
  --workdir /src/js \
  emscripten/emsdk:1.40.1 \
  sh -c "apt-get update && apt-get install pkgconf uncrustify && make"
```
