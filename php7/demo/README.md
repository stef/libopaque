# libopaque PHP Server and JavaScript Web Client Demo

## Building and Running

```sh
$ docker run -it -p 8080:8080 --rm --volume $(pwd):/tmp --workdir /tmp ubuntu:focal bash
$ cd src
$ apt update
$ apt install -y build-essential git libsodium-dev php php-apcu php-dev pkgconf vim
$ git submodule update --init --recursive tests/munit
$ make
$ cd ../php7
$ phpize
$ LIBOPAQUE_CFLAGS='-I ../src' LIBOPAQUE_LIBS='-lopaque' ./configure
$ LD_LIBRARY_PATH=../src TEST_PHP_ARGS=-q make EXTRA_CFLAGS=-I../src EXTRA_LDFLAGS=-L../src test
$ ln -s /tmp/php7/modules/opaque.so /usr/lib/php/20190902/opaque.so
$ vi /etc/php/7.4/cli/php.ini # Add extension=opaque to the "Dynamic Extensions" section.
$ demo/app.sh # Navigate to http://localhost:8080 in a browser.
```
