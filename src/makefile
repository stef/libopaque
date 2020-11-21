PREFIX?=/usr/local
LIBS=-lsodium
CFLAGS=-march=native -Wall -fPIC -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -DTRACE -DNORANDOM
LDFLAGS=-g $(LIBS)
CC=gcc
SOEXT=so

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
	CFLAGS+= -Iaux
	EXTRA_OBJECTS+= aux/kdf_hkdf_sha256.o
else
	CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

all: bin libopaque.so tests

tests$(EXT): tests/opaque$(EXT) tests/opaque-munit

libopaque.$(SOEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(CC) -shared -fpic $(CFLAGS) -o libopaque.$(SOEXT) $^ $(LDFLAGS)

tests/opaque$(EXT): tests/opaque-test.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque$(EXT) tests/opaque-test.c -L. -lopaque $(LDFLAGS)

tests/opaque-munit$(EXT): tests/opaque_munit.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/munit-opaque$(EXT) tests/munit/munit.c tests/opaque_munit.c -L. -lopaque $(LDFLAGS)

test: tests/opaque-munit$(EXT)
	LD_PRELOAD=./libopaque.so ./tests/munit-opaque --fatal-failures

install: $(PREFIX)/lib/libopaque.$(SOEXT) $(PREFIX)/include/opaque.h

$(PREFIX)/lib/libopaque.$(SOEXT): libopaque.$(SOEXT)
	cp $< $@

$(PREFIX)/include/opaque.h: opaque.h
	cp $< $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f libopaque.so
	rm -f tests/opaque tests/opaque.exe *.o tests/opaque-munit$(EXT)
	rm -f libopaque.dll

.PHONY: bin clean install
