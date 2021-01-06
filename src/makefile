PREFIX?=/usr/local
LIBS=-lsodium
DEFINES=
#DEFINES=-DTRACE -DNORANDOM
CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack $(DEFINES)
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

all: libopaque.so tests

tests: tests/opaque-test$(EXT) tests/opaque-munit$(EXT)

libopaque.$(SOEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(CC) -shared -fpic $(CFLAGS) -o libopaque.$(SOEXT) $^ $(LDFLAGS)

tests/opaque-test$(EXT): tests/opaque-test.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-test$(EXT) tests/opaque-test.c -L. -lopaque $(LDFLAGS)

tests/opaque-munit$(EXT): tests/opaque-munit.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-munit$(EXT) tests/munit/munit.c tests/opaque-munit.c -L. -lopaque $(LDFLAGS)

test: tests
	LD_LIBRARY_PATH=. ./tests/opaque-test$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-munit$(EXT) --fatal-failures

install: $(PREFIX)/lib/libopaque.$(SOEXT) $(PREFIX)/include/opaque.h

$(PREFIX)/lib/libopaque.$(SOEXT): libopaque.$(SOEXT)
	cp $< $@

$(PREFIX)/include/opaque.h: opaque.h
	cp $< $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f \
		*.o \
		aux/*.o \
		libopaque.dll \
		libopaque.so \
		tests/opaque-munit \
		tests/opaque-munit.exe \
		tests/opaque-test \
		tests/opaque-test.exe

.PHONY: all clean install test
