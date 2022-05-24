PREFIX?=/usr/local
LIBS=-lsodium
DEFINES=
CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack $(DEFINES)
LDFLAGS=-g $(LIBS)
CC=gcc
SOEXT=so

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
	CFLAGS+= -Iaux_
	EXTRA_OBJECTS+= aux_/kdf_hkdf_sha512.o
else
	CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif


win: CC=x86_64-w64-mingw32-gcc
win: CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -ftrapv $(DEFINES)
win: LIBS=-lsodium -lws2_32
win: SOEXT=dll
win: EXT=.exe
win: MAKETARGET=win
win: libopaque.$(SOEXT) tests utils/opaque


all: libopaque.$(SOEXT) tests utils/opaque
debug: DEFINES=-DTRACE -DNORANDOM
debug: all

asan: DEFINES=-DTRACE -DNORANDOM
asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,noexecstack $(DEFINES)
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

tests: tests/opaque-test$(EXT) tests/opaque-munit$(EXT) tests/opaque-tv1$(EXT)

libopaque.$(SOEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(CC) -shared $(CFLAGS) -Wl,-soname,libopaque.so -o libopaque.$(SOEXT) $^ $(LDFLAGS)

tests/opaque-test$(EXT): tests/opaque-test.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-test$(EXT) tests/opaque-test.c -L. -lopaque $(LDFLAGS)

tests/opaque-munit$(EXT): tests/opaque-munit.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-munit$(EXT) tests/munit/munit.c tests/opaque-munit.c -L. -lopaque $(LDFLAGS)

common-v.o: common.c
	$(CC) $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

opaque-tv1.o: opaque.c
	$(CC) $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

tests/opaque-tv1$(EXT): tests/opaque-testvectors.c opaque-tv1.o common-v.o
	$(CC) $(CFLAGS) -DCFRG_TEST_VEC -o $@ tests/opaque-testvectors.c common-v.o $(EXTRA_OBJECTS) opaque-tv1.o $(LDFLAGS)

test: tests
	./tests/opaque-tv1$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-test$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-munit$(EXT) --fatal-failures

utils/opaque: utils/main.c
	gcc $(CFLAGS) -I. -o utils/opaque utils/main.c -L. -lopaque -lsodium

install: $(PREFIX)/lib/libopaque.$(SOEXT) $(PREFIX)/include/opaque.h $(PREFIX)/bin/opaque

$(PREFIX)/lib/libopaque.$(SOEXT): libopaque.$(SOEXT)
	cp $< $@

$(PREFIX)/include/opaque.h: opaque.h
	cp $< $@

$(PREFIX)/bin/opaque: utils/opaque
	cp $< $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f \
		*.o \
		aux_/*.o \
		libopaque.dll \
		libopaque.so \
		tests/opaque-munit \
		tests/opaque-munit.exe \
		tests/opaque-munit.html \
		tests/opaque-munit.js \
		tests/opaque-test \
		tests/opaque-test.exe \
		tests/opaque-test.html \
		tests/opaque-test.js \
		tests/opaque-tv1 \
		tests/opaque-tv1.exe \
		tests/opaque-tv1.html \
		tests/opaque-tv1.js \
		utils/opaque

.PHONY: all clean debug install test
