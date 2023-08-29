PREFIX?=/usr/local
LIBS=-lsodium -loprf
DEFINES=
CFLAGS?=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic \
		  -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration \
        -Warray-bounds -fsanitize=bounds -fsanitize-undefined-trap-on-error \
        -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack -std=c99 $(DEFINES)
        #-fstrict-flex-arrays
LDFLAGS=-g $(LIBS)
CC=gcc
SOEXT=so
AEXT=a
SOVER=0

AR?=ar

SODIUM_NEWER_THAN_1_0_18 := $(shell pkgconf --atleast-version=1.0.19 libsodium; echo $$?)
ifeq ($(SODIUM_NEWER_THAN_1_0_18),1)
	CFLAGS+= -Iaux_
	EXTRA_OBJECTS+= aux_/kdf_hkdf_sha512.o
else
	CFLAGS+= -DHAVE_SODIUM_HKDF=1
endif

ifdef OPRFHOME
	OPRFINCDIR=$(OPRFHOME)
	LDFLAGS+= -L$(OPRFHOME)

else
	OPRFINCDIR=/usr/include/oprf
endif

all: libopaque.$(SOEXT) libopaque.$(AEXT) tests utils/opaque

debug: DEFINES=-DTRACE -DNORANDOM
debug: all

asan: DEFINES=-DTRACE -DNORANDOM
asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,noexecstack $(DEFINES)
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

mingw64: CC=x86_64-w64-mingw32-gcc
mingw64: CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -ftrapv $(DEFINES)
mingw64: LIBS=-L. -lws2_32 -Lwin/libsodium-win64/lib/ -Wl,-Bstatic -lsodium -Wl,-Bdynamic
mingw64: INC=-Iwin/libsodium-win64/include/sodium -Iwin/libsodium-win64/include
mingw64: SOEXT=dll
mingw64: EXT=.exe
mingw64: MAKETARGET=mingw
mingw64: win/libsodium-win64 libopaque.$(SOEXT) tests utils/opaque

TESTS=tests/opaque-test$(EXT) tests/opaque-munit$(EXT)
ifeq ($(shell test -e $(OPRFHOME)/oprf.c && echo -n yes),yes)
	TESTS+=tests/opaque-tv1$(EXT)
endif

tests: $(TESTS)

libopaque.$(SOEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(CC) -shared $(CFLAGS) -Wl,-soname,libopaque.so.$(SOVER) -o libopaque.$(SOEXT) $^ $(LDFLAGS) 

libopaque.$(AEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(AR) -rcs libopaque.$(AEXT) $^

tests/opaque-test$(EXT): tests/opaque-test.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-test$(EXT) tests/opaque-test.c -L. -lopaque $(LDFLAGS)

tests/opaque-munit$(EXT): tests/opaque-munit.c libopaque.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/opaque-munit$(EXT) tests/munit/munit.c tests/opaque-munit.c -L. -lopaque $(LDFLAGS)

common-v.o: common.c
	$(CC) $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

opaque-tv1.o: opaque.c
	$(CC) $(CFLAGS) -I$(OPRFHOME) -DCFRG_TEST_VEC -o $@ -c $<

oprf-v.o: $(OPRFHOME)/oprf.c
	$(CC) -I. $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

tests/opaque-tv1$(EXT): tests/opaque-testvectors.c common-v.o oprf-v.o opaque-tv1.o 
	$(CC) $(CFLAGS) -DCFRG_TEST_VEC -o $@ $^ $(EXTRA_OBJECTS) -lsodium -g

test: tests
	./tests/opaque-tv1$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-test$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-munit$(EXT) --fatal-failures

utils/opaque: utils/main.c
	gcc $(CFLAGS) -I. -o utils/opaque utils/main.c -L. $(LDFLAGS) -lopaque -lsodium

install: $(PREFIX)/lib/libopaque.$(SOEXT) $(PREFIX)/lib/libopaque.$(AEXT) $(PREFIX)/include/opaque.h $(PREFIX)/bin/opaque

uninstall: $(PREFIX)/lib/libopaque.$(SOEXT) $(PREFIX)/lib/libopaque.$(AEXT) $(PREFIX)/include/opaque.h $(PREFIX)/bin/opaque
	rm $^

$(PREFIX)/lib/libopaque.$(SOEXT): libopaque.$(SOEXT)
	install -D $< $@.$(SOVER)
	ln -fs $@.$(SOVER) $@

$(PREFIX)/lib/libopaque.$(AEXT): libopaque.$(AEXT)
	cp $< $@


$(PREFIX)/include/opaque.h: opaque.h
	cp $< $@

$(PREFIX)/bin/opaque: utils/opaque
	cp $< $@

opaque.o: opaque.c
	$(CC) $(CFLAGS) -I$(OPRFINCDIR) -o $@ -c $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

win/libsodium-win64:
	@echo 'win/libsodium-win64 not found.'
	@echo 'download and unpack latest libsodium-*-mingw.tar.gz and unpack into win/'
	@echo 'https://download.libsodium.org/libsodium/releases/'
	@false

clean:
	rm -f \
		*.o \
		aux_/*.o \
		libopaque.dll \
		libopaque.so \
		libopaque.a \
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
