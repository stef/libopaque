PREFIX?=/usr/local
LIBS=-lsodium -loprf
DEFINES=
CFLAGS?=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables \
		  -Werror=format-security -Werror=implicit-function-declaration \
        -Warray-bounds -fsanitize=bounds -fsanitize-undefined-trap-on-error -ftrapv $(DEFINES)
        #-fstrict-flex-arrays
CFLAGS+= -std=c99 -fpic
LDFLAGS=-g $(LIBS)
CC?=gcc
AEXT=a
SOVER=0

AR?=ar

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(UNAME),Darwin)
	SOEXT=dylib
	SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/libopaque.$(SOEXT)
else
	CFLAGS+=-Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now \
			  -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error
	#		  -mbranch-protection=standard -fstrict-flex-arrays=3 
	SOEXT=so
	SOFLAGS=-Wl,-soname,libopaque.$(SOEXT).$(SOVER)
   ifeq ($(ARCH),x86_64)
      CFLAGS+=-fcf-protection=full
   endif

   ifeq ($(ARCH),parisc64)
   else ifeq ($(ARCH),parisc64)
   else
      CFLAGS+=-fstack-clash-protection
   endif
endif

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

ifneq (, $(shell which pandoc))
	MANPAGES=man
	MANPAGES-clean=man-clean
	MANPAGES-install=man-install
	MANPAGES-uninstall=man-uninstall
endif


all: libopaque.$(SOEXT) libopaque.$(AEXT) tests utils/opaque $(MANPAGES)

debug: DEFINES=-DTRACE -DNORANDOM
debug: all

asan:
	CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,noexecstack $(DEFINES)
	ifeq ($(ARCH),x86_64)
	   CFLAGS+=-fcf-protection=full
	endif
	ifeq ($(ARCH),parisc64)
	else ifeq ($(ARCH),parisc64)
	else
	   CFLAGS+=-fstack-clash-protection
	endif
asan: DEFINES=-DTRACE -DNORANDOM
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

mingw64:
	 CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -Werror=format-security -Werror=implicit-function-declaration -ftrapv $(DEFINES)
	ifeq ($(ARCH),x86_64)
	   CFLAGS+=-fcf-protection=full
	endif
	ifeq ($(ARCH),parisc64)
	else ifeq ($(ARCH),parisc64)
	else
	   CFLAGS+=-fstack-clash-protection
	endif
mingw64: CC=x86_64-w64-mingw32-gcc
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
	$(CC) -shared $(CFLAGS) $(SOFLAGS) -o libopaque.$(SOEXT) $^ $(LDFLAGS) 
	ln -fs libopaque.$(SOEXT) libopaque.so.$(SOVER)

libopaque.$(AEXT): common.o opaque.o $(EXTRA_OBJECTS)
	$(AR) -rcs libopaque.$(AEXT) $^

tests/opaque-test$(EXT): tests/opaque-test.c libopaque.$(SOEXT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tests/opaque-test$(EXT) tests/opaque-test.c -L. -lopaque $(LDFLAGS)

tests/opaque-munit$(EXT): tests/opaque-munit.c libopaque.$(SOEXT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tests/opaque-munit$(EXT) tests/munit/munit.c tests/opaque-munit.c -L. -lopaque $(LDFLAGS)

common-v.o: common.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

opaque-tv1.o: opaque.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(OPRFHOME) -DCFRG_TEST_VEC -o $@ -c $<

oprf-v.o: $(OPRFHOME)/oprf.c
	$(CC) -I. $(CPPFLAGS) $(CFLAGS) -DCFRG_TEST_VEC -o $@ -c $<

tests/opaque-tv1$(EXT): tests/opaque-testvectors.c common-v.o oprf-v.o opaque-tv1.o 
	$(CC) $(CPPFLAGS) $(CFLAGS) -DCFRG_TEST_VEC -o $@ $^ $(EXTRA_OBJECTS) -lsodium -loprf -g

test: tests
	test -x ./tests/opaque-tv1$(EXT) && ./tests/opaque-tv1$(EXT) || true
	LD_LIBRARY_PATH=. ./tests/opaque-test$(EXT)
	LD_LIBRARY_PATH=. ./tests/opaque-munit$(EXT) --fatal-failures

utils/opaque: utils/main.c libopaque.$(SOEXT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o utils/opaque utils/main.c -L. $(LDFLAGS) -lopaque -lsodium

install: $(DESTDIR)$(PREFIX)/lib/libopaque.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/libopaque.$(AEXT) $(DESTDIR)$(PREFIX)/include/opaque.h $(DESTDIR)$(PREFIX)/bin/opaque $(MANPAGES-install)

uninstall: $(DESTDIR)$(PREFIX)/lib/libopaque.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/libopaque.$(AEXT) $(DESTDIR)$(PREFIX)/include/opaque.h $(DESTDIR)$(PREFIX)/bin/opaque $(MANPAGES-uninstall)
	rm $^

man:
	make -C utils/man

man-clean:
	make -C utils/man clean

man-install:
	make -C utils/man install

man-uninstall:
	make -C utils/man uninstall

$(DESTDIR)$(PREFIX)/lib/libopaque.$(SOEXT): libopaque.$(SOEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@.$(SOVER)
	ln -fs $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/libopaque.$(AEXT): libopaque.$(AEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@

$(DESTDIR)$(PREFIX)/include/opaque.h: opaque.h
	mkdir -p $(DESTDIR)$(PREFIX)/include
	cp $< $@

$(DESTDIR)$(PREFIX)/bin/opaque: utils/opaque
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $@

opaque.o: opaque.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(OPRFINCDIR) -o $@ -c $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

win/libsodium-win64:
	@echo 'win/libsodium-win64 not found.'
	@echo 'download and unpack latest libsodium-*-mingw.tar.gz and unpack into win/'
	@echo 'https://download.libsodium.org/libsodium/releases/'
	@false

clean: $(MANPAGES-clean)
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
