
CC=emcc
#DEFINES=
DEFINES=-DTRACE -DNORANDOM

# Note that common.h has an __EMSCRIPTEN__ preprocessor macro that replaces
# sodium_m(un)?lock.

# LIBOPAQUE_CFLAGS should closely match CFLAGS in ../src/makefile. We note
# exceptions below:
# - We added -I../js/libsodium.js/libsodium/src/libsodium/include.
# - We removed -fcf-protection=full because of the following two errors:
#   - error: option 'cf-protection=return' cannot be specified on this target
#   - error: option 'cf-protection=branch' cannot be specified on this target
# - We replaced -fstack-protector-strong with -fno-stack-protector because of
#   the following errors when compiling opaque-test.c:
#   - error: undefined symbol: __stack_chk_fail (referenced by top-level compiled C/C++ code)
#   - warning: Link with `-s LLD_REPORT_UNDEFINED` to get more information on undefined symbols
#   - warning: To disable errors for undefined symbols use `-s ERROR_ON_UNDEFINED_SYMBOLS=0`
#   - warning: ___stack_chk_fail may need to be added to EXPORTED_FUNCTIONS if it arrives from a system library
#   - Error: Aborting compilation due to previous errors
# - We moved several flags to LIBOPAQUE_LDFLAGS because of the following
#   warnings:
#   - emcc: warning: argument unused during compilation: '-z' [-Wunused-command-line-argument]
#   - emcc: warning: argument unused during compilation: 'defs' [-Wunused-command-line-argument]
#   - emcc: warning: argument unused during compilation: '-z' [-Wunused-command-line-argument]
#   - emcc: warning: argument unused during compilation: 'relro' [-Wunused-command-line-argument]
#   - emcc: warning: argument unused during compilation: '-z' [-Wunused-command-line-argument]
#   - emcc: warning: argument unused during compilation: 'noexecstack' [-Wunused-command-line-argument]
# - We moved the following to LDFLAGS in "make ... libopaque.so" because of the
#   following warning. We did not add it to "make ... tests.html" or
#   "make ... tests.js" because the warning still appears.
#   - clang-12: warning: argument unused during compilation: '-fstack-clash-protection' [-Wunused-command-line-argument]
# TODO Write a verifier to ensure LIBOPAQUE_CFLAGS closely matches CFLAGS in
#      ../src/makefile.
LIBOPAQUE_CFLAGS=\
-I../js/libsodium.js/libsodium/src/libsodium/include \
-march=native \
-Wall \
-O2 \
-g \
-fno-stack-protector \
-D_FORTIFY_SOURCE=2 \
-fasynchronous-unwind-tables \
-fpic \
-Werror=format-security \
-Werror=implicit-function-declaration \
-ftrapv \
$(DEFINES)

CFLAGS=$(LIBOPAQUE_CFLAGS) -I../src

EXPORTED_FUNCTIONS=\
"_opaquejs_crypto_auth_hmacsha512_BYTES", \
"_opaquejs_crypto_core_ristretto255_BYTES", \
"_opaquejs_crypto_hash_sha512_BYTES", \
"_opaquejs_crypto_scalarmult_BYTES", \
"_opaquejs_crypto_scalarmult_SCALARBYTES", \
"_opaquejs_OPAQUE_USER_RECORD_LEN", \
"_opaquejs_OPAQUE_USER_SESSION_PUBLIC_LEN", \
"_opaquejs_OPAQUE_USER_SESSION_SECRET_LEN", \
"_opaquejs_OPAQUE_SERVER_SESSION_LEN", \
"_opaquejs_OPAQUE_REGISTER_USER_SEC_LEN", \
"_opaquejs_OPAQUE_REGISTER_PUBLIC_LEN", \
"_opaquejs_OPAQUE_REGISTER_SECRET_LEN", \
"_opaquejs_OPAQUE_SHARED_SECRETBYTES", \
"_opaquejs_OPAQUE_REGISTRATION_RECORD_LEN", \
"_opaquejs_GenServerKeyPair", \
"_opaquejs_Register", \
"_opaquejs_CreateCredentialRequest", \
"_opaquejs_CreateCredentialResponse", \
"_opaquejs_RecoverCredentials", \
"_opaquejs_UserAuth", \
"_opaquejs_CreateRegistrationRequest", \
"_opaquejs_CreateRegistrationResponse", \
"_opaquejs_FinalizeRequest", \
"_opaquejs_StoreUserRecord", \
"_free", \
"_malloc"

EXPORTED_RUNTIME_METHODS=\
"cwrap", \
"getValue", \
"setValue", \
"stringToUTF8", \
"UTF8ToString"

# LIBOPAQUE_LDFLAGS should closely match LDFLAGS in ../src/makefile. We note
# exceptions below:
# - We added -L../js/libsodium.js/libsodium/src/libsodium/.libs so that the
#   linker can find libsodium.
# - See LIBOPAQUE_CFLAGS for why we include -fstack-clash-protection the
#   various -Wl,-z flags here.
# TODO Write a verifier to ensure LIBOPAQUE_LDFLAGS closely matches LDFLAGS in
#      ../src/makefile.
LIBOPAQUE_LDFLAGS=\
-g \
-L../js/libsodium.js/libsodium/src/libsodium/.libs \
-lsodium \
-Wl,-z,defs \
-Wl,-z,relro \
-Wl,-z,noexecstack

LDFLAGS=\
-L../src \
-lopaque \
-Wl,-z,defs \
-Wl,-z,relro \
-Wl,-z,noexecstack

all: libsodium libopaque libopaque-tests libopaquejs

all-libopaque: clean-libopaque libopaque libopaque-tests

all-libopaquejs: clean-libopaquejs format libopaquejs es-check

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

# See the comments for LIBOPAQUE_CFLAGS for why -fstack-clash-protection
# appears for libopaque.so but not for tests.html or tests.js.
../src/libopaque.so:
	make \
		--directory=../src \
		CC=$(CC) \
		CFLAGS='$(LIBOPAQUE_CFLAGS)' \
		LDFLAGS='$(LIBOPAQUE_LDFLAGS) -fstack-clash-protection' \
		libopaque.so

../src/tests/opaque-test.html:
	make \
		--directory=../src \
		CC=$(CC) \
		CFLAGS='$(LIBOPAQUE_CFLAGS) --pre-js ../js/test/libopaque-test-pre.js -s ALLOW_MEMORY_GROWTH=1 -s SINGLE_FILE=1' \
		EXT=.html \
		LDFLAGS='$(LIBOPAQUE_LDFLAGS)' \
		tests
	make \
		--directory=../src \
		CC=$(CC) \
		CFLAGS='$(LIBOPAQUE_CFLAGS) --pre-js ../js/test/libopaque-test-pre.js -s ALLOW_MEMORY_GROWTH=1 -s SINGLE_FILE=1' \
		EXT=.js \
		LDFLAGS='$(LIBOPAQUE_LDFLAGS)' \
		tests

build: clean format all es-check test

clean-all: clean-libsodium clean-libopaque clean-libopaquejs

clean: clean-libopaque clean-libopaquejs

clean-libopaque:
	make --directory=../src clean

clean-libopaquejs:
	rm -rf dist/libopaque.debug.js dist/libopaque.js wrapper/opaquejs.o

clean-libsodium:
	make --directory=libsodium.js clean

dist/libopaque.js: wrapper/opaquejs.o node_modules wrapper/libopaque-post.js wrapper/libopaque-pre.js
	$(CC) \
	$(CFLAGS) \
	--post-js wrapper/libopaque-post.js \
	--pre-js wrapper/libopaque-pre.js \
	-s ALLOW_MEMORY_GROWTH=1 \
	-s EXPORTED_FUNCTIONS='[$(EXPORTED_FUNCTIONS)]' \
	-s EXPORTED_RUNTIME_METHODS='[$(EXPORTED_RUNTIME_METHODS)]' \
	-s SINGLE_FILE=1 \
	-o dist/libopaque.debug.js \
	wrapper/opaquejs.o \
	$(LDFLAGS) \
	-fstack-clash-protection
	npx terser --output dist/libopaque.js -- dist/libopaque.debug.js

# Check that our JavaScript is ES6-compatible.
es-check: node_modules
	npx es-check es6 dist/*.js --verbose
	npx es-check es6 demo/public/*.js --verbose

# Even though the following 3 lines
#
# cat wrapper/libopaque-pre.js >> wrapper/libopaque-pre.tmp
# printf "}})();" >> wrapper/libopaque-pre.tmp
# mv wrapper/libopaque-pre.tmp wrapper/libopaque-pre.js
#
# could be simplified to just
#
# printf "}})();" >> wrapper/libopaque-pre.js
#
# introducing the TMP file prevents the following intermittent error:
# [error] wrapper/libopaque-pre.js: SyntaxError: Unexpected character '' (1315:1)
# [error]   1313 |       Module["postRun"] = [resolveFunction, postCwrap];
# [error]   1314 |     }
# [error] > 1315 | }})();
# [error]        | ^
format: node_modules
	npx sort-package-json package.json demo/package.json
	# Make the syntax valid for partial JavaScript files.
	cat wrapper/libopaque-pre.js >> wrapper/libopaque-pre.tmp
	printf "});}})();" >> wrapper/libopaque-pre.tmp
	mv wrapper/libopaque-pre.tmp wrapper/libopaque-pre.js
	printf "(function(){{(function(){\"use strict\";\n" >> wrapper/libopaque-post.tmp
	cat wrapper/libopaque-post.js >> wrapper/libopaque-post.tmp
	rm wrapper/libopaque-post.js
	mv wrapper/libopaque-post.tmp wrapper/libopaque-post.js
	npx prettier --write .
	# Remove the last two lines of libopaque-pre.js.
	sed -i '$$d' wrapper/libopaque-pre.js
	sed -i '$$d' wrapper/libopaque-pre.js
	sed -i '$$d' wrapper/libopaque-pre.js
	# Remove the first two lines of libopaque-post.js.
	sed -i '1d;2d;3d;4d' wrapper/libopaque-post.js
	uncrustify -c uncrustify.cfg --no-backup wrapper/opaquejs.c wrapper/opaquejs.h

libopaque: ../src/libopaque.so

libopaque-tests: ../src/tests/opaque-test.html

libopaquejs: dist/libopaque.js

libsodium: libsodium.js/Makefile
	make --directory=libsodium.js sumo

libsodium.js/Makefile:
	git submodule update --init --recursive

node_modules:
	npm install

test: testjs
	./test/libopaque-test.js
	./test/libopaque-munit.js --fatal-failures

testjs: all
	./test/libopaquejs-test-1-step-register.js
	./test/libopaquejs-test-global-pkS.js
	./test/libopaquejs-test-per-user-pkS.js

update: node_modules
	npx npm-check-updates --upgrade
	npx npm-check-updates --upgrade --packageFile demo/package.json
	npm install
	cd demo && npm install

.PHONY: all all-libopaque all-libopaquejs build clean clean-libopaque clean-libopaquejs clean-libsodium es-check format libopaque libopaque-tests libopaquejs libsodium test testjs update clean-all
