CFLAGS=-Wall -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack
LDFLAGS=-flto -lopaque

libopaque.so: utils.c opaque.c
	gcc -shared $(CFLAGS) -o $@ opaque.c $(LDFLAGS)

clean:
	rm -f libopaque.so
