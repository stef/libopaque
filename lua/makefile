all: opaque.so

opaque.so: opaque.c
	gcc opaque.c -g -shared -o opaque.so -fPIC  $(shell pkgconf --libs lua) -lopaque

test: opaque.so
	./test.lua

clean:
	rm -f opaque.so
