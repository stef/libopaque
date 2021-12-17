opaque.so: opaque.c
	gcc opaque.c -g -shared -o opaque.so -fPIC  -llua -lopaque

test: opaque.so
	./test.lua

clean:
	rm -f opaque.so
