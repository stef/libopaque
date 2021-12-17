all: opaque.beam opaque.so

opaque.beam: opaque.erl
	erlc opaque.erl

opaque.so: opaque.c
	gcc -fPIC -shared -o opaque.so opaque.c -lopaque -I/usr/lib/erlang/usr/include/

test: opaque.so opaque.beam
	escript test.erl

clean:
	rm -f erl_crash.dump
	rm -f opaque.beam
	rm -f opaque.so
