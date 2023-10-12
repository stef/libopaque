all: opaque.1

install: $(DESTDIR)$(PREFIX)/share/man/man1/opaque.1

uninstall: $(DESTDIR)$(PREFIX)/share/man/man1/opaque.1
	rm $^

$(DESTDIR)$(PREFIX)/share/man/man1/opaque.1: opaque.1
	install -D $< $@

clean:
	   rm -f *.1

%.1: %.md
	   pandoc -s  -o $@ $<
