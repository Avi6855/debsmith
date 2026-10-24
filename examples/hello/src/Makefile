CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
PREFIX ?= /usr

hello: hello.c
	$(CC) $(CFLAGS) -o hello hello.c

install: hello
	install -Dm755 hello $(DESTDIR)$(PREFIX)/bin/hello

clean:
	rm -f hello

.PHONY: install clean
