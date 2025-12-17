CC=gcc
CFLAGS=-Wall -Wextra -g -O0
LDFLAGS=-lelf

all: ptrace_guard

ptrace_guard: ptrace_guard.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f ptrace_guard
