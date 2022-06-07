
CC=gcc
CXX=g++

.PHONY: all
all: hello deadlock variables

hello: hello.c
	$(CC) $< -o $@

deadlock: deadlock.c
	$(CC) $< -o $@

variables: variables.c
	$(CC) $< -o $@

clean:
	rm -rf hello deadlock variables

