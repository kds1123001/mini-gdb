CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -Iinclude
SRC = src/elf_parser.c src/ptrace_wrapper.c src/breakpoint.c src/dbgregs.c src/main.c
BIN = minigdb

.PHONY: all clean test-target

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

test-target: test/target.c
	$(CC) -O0 -g -fno-pie -no-pie -o test/target test/target.c

clean:
	rm -f $(BIN) test/target
