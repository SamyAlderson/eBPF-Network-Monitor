CC=gcc
CFLAGS=-Wall -Wextra -std=c11

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)
BIN=eBPF Network Monitor

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(BIN)

test:
	@echo "No tests configured"

.PHONY: all clean test
