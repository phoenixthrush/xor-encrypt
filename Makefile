UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    CFLAGS := -I/opt/homebrew/opt/openssl@3/include
    LDFLAGS := -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
    CC := gcc
else ifeq ($(UNAME_S),Linux)
    CFLAGS := -I/usr/local/opt/openssl/include
    LDFLAGS := -L/usr/local/opt/openssl/lib -lssl -lcrypto
    CC := gcc
else
    CFLAGS := -IC:\\Program\ Files\\OpenSSL-Win64\\include
    LDFLAGS := -LC:\\Program\ Files\\OpenSSL-Win64\\lib -lssl -lcrypto
    CC := gcc
endif

SRC := main.c
OUT := build/main

all: $(OUT)

$(OUT): $(SRC)
	mkdir -p build
	$(CC) -o $(OUT) $(SRC) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OUT)

.PHONY: all clean
