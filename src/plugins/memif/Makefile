CC=gcc

LDFLAGS += -lm -lrt -Wl,--no-as-needed -ldl -lcrypto

CFLAGS += -Wall -fPIC -g -c

OFILE = memif_lib.o
AFILE = libmemif_lib.a

OBJS = memif_lib.c
DEPS = $(OBJS) memif_lib.h

TESTFILE = memif_test.c
TESTOUT = memif_test

.PHONY: help build build-lib build-test

help:
	@echo " build         compile memif_lib.o"
	@echo " build-lib     make libmemif.a"
	@echo " build-test    compile memif_test binary"

build: $(DEPS)
	$(CC) -o $(OFILE) $(CFLAGS) $(LDFLAGS) $(OBJS)

build-lib: $(OFILE)
	ar cr $(AFILE) $(OFILE)

$(OFILE): $(DEPS)
	$(CC) -o $(OFILE) $(CFLAGS) $(LDFLAGS) $(OBJS)

$(AFILE): $(OFILE)
	ar cr $(AFILE) $(OFILE)

build-test: $(AFILE)
	$(CC) -o $(TESTOUT) $(TESTFILE) $(AFILE)
