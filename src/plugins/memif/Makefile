CC=gcc

LDFLAGS += -lm -lrt -Wl,--no-as-needed -ldl -lcrypto

CFLAGS += -Wall -fPIC -g -c
SCFLAGS += -Wall -fPIC -g

SRCS = memif_lib.c memif_lib_sock.c
OBJS = $(SRCS:.c=.o)
SOBJS = $(SRCS:.c=.so)
DEPS = $(OBJS) memif_lib.h memif_lib_vec.h memif_lib_priv.h

AFILE = libmemif_lib.a
SAFILE = libmemif_lib_s.a

TESTFILE = memif_lib_test.c
TESTOUT = memif_lib_test

.PHONY: help build build-shared build-lib build-shared-lib build-test

help:
	@echo " build               compile static libraries"
	@echo " build-shared        compile shared libraries"
	@echo " build-lib           make archive containing static libraries"
	@echo " build-shared-lib    make archive containing shared libraries"
	@echo " build-test          compile demo binary -> memif_lib_test"

build: $(DEPS)
	$(foreach src, $(SRCS), $(CC) -o $(src:.c=.o) $(LDFLAGS) $(CFLAGS) $(src);)

build-shared: $(OBJS)
	$(foreach obj, $(OBJS), $(CC) -shared -o $(obj:.o=.so) $(LDFLAGS) $(SCFLAGS) $(obj);)

build-lib: $(OBJS)
	ar cr $(AFILE) $(OBJS)

build-shared-lib: $(SOBJS)
	ar cr $(SAFILE) $(SOBJS)

$(OBJS): $(DEPS)
	$(foreach src, $(SRCS), $(CC) -o $(src:.c=.o) $(LDFLAGS) $(CFLAGS) $(src);)

$(AFILE): $(OBJS)
	ar cr $(AFILE) $(OBJS)

build-test: $(AFILE)
	$(CC) -o $(TESTOUT) $(LDFLAGS) $(SCFLAGS) $(TESTFILE) $(AFILE)
