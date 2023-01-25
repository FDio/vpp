CC := $(shell which clang)

# where to find bpf includes?
BPF_ROOT := /opt/vpp/build-root/install-vpp-native/external/include

CFLAGS := -O2 -g -Wextra -Wall -target bpf
CFLAGS += -I$(BPF_ROOT)
# Workaround for Ubuntu/Debian for asm/types.h
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -DDEBUG

all: af_xdp.bpf.o

clean:
	$(RM) af_xdp.bpf.o

.PHONY: all clean
