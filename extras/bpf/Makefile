CC := $(shell which clang)

# where to find bpf includes?
BPF_ROOT ?= /usr/include
#BPF_ROOT ?= /opt/vpp/build-root/install-vpp-native/external/include

CFLAGS := -O2 -g -Wextra -Wall -target bpf
# Workaround for Ubuntu/Debian for asm/types.h
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -I$(BPF_ROOT)
#CFLAGS += -DDEBUG

all: af_xdp.bpf.o

clean:
	$(RM) af_xdp.bpf.o

.PHONY: all clean
