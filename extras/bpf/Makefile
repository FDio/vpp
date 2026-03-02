CC := $(shell which clang)

# where to find bpf includes?
BPF_ROOT ?= /usr/include
#BPF_ROOT ?= /opt/vpp/external/x86_64/include

CFLAGS := -O3 -g -Wextra -Wall -target bpf
# Workaround for Ubuntu/Debian for asm/types.h
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -I$(BPF_ROOT)
#CFLAGS += -DDEBUG

all: af_xdp.bpf.o af_xdp_mb.bpf.o

clean:
	$(RM) af_xdp.bpf.o af_xdp_mb.bpf.o

.PHONY: all clean
