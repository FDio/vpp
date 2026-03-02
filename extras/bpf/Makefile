CC := $(shell which clang)

# where to find bpf includes?
BPF_ROOT ?= /usr/include
#BPF_ROOT ?= /opt/vpp/external/x86_64/include

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
EXTERNAL_BPF_ROOT := /opt/vpp/external/$(shell uname -m)/include
MULTIARCH_BPF_ROOT := /usr/include/$(shell uname -m)-linux-gnu

CFLAGS := -O3 -g -Wextra -Wall -target bpf
# Workaround for Ubuntu/Debian for asm/types.h
CFLAGS += -I$(MULTIARCH_BPF_ROOT)
CFLAGS += -I$(BPF_ROOT)
CFLAGS += $(LIBBPF_CFLAGS)
ifneq ($(wildcard $(EXTERNAL_BPF_ROOT)/bpf/bpf_helpers.h),)
CFLAGS += -I$(EXTERNAL_BPF_ROOT)
endif
#CFLAGS += -DDEBUG

all: af_xdp.bpf.o af_xdp_mb.bpf.o

clean:
	$(RM) af_xdp.bpf.o af_xdp_mb.bpf.o

.PHONY: all clean
