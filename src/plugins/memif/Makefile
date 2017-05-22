CC=gcc

export CPATH := /vpp-gerrit/src:$(CPATH)
INFRA = /vpp-gerrit/src/vppinfra/
VLIB = /vpp-gerrit/src/vlib/

VPP_LIBS += -lvlibmemoryclient
VPP_LIBS += -lsvm
VPP_LIBS += -lvppinfra
VPP_LIBS += -lvlib

LDFLAGS += $(VPP_LIBS)
LDFLAGS += -pthread -lm -lrt -Wl,--no-as-needed -ldl -lcrypto

CFLAGS += -fPIC -g
OBJS = memif_test.c memif_lib.c \
    $(INFRA)mhash.c \
    $(INFRA)vec.c \
    $(INFRA)mem_mheap.c \
    $(INFRA)mheap.c \
    $(INFRA)hash.c \
    $(INFRA)unix-misc.c \
    $(INFRA)error.c \
    $(INFRA)format.c \
    $(INFRA)unformat.c \
    $(INFRA)std-formats.c \
    $(INFRA)backtrace.c \
    $(INFRA)elf_clib.c \
    $(INFRA)elf.c \
    $(INFRA)heap.c \
    $(VLIB)unix/main.c \
    $(VLIB)main.c \
    $(VLIB)init.c \
    $(VLIB)trace.c \
    $(VLIB)threads.c \
    $(VLIB)buffer.c \
    $(VLIB)cli.c \
    $(VLIB)unix/cli.c \
    $(VLIB)format.c \
    $(INFRA)cpu.c \
    $(VLIB)unix/physmem.c \
    $(INFRA)time.c \
    $(INFRA)elog.c \
    $(INFRA)serialize.c \
    $(INFRA)longjmp.S \
    $(VLIB)node_format.c \
    $(VLIB)node_cli.c \
    $(VLIB)node.c \
    $(VLIB)error.c \
    $(INFRA)random_buffer.c \
    $(INFRA)timing_wheel.c \
    $(INFRA)random_isaac.c \
    $(VLIB)unix/plugin.c \
    $(INFRA)unix-formats.c \
    $(INFRA)socket.c \
    $(INFRA)timer.c \
    $(VLIB)unix/input.c
    

SOFILE = memif_test

$(SOFILE): $(OBJS)
	$(QUIET_SLINK)$(CC) -o $(SOFILE) $(CFLAGS) $(LDFLAGS) $(OBJS)
