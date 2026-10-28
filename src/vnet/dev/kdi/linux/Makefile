# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Cisco Systems, Inc.

obj-m += vpp_kdi.o
vpp_kdi-y := main.o clock.o reset.o interconnect.o ethernet_phy.o clock_provider.o

KDIR ?= /lib/modules/$(shell uname -r)/build
MO ?= $(CURDIR)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MO=$(MO) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MO=$(MO) clean

.PHONY: all clean
