obj-m:=igb_uio.o

CONFIG_MODULE_SIG=n

EXTRA_CFLAGS += -Winline -I$(PWD)

ARCH=$(shell uname -r)
ifeq ($(PLATFORM),aarch64-generic)
ARCH=aarch64
endif

default:
	    $(MAKE) -C /lib/modules/$(ARCH)/build M=$(shell pwd) modules
clean:
	    $(MAKE) -C /lib/modules/$(ARCH)/build M=$(shell pwd) clean
