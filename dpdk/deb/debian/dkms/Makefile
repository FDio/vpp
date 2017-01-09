obj-m:=igb_uio.o

CONFIG_MODULE_SIG=n

EXTRA_CFLAGS += -Winline -I$(PWD)

default:
	    $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	    $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
