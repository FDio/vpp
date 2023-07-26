TARGET=libstrongswan-kernel-vpp.so

SOURCES=kernel_vpp_ipsec.c kernel_vpp_plugin.c ../common/kernel_vpp_shared.c ../common/kernel_vpp_net.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	gcc $(CFLAGS) -shared -DPIC $(OBJECTS) $(LDFLAGS) -Wl,-soname -Wl,$(TARGET) -o $@
	cp $(TARGET) ${SWANDIR}

%.o: %.c
	gcc $(CFLAGS) $(CFLAGS_I) -c $< -o $@ $(LDFLAGS)

install:
	cp $(TARGET) $(SWANPLUGINS)/$(TARGET)
	cp kernel-vpp.conf $(PLUGINCONF)

uninstall:
	@if [ -f "$(SWANPLUGINS)/$(TARGET)" ]; then \
	  rm $(SWANPLUGINS)/$(TARGET); \
	fi
	@if [ -f "$(PLUGINCONF)/kernel-vpp.conf" ]; then \
	  rm $(PLUGINCONF)/kernel-vpp.conf; \
	fi

clean:
	rm -f *.so *.o

.PHONY: clean install uninstall all
