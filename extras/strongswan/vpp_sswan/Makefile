# the directory to the strongSwan sources
SWANDIR=${CURDIR}/../../../build-root/build-vpp-native/external/sswan
# location of config.h
CONFIGH=$(SWANDIR)/config.h
# default install prefix: /usr/local or /usr
PREFIX=/usr
# location of the installed strongSwan libraries
SWANLIBS=$(PREFIX)/lib/ipsec/
# location of the strongSwan plugins
SWANPLUGINS=$(PREFIX)/lib/ipsec/plugins
# location of the strongSwan archive
SWANARCHIVE=${CURDIR}/../../../build/external/downloads
# default install configuration files:
PREFIX_SYS_CONF=/etc
# target location of the plugin config snippet: $(PREFIX)/etc/strongswan.d/charon/ or /etc/strongswan.d/charon/
PLUGINCONF=$(PREFIX_SYS_CONF)/strongswan.d/charon/
# location of the  VPP libraries
VPPLIBS=$(CURDIR)/../../../build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu
# the directory to the VPP sources
VPPDIR=../../../build-root/install-vpp-native/vpp/include

TARGET=libstrongswan-kernel-vpp.so

# tested only with 5.9.5 and 5.9.6 version of strongSwan
VERSION_SSWAN="5.9.6"

CFLAGS=-O2 -g -Wall -Wextra -fpic

CFLAGS_I=-include $(CONFIGH) \
	-I$(SWANDIR)/src/libstrongswan \
	-I$(SWANDIR)/src/libcharon

LDFLAGS= -lvppinfra \
	-lvlibmemoryclient \
	-lvppapiclient \
	-lsvm \
	-lvlib

# check if VPPDIR exists
ifeq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	CFLAGS_I += -I$(VPPDIR)
endif

# check if VPPLIBS exists
ifeq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	LDFLAGS += -L$(VPPLIBS)
	LDFLAGS += -Wl,-rpath=$(VPPLIBS)
endif

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

all: pull-swan $(TARGET)

pull-swan:
	@if [ -d "${SWANDIR}" ]; then \
	  rm -rf ${SWANDIR} ; \
	fi
	@if ! [ -f "${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz" ]; then \
	  wget -P ${SWANARCHIVE} https://download.strongswan.org/strongswan-${VERSION_SSWAN}.tar.gz ; \
	fi
	tar -zxof ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz -C ${CURDIR}/../../../build-root/build-vpp-native/external/
	mv ${CURDIR}/../../../build-root/build-vpp-native/external/strongswan-${VERSION_SSWAN} ${SWANDIR}
	cd ${SWANDIR} && ./configure --prefix=${PREFIX} --sysconfdir=${PREFIX_SYS_CONF} --enable-libipsec --enable-systemd --enable-swanctl --disable-gmp --enable-openssl
	cd ${SWANDIR} && make -j$(nproc)
#	cd ${SWANDIR} && sudo make install
# check if VPPDIR exists
ifneq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	$(error ERROR: directory $(VPPDIR) - doesn't exists, please compile VPP before build this)
endif
# check if VPPLIBS exists
ifneq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	$(error ERROR: directory $(VPPLIBS) - doesn't exists, please compile VPP before build this)
endif

$(TARGET): $(OBJECTS)
	gcc $(CFLAGS) -shared -DPIC $(OBJECTS) $(LDFLAGS) -Wl,-soname -Wl,$(TARGET) -o $@
	cp $(TARGET) ${SWANDIR}

%.o: %.c
	gcc $(CFLAGS) $(CFLAGS_I) -c $< -o $@ $(LDFLAGS)

install:
	cp $(TARGET) $(SWANPLUGINS)/$(TARGET)
	cp kernel-vpp.conf $(PLUGINCONF)

clean:
	rm -f *.so *.o

.PHONY: clean install all