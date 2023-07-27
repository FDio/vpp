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
PLUGINCONF=$(PREFIX_SYS_CONF)/strongswan.d/charon
# location of the  VPP libraries
VPPLIBS=$(CURDIR)/../../../build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu
# the directory to the VPP sources
VPPDIR=$(CURDIR)/../../../build-root/install-vpp-native/vpp/include

# tested only with 5.9.5 and 5.9.6 version of strongSwan
VERSION_SSWAN=5.9.6

CFLAGS=-O2 -g -Wall -Wextra -fpic

CFLAGS_I=-include $(CONFIGH) \
	-I$(SWANDIR)/src/libstrongswan \
	-I$(SWANDIR)/src/libcharon

LDFLAGS= -lvppinfra \
	-lvlibmemoryclient \
	-lvlibapi \
	-lsvm \
	-lvppapiclient

VERSION_VPP=$(shell (dpkg -s vpp | grep Version) | grep -Po '(?<=Version: )\d\d.\d\d')

# check if VPP is installed
ifneq ($(shell test "$(shell ldconfig -p | grep vppinfra.so | awk 'NR==1{print $$1;}')" && echo "yes"), yes)
# check if VPPDIR exists
ifeq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	CFLAGS_I += -I$(VPPDIR)
endif
# check if VPPLIBS exists
ifeq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	LDFLAGS += -L$(VPPLIBS)
	LDFLAGS += -Wl,-rpath=$(VPPLIBS)
endif
endif

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

export CFLAGS
export CFLAGS_I
export LDFLAGS
export VPPLIBS
export VPPDIR
export SWANDIR
export SWANPLUGINS
export PLUGINCONF

all: pull-swan install-swan build

pull-swan:
	@if [ -d "${SWANDIR}" ]; then \
	  rm -rf ${SWANDIR} ; \
	fi
	@if ! [ -f "${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz" ]; then \
	  curl -o ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz -LO https://github.com/strongswan/strongswan/archive/${VERSION_SSWAN}.tar.gz; \
	fi
	@if ! [ -d "${CURDIR}/../../../build-root/build-vpp-native/external/" ]; then \
	  mkdir ${CURDIR}/../../../build-root/build-vpp-native/external; \
	fi
	tar -zxof ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz -C ${CURDIR}/../../../build-root/build-vpp-native/external/
	mv ${CURDIR}/../../../build-root/build-vpp-native/external/strongswan-${VERSION_SSWAN} ${SWANDIR}
	cd ${SWANDIR} && ./autogen.sh
	cd ${SWANDIR} && ./configure --prefix=${PREFIX} --sysconfdir=${PREFIX_SYS_CONF} --enable-libipsec --enable-systemd --enable-swanctl --disable-gmp --enable-openssl

install-swan:
	@if ! [ -f "${SWANDIR}/configure" ]; then \
	  echo "SSWAN not downloaded, please run "make" or "make pull-swan" first." ; \
	  exit 1 ; \
	fi
	cd ${SWANDIR} && make -j$(nproc)
	cd ${SWANDIR} && sudo make install

# check if VPP is installed
ifneq ($(shell test "$(shell ldconfig -p | grep vppinfra.so | awk 'NR==1{print $$1;}')" && echo "yes"), yes)
	$(info INFO: Not found installed VPP - checking if locally VPP exists)
# check if VPPDIR exists
ifneq ($(shell test -d $(VPPDIR) && echo "yes"), yes)
	$(error ERROR: Not found installed VPP and locally VPP - please install or build)
else
# check if VPPLIBS exists
ifneq ($(shell test -d $(VPPLIBS) && echo "yes"), yes)
	$(error ERROR: directory $(VPPLIBS) - doesn't exists, please compile VPP before build this)
else
	$(info INFO: Found locally VPP)
endif
endif
else
	$(info INFO: Found installed VPP in version: $(VERSION_VPP))
endif

build:
	$(MAKE) -C policy-based all
	$(MAKE) -C route-based all

install-policy: uninstall
	$(MAKE) -C policy-based install

install-route: uninstall
	$(MAKE) -C route-based install

uninstall:
	$(MAKE) -C policy-based uninstall
	$(MAKE) -C route-based uninstall

clean:
	rm -f ${SWANARCHIVE}/strongswan-${VERSION_SSWAN}.tar.gz
	rm -rf ${SWANDIR}
	$(MAKE) -C policy-based clean
	$(MAKE) -C route-based clean
	rm -f common/*.o

.PHONY: clean uninstall install-policy install-route build all
