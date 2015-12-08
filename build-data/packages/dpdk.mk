
DPDK_MARCH = $(strip $($(PLATFORM)_dpdk_arch))
ifeq ($(DPDK_MARCH),)
	DPDK_MARCH="native"
endif

ifneq (,$(findstring debug,$(TAG)))
	DPDK_DEBUG=y
else
	DPDK_DEBUG=n
endif

DPDK_MAKE_ARGS = -C $(call find_source_fn,$(PACKAGE_SOURCE)) \
	DPDK_BUILD_DIR=$(PACKAGE_BUILD_DIR) \
	DPDK_INSTALL_DIR=$(PACKAGE_INSTALL_DIR) \
	DPDK_MARCH=$(DPDK_MARCH) \
	DPDK_DEBUG=$(DPDK_DEBUG)


dpdk_configure = echo 

dpdk_make_args = $(DPDK_MAKE_ARGS) config

dpdk_install =  make $(DPDK_MAKE_ARGS) build
