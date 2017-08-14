
ifneq (,$(findstring debug,$(TAG)))
	DPDK_DEBUG=y
else
	DPDK_DEBUG=n
endif

DPDK_MAKE_ARGS = -C $(call find_source_fn,$(PACKAGE_SOURCE)) \
	DPDK_BUILD_DIR=$(PACKAGE_BUILD_DIR) \
	DPDK_INSTALL_DIR=$(PACKAGE_INSTALL_DIR) \
	DPDK_DEBUG=$(DPDK_DEBUG)

DPDK_MLX5_PMD=$(strip $($(PLATFORM)_uses_dpdk_mlx5_pmd))
ifneq ($(DPDK_MLX5_PMD),)
DPDK_MAKE_ARGS += DPDK_MLX5_PMD=y
endif

DPDK_PLATFORM_TARGET=$(strip $($(PLATFORM)_dpdk_target))
ifneq ($(DPDK_PLATFORM_TARGET),)
DPDK_MAKE_ARGS += DPDK_TARGET=$(DPDK_PLATFORM_TARGET)
endif

DPDK_MAKE_EXTRA_ARGS = $(strip $($(PLATFORM)_dpdk_make_extra_args))
ifneq ($(DPDK_MAKE_EXTRA_ARGS),)
DPDK_MAKE_ARGS += DPDK_MAKE_EXTRA_ARGS="$(DPDK_MAKE_EXTRA_ARGS)"
endif

dpdk_configure = echo

dpdk_make_args = $(DPDK_MAKE_ARGS) ebuild-build

dpdk_install =  make $(DPDK_MAKE_ARGS) ebuild-install
