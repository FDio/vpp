vlib_configure_depend = vppinfra-install mbedtls-install

vlib_CPPFLAGS = $(call installed_includes_fn, vppinfra mbedtls)
vlib_CPPFLAGS += $(call installed_includes_fn, mbedtls)/include
vlib_LDFLAGS = $(call installed_libs_fn, vppinfra mbedtls)

ifneq ($($(PLATFORM)_uses_dpdk),no)
vlib_configure_args += --with-dpdk
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vlib_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vlib_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vlib_configure_depend += dpdk-install
vlib_CPPFLAGS += $(call installed_includes_fn, dpdk)
vlib_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
endif
