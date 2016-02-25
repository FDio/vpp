vlib_configure_depend = vppinfra-install

vlib_CPPFLAGS = $(call installed_includes_fn, vppinfra)
vlib_LDFLAGS = $(call installed_libs_fn, vppinfra)

ifeq ($($(PLATFORM)_uses_dpdk),yes)
vlib_configure_depend += dpdk-install
vlib_configure_args += --with-dpdk
vlib_CPPFLAGS += $(call installed_includes_fn, dpdk)
vlib_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
