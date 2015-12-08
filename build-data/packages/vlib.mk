vlib_configure_depend = vppinfra-install dpdk-install

vlib_configure_args += --with-dpdk

vlib_CPPFLAGS = $(call installed_includes_fn, vppinfra dpdk)
vlib_LDFLAGS = $(call installed_libs_fn, vppinfra dpdk)
