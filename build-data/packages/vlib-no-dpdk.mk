vlib-no-dpdk_source = vlib
vlib-no-dpdk_configure_depend = vppinfra-install

vlib-no-dpdk_CPPFLAGS = $(call installed_includes_fn, vppinfra)
vlib-no-dpdk_LDFLAGS = $(call installed_libs_fn, vppinfra)
