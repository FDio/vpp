vlib-cavium-dpdk_source = vlib
vlib-cavium-dpdk_configure_depend = vppinfra-install cavium-dpdk-install

vlib-cavium-dpdk_configure_args += --with-dpdk

vlib-cavium-dpdk_CPPFLAGS = $(call installed_includes_fn, vppinfra cavium-dpdk)
vlib-cavium-dpdk_LDFLAGS = $(call installed_libs_fn, vppinfra cavium-dpdk)
