vlib-api-cavium-dpdk_source = vlib-api

vlib-api-cavium-dpdk_configure_depend = vppinfra-install svm-install vlib-cavium-dpdk-install

vlib-api-cavium-dpdk_CPPFLAGS = $(call installed_includes_fn, vppinfra svm vlib-cavium-dpdk)
vlib-api-cavium-dpdk_LDFLAGS = $(call installed_libs_fn, vppinfra svm vlib-cavium-dpdk)
