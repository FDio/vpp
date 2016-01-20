vlib-api-no-dpdk_source = vlib-api

vlib-api-no-dpdk_configure_depend = vppinfra-install svm-install vlib-no-dpdk-install

vlib-api-no-dpdk_CPPFLAGS = $(call installed_includes_fn, vppinfra svm vlib-no-dpdk)
vlib-api-no-dpdk_LDFLAGS = $(call installed_libs_fn, vppinfra svm vlib-no-dpdk)
