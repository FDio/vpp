vpp-api-test-no-dpdk_source = vpp-api-test

vpp-api-test-no-dpdk_configure_depend =		\
	vppinfra-install			\
	svm-install				\
	vlib-api-no-dpdk-install		\
	vlib-no-dpdk-install			\
	vnet-no-dpdk-install			\
	vpp-no-dpdk-install

# 
vpp-api-test-no-dpdk_configure_args = 

vpp-api-test-no-dpdk_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra						\
	svm							\
	vlib-no-dpdk						\
	vlib-api-no-dpdk					\
	vnet-no-dpdk						\
	vpp-no-dpdk)

vpp-api-test-no-dpdk_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra						\
	svm							\
	vlib-no-dpdk						\
	vlib-api-no-dpdk					\
	vnet-no-dpdk						\
	vpp-no-dpdk)

