vpp-api-test-cavium-dpdk_source = vpp-api-test

vpp-api-test-cavium-dpdk_configure_depend =	\
	vppinfra-install			\
	cavium-dpdk-install			\
	svm-install				\
	vlib-api-cavium-dpdk-install		\
	vlib-cavium-dpdk-install		\
	vnet-cavium-dpdk-install		\
	vpp-cavium-dpdk-install

# 
vpp-api-test-cavium-dpdk_configure_args = --with-dpdk 

vpp-api-test-cavium-dpdk_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra							\
	cavium-dpdk							\
	svm								\
	vlib-cavium-dpdk						\
	vlib-api-cavium-dpdk						\
	vnet-cavium-dpdk						\
	vpp-cavium-dpdk)

vpp-api-test-cavium-dpdk_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra						\
	cavium-dpdk						\
	svm							\
	vlib-cavium-dpdk					\
	vlib-api-cavium-dpdk					\
	vnet-cavium-dpdk					\
	vpp-cavium-dpdk)

