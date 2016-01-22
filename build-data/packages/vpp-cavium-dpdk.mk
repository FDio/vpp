vpp-cavium-dpdk_source = vpp

vpp-cavium-dpdk_configure_depend =		\
	vppinfra-install			\
	cavium-dpdk-install			\
	svm-install				\
	vlib-api-cavium-dpdk-install		\
	vlib-cavium-dpdk-install		\
	vnet-cavium-dpdk-install

# Platform dependent configure flags
vpp-cavium-dpdk_configure_args += $(vpp-cavium-dpdk_configure_args_$(PLATFORM))

vpp-cavium-dpdk_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra						\
	cavium-dpdk						\
        openssl							\
	svm							\
	vlib-cavium-dpdk					\
	vlib-api-cavium-dpdk					\
	vnet-cavium-dpdk)

vpp-cavium-dpdk_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	cavium-dpdk					\
	openssl						\
	svm						\
	vlib-cavium-dpdk				\
	vlib-api-cavium-dpdk				\
	vnet-cavium-dpdk)
