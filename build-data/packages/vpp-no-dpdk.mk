vpp-no-dpdk_source = vpp

vpp-no-dpdk_configure_depend =			\
	vppinfra-install			\
	openssl-install				\
	svm-install				\
	vlib-api-no-dpdk-install		\
	vlib-no-dpdk-install			\
	vnet-no-dpdk-install

# 
vpp-no-dpdk_configure_args = 

# Platform dependent configure flags
vpp-no-dpdk_configure_args += $(vpp-no-dpdk_configure_args_$(PLATFORM))


vpp-no-dpdk_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
        openssl						\
	svm						\
	vlib-no-dpdk					\
	vlib-api-no-dpdk				\
	vnet-no-dpdk)

vpp-no-dpdk_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra				\
	openssl					\
	svm					\
	vlib-no-dpdk				\
	vlib-api-no-dpdk			\
	vnet-no-dpdk)
