vnet-cavium-dpdk_source = vnet

vnet-cavium-dpdk_configure_depend =		\
    vppinfra-install				\
    cavium-dpdk-install				\
    svm-install					\
    vlib-api-cavium-dpdk-install		\
    vlib-cavium-dpdk-install 


vnet-cavium-dpdk_CPPFLAGS = $(call installed_includes_fn,	\
    vppinfra							\
    cavium-dpdk							\
    openssl							\
    svm								\
    vlib-cavium-dpdk						\
    vlib-api-cavium-dpdk)

vnet-cavium-dpdk_LDFLAGS = $(call installed_libs_fn,	\
    vppinfra						\
    cavium-dpdk						\
    openssl						\
    svm							\
    vlib-cavium-dpdk					\
    vlib-api-cavium-dpdk)

# Platform dependent configure flags
vnet-cavium-dpdk_configure_args += $(vnet-cavium-dpdk_configure_args_$(PLATFORM))

