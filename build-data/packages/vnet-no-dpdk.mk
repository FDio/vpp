vnet-no-dpdk_source = vnet

vnet-no-dpdk_configure_depend = 		\
    vppinfra-install 				\
    svm-install					\
    openssl-install				\
    vlib-api-no-dpdk-install 				\
    vlib-no-dpdk-install 

vnet-no-dpdk_CPPFLAGS = $(call installed_includes_fn, 	\
    vppinfra 					\
    openssl					\
    svm						\
    vlib-no-dpdk 					\
    vlib-api-no-dpdk)

vnet-no-dpdk_LDFLAGS = $(call installed_libs_fn, 	\
    vppinfra					\
    openssl					\
    svm						\
    vlib-no-dpdk					\
    vlib-api-no-dpdk)

# Platform dependent configure flags
vnet-no-dpdk_configure_args += $(vnet-no-dpdk_configure_args_$(PLATFORM))

