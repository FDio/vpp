vnet_configure_depend = 			\
    vppinfra-install 				\
    dpdk-install				\
    svm-install					\
    vlib-api-install 				\
    vlib-install 

vnet_CPPFLAGS = $(call installed_includes_fn, 	\
    vppinfra 					\
    dpdk 					\
    openssl					\
    svm						\
    vlib 					\
    vlib-api)

vnet_LDFLAGS = $(call installed_libs_fn, 	\
    vppinfra					\
    dpdk					\
    openssl					\
    svm						\
    vlib					\
    vlib-api)

# Platform dependent configure flags
vnet_configure_args += $(vnet_configure_args_$(PLATFORM))

