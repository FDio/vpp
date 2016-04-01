vnet_configure_depend = 			\
    vppinfra-install 				\
    svm-install					\
    vlib-api-install 				\
    vlib-install 

vnet_CPPFLAGS = $(call installed_includes_fn, 	\
    vppinfra 					\
    openssl					\
    svm						\
    vlib 					\
    vlib-api)

vnet_LDFLAGS = $(call installed_libs_fn, 	\
    vppinfra					\
    openssl					\
    svm						\
    vlib					\
    vlib-api)

# Platform dependent configure flags
vnet_configure_args += $(vnet_configure_args_$(PLATFORM))

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vnet_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vnet_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vnet_configure_depend += dpdk-install
vnet_CPPFLAGS += $(call installed_includes_fn, dpdk)
vnet_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
endif
