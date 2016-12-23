vnet_configure_depend = 			\
    vppinfra-install 				\
    svm-install					\
    vlib-api-install 				\
    vlib-install 

vnet_CPPFLAGS = $(call installed_includes_fn, 	\
    vppinfra 					\
    svm						\
    vlib 					\
    vlib-api)

vnet_LDFLAGS = $(call installed_libs_fn, 	\
    vppinfra					\
    svm						\
    vlib					\
    vlib-api)

ifeq ($($(PLATFORM)_enable_tests),yes)
vnet_configure_args += --enable-tests
endif

# Platform dependent configure flags
vnet_configure_args += $(vnet_configure_args_$(PLATFORM))

# include & link with openssl only if needed
ifneq ($($(PLATFORM)_uses_openssl),no)
vnet_CPPFLAGS += $(call installed_includes_fn, openssl)
vnet_LDFLAGS += $(call installed_libs_fn, openssl)
endif

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vnet_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vnet_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vnet_configure_depend += dpdk-install
vnet_CPPFLAGS += $(call installed_includes_fn, dpdk)
vnet_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
ifeq ($($(PLATFORM)_uses_dpdk_cryptodev),yes)
vnet_configure_args += --with-dpdk-crypto
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx5_pmd),yes)
vnet_configure_args += --with-dpdk-mlx5-pmd
endif
endif
