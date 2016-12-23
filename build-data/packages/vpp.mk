vpp_configure_depend =				\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\

# 
ifeq ($($(PLATFORM)_dpdk_shared_lib),yes)
vpp_configure_args = --enable-dpdk-shared
else
vpp_configure_args =
endif

# Platform dependent configure flags
vpp_configure_args += $(vpp_configure_args_$(PLATFORM))


vpp_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api				\
	vnet)

vpp_LDFLAGS = $(call installed_libs_fn,		\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api				\
	vnet)

# include & link with openssl only if needed
ifneq ($($(PLATFORM)_uses_openssl),no)
vpp_CPPFLAGS += $(call installed_includes_fn, openssl)
vpp_LDFLAGS += $(call installed_libs_fn, openssl)
endif

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vpp_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vpp_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vpp_configure_depend += dpdk-install
vpp_CPPFLAGS += $(call installed_includes_fn, dpdk)
vpp_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
ifeq ($($(PLATFORM)_uses_dpdk_cryptodev),yes)
vpp_configure_args += --with-dpdk-crypto
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx5_pmd),yes)
vpp_configure_args += --with-dpdk-mlx5-pmd
endif
endif
