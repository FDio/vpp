vpp_configure_depend =				\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\

# 
vpp_configure_args = 

# Platform dependent configure flags
vpp_configure_args += $(vpp_configure_args_$(PLATFORM))


vpp_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra				\
        openssl					\
	svm					\
	vlib					\
	vlib-api				\
	vnet)

vpp_LDFLAGS = $(call installed_libs_fn,		\
	vppinfra				\
	openssl					\
	svm					\
	vlib					\
	vlib-api				\
	vnet)

ifeq ($($(PLATFORM)_uses_dpdk),yes)
vpp_configure_depend += dpdk-install
vpp_CPPFLAGS += $(call installed_includes_fn, dpdk)
vpp_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
