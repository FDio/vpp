vpp_configure_depend =				\
	vppinfra-install			\
	dpdk-install				\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\

# 
vpp_configure_args = --with-q-platform=$(PLATFORM) \
       --with-q-plugin-prefix=$(MU_BUILD_ROOT_DIR)/packages-$(PLATFORM)

# Platform dependent configure flags
vpp_configure_args += $(vpp_configure_args_$(PLATFORM))


vpp_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra				\
	dpdk					\
        openssl					\
	svm					\
	vlib					\
	vlib-api				\
	vnet)

vpp_LDFLAGS = $(call installed_libs_fn,		\
	vppinfra				\
	dpdk					\
	openssl					\
	svm					\
	vlib					\
	vlib-api				\
	vnet)
