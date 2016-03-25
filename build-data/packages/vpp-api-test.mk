vpp-api-test_configure_depend =			\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

vpp-api-test_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

vpp-api-test_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

ifneq ($($(PLATFORM)_uses_dpdk),no)
vpp-api-test_configure_args = --with-dpdk
vpp-api-test_configure_depend += dpdk-install
vpp-api-test_CPPFLAGS += $(call installed_includes_fn, dpdk)
vpp-api-test_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
