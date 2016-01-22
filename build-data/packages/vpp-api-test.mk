vpp-api-test_configure_depend =			\
	vppinfra-install			\
	dpdk-install				\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

# 
vpp-api-test_configure_args = --with-dpdk 

vpp-api-test_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	dpdk						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

vpp-api-test_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	dpdk						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

