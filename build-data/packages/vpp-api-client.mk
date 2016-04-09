vpp-api-client_configure_depend =		\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

vpp-api-client_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

vpp-api-client_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api)

vpp-api-client_CPPFLAGS +=
