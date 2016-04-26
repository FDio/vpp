vpp-api_configure_depend =			\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

vpp-api_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

vpp-api_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api)

vpp-api_CPPFLAGS += -I/usr/lib/jvm/java-8-openjdk-amd64/include
