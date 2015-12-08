vpp-japi_configure_depend =			\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install

vpp-japi_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp)

vpp-japi_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra				\
	svm					\
	vlib					\
	vlib-api)

vpp-japi_CPPFLAGS += -I/usr/lib/jvm/java-7-openjdk-amd64/include
