sample-plugin_configure_depend =		\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install				\
	vpp-api-test-install

sample-plugin_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	openssl						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp						\
        vpp-api-test)

sample-plugin_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	openssl						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp						\
	vpp-api-test)

sample-plugin_post_install = \
	mkdir -p $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/vlib_plugins ; 	\
	cp $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/*.so 			\
	  $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/vlib_plugins

sample-plugin_image_include = echo $(arch_lib_dir)/vlib_plugins

ifneq ($($(PLATFORM)_uses_dpdk),no)
sample-plugin_configure_args = --with-dpdk
sample-plugin_configure_depend += dpdk-install
sample-plugin_CPPFLAGS += $(call installed_includes_fn, dpdk)
sample-plugin_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
