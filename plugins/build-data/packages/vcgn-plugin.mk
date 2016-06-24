vcgn-plugin_configure_depend =		\
	vppinfra-install			\
	svm-install				\
	vlib-api-install			\
	vlib-install				\
	vnet-install				\
	vpp-install				\
	vpp-api-test-install

vcgn-plugin_CPPFLAGS = $(call installed_includes_fn,	\
	vppinfra					\
	openssl						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp						\
        vpp-api-test)

vcgn-plugin_LDFLAGS = $(call installed_libs_fn,	\
	vppinfra					\
	openssl						\
	svm						\
	vlib						\
	vlib-api					\
	vnet						\
	vpp						\
	vpp-api-test)

vcgn-plugin_post_install = \
	mkdir -p $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/vlib_plugins ; 	\
	cp $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/*.so 			\
	  $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/vlib_plugins

vcgn-plugin_image_include = echo $(arch_lib_dir)/vlib_plugins

ifneq ($($(PLATFORM)_uses_dpdk),no)
vcgn-plugin_configure_args = --with-dpdk
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vcgn-plugin_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vcgn-plugin_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vcgn-plugin_configure_depend += dpdk-install
vcgn-plugin_CPPFLAGS += $(call installed_includes_fn, dpdk)
vcgn-plugin_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
endif
