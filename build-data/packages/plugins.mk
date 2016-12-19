plugins_configure_depend = 			\
    vpp-api-install				\
    vpp-install

plugins_CPPFLAGS = $(call installed_includes_fn, \
    vpp  \
    vpp-api)

plugins_LDFLAGS = $(call installed_libs_fn,     \
    vpp)

ifeq ($($(PLATFORM)_enable_tests),yes)
plugins_configure_args += --enable-tests
endif

# Platform dependent configure flags
plugins_configure_args += $(plugins_configure_args_$(PLATFORM))

# include & link with openssl only if needed
ifneq ($($(PLATFORM)_uses_openssl),no)
plugins_CPPFLAGS += $(call installed_includes_fn, openssl)
plugins_LDFLAGS += $(call installed_libs_fn, openssl)
endif

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
plugins_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
plugins_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
plugins_configure_depend += dpdk-install
plugins_CPPFLAGS += $(call installed_includes_fn, dpdk)
plugins_LDFLAGS += $(call installed_libs_fn, dpdk)
endif
endif
