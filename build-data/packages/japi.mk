japi_configure_depend = vpp-install
japi_source = extras
japi_configure_subdir = japi
japi_CPPFLAGS = $(call installed_includes_fn, vpp) $(call installed_includes_fn, vpp)/vpp_plugins
japi_LDFLAGS = $(call installed_libs_fn, vpp)

