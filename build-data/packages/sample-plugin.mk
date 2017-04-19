sample-plugin_source = src
sample-plugin_configure_subdir = examples/sample-plugin
sample-plugin_configure_depend = vpp-install
sample-plugin_CPPFLAGS = $(call installed_includes_fn, vpp)
sample-plugin_LDFLAGS = $(call installed_libs_fn, vpp)
