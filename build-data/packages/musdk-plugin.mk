musdk-plugin_source = extras
musdk-plugin_configure_subdir = musdk-plugin
#musdk-plugin_configure_depend = vpp-install
musdk-plugin_CPPFLAGS = $(call installed_includes_fn, vpp)
musdk-plugin_LDFLAGS = $(call installed_libs_fn, vpp)
