mrvl-device-plugin_source = extras
mrvl-device-plugin_configure_subdir = mrvl-device-plugin
#mrvl-device-plugin_configure_depend = vpp-install
mrvl-device-plugin_CPPFLAGS = $(call installed_includes_fn, vpp)
mrvl-device-plugin_LDFLAGS = $(call installed_libs_fn, vpp)
