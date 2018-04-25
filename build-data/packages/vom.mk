vom_configure_depend = vpp-install
vom_source = extras
vom_configure_subdir = vom
vom_CPPFLAGS = $(call installed_includes_fn, vpp)
vom_LDFLAGS = $(call installed_libs_fn, vpp)

