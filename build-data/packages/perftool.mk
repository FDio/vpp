perftool_configure_depend = vpp-install

perftool_CPPFLAGS = $(call installed_includes_fn, vpp)

perftool_LDFLAGS = $(call installed_libs_fn, vpp)
