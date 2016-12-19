g2_configure_depend = vpp-install

g2_CPPFLAGS = $(call installed_includes_fn, vpp)

g2_LDFLAGS = $(call installed_libs_fn, vpp)
