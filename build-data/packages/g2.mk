g2_configure_depend = vppinfra-install

g2_CPPFLAGS = $(call installed_includes_fn, vppinfra)

g2_LDFLAGS = $(call installed_libs_fn, vppinfra)
