vppversion_configure_depend = vppinfra-install

vppversion_CPPFLAGS = $(call installed_includes_fn, vppinfra)

vppversion_LDFLAGS = $(call installed_libs_fn, vppinfra)
