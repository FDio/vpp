perftool_configure_depend = vppinfra-install

perftool_CPPFLAGS = $(call installed_includes_fn, vppinfra)

perftool_LDFLAGS = $(call installed_libs_fn, vppinfra)
