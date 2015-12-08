vppapigen_configure_depend = vppinfra-install

vppapigen_CPPFLAGS = $(call installed_includes_fn, vppinfra)

vppapigen_LDFLAGS = $(call installed_libs_fn, vppinfra)
