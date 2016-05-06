sign_configure_depend = vppinfra-install

sign_CPPFLAGS = $(call installed_includes_fn, vppinfra)
sign_LDFLAGS = $(call installed_libs_fn, vppinfra)

