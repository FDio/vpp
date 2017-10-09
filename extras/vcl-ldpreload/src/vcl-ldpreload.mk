vcl_ldpreload_configure_depend = vpp-install

vcl_ldpreload_CPPFLAGS = $(call installed_includes_fn, \
	vppinfra                                \
	uri)

vcl_ldpreload_LDFLAGS = $(call installed_libs_fn,      \
	vppinfra                                \
	uri)
