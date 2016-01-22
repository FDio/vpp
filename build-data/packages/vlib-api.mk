vlib-api_configure_depend = vppinfra-install svm-install vlib-install

vlib-api_CPPFLAGS = $(call installed_includes_fn, vppinfra svm vlib)
vlib-api_LDFLAGS = $(call installed_libs_fn, vppinfra svm vlib)
