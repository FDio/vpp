svm_top_srcdir = $(call find_source_fn,svm)
svm_configure_depend = vppinfra-install

svm_CPPFLAGS = $(call installed_includes_fn, vppinfra)
svm_LDFLAGS = $(call installed_libs_fn, vppinfra)
