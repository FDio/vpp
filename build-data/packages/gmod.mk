gmod_configure_depend = vppinfra-install svm-install

gmod_configure_args = # --libdir=$(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/ganglia

gmod_CPPFLAGS = $(call installed_includes_fn, vppinfra svm)
gmod_CPPFLAGS += -I/usr/include/apr-1.0
gmod_LDFLAGS = $(call installed_libs_fn, vppinfra svm)

gmod_image_include = echo $(arch_lib_dir)/ganglia/libgmodvpp.so etc
