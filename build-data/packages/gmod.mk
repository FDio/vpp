gmod_configure_depend = vpp-install

gmod_configure_args = --libdir=$(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/ganglia

gmod_CPPFLAGS = $(call installed_includes_fn, vpp)
gmod_CPPFLAGS += -I/usr/include/apr-1.0 -I/usr/include/apr-1 -I/usr/include
gmod_LDFLAGS = $(call installed_libs_fn, vpp)

gmod_image_include = echo $(arch_lib_dir)/ganglia/libgmodvpp.so etc
