# Temporary until Cavium upstreams their work

cavium-dpdk_configure =							\
  src_dir=$(call find_source_fn,$(PACKAGE_SOURCE)) ;			\
  dst_dir=$(PACKAGE_BUILD_DIR) ;					\
  tar -C $${src_dir} -cf - . | tar -C $${dst_dir} -xf - ;		\
  cd $${dst_dir} ;							\
  : colossal hemorrhoid to configure headroom	;			\
  if [ x$($(PACKAGE)_configure_args_$(PLATFORM)) = "x" ] ; then		\
    HR=256 ;								\
  else									\
     dpdk_configure_args=$($(PACKAGE)_configure_args_$(PLATFORM)) ;	\
     if [ $$dpdk_configure_args = "--with-headroom=256" ] ; then	\
	HR=256 ;							\
     elif [ $$dpdk_configure_args = "--with-headroom=384" ] ; then	\
	HR=384 ;							\
     else								\
	HR=256 ;							\
     fi ;								\
  fi ;									\
  env HR=$$HR								\
     spp -o								\
  $(PACKAGE_BUILD_DIR)/config/common_linuxapp				\
  $(PACKAGE_BUILD_DIR)/config/common_linuxapp.spp			\
	;								\
  env $(CONFIGURE_ENV)							\
    make config T=arm64-thunderx-linuxapp-gcc RTE_ARCH=arm64		\
        CC=aarch64-thunderx-linux-gnu-gcc V=0				\
        RTE_SDK=$(PACKAGE_BUILD_DIR)					\
        RTE_TARGET=arm-default-linuxapp-gcc

# Note: add e.g. "-O0" to EXTRA_CFLAGS if desired: EXTRA_CFLAGS='-g -O0'

cavium-dpdk_make_args = install T=arm64-thunderx-linuxapp-gcc RTE_ARCH=arm64 \
        CC=aarch64-thunderx-linux-gnu-gcc V=0				     \
        RTE_SDK=$(PACKAGE_BUILD_DIR)					     \
        RTE_TARGET=arm-default-linuxapp-gcc

cavium-dpdk_install =						\
  src_dir=$(PACKAGE_BUILD_DIR) ;				\
  dst_dir=$(PACKAGE_INSTALL_DIR) ;				\
  tar -h -C $${src_dir}/arm64-thunderx-linuxapp-gcc -cf - .	\
    | tar -C $${dst_dir} -xf - 

# dpdk libraries end up in .../lib not .../lib64. Fix it.
cavium-dpdk_post_install =							\
  if [ "$(arch_lib_dir)" != "lib" ] ; then					\
     mkdir -p $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir) ;				\
     cd $(PACKAGE_INSTALL_DIR)/lib		     ;				\
     tar cf - . | ( cd $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir); tar xf - ) ;	\
  fi 

# nothing to install, all static libraries
cavium-dpdk_image_include = echo

