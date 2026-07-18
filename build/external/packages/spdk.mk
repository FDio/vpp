# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

SPDK_DEBUG ?= n

spdk_version := 4828014884dcfafaaae1a741d613a45c57b64816
spdk_tarball := spdk-$(spdk_version).tar.gz
spdk_tarball_sha256sum := cc206b53805dd136fdde93fdad1a87bec6e888538015c2e8a8d71eb8cd0408ed
spdk_url := https://github.com/spdk/spdk/archive/$(spdk_version).tar.gz
spdk_tarball_strip_dirs := 1
spdk_env_dir := $(CURDIR)/spdk-env-vpp
spdk_target_arch := $(if $(AARCH64),armv8-a+crc,native)
# Use the C++ companion of the selected C compiler for shared CPU flags.
spdk_cxx ?= $(if $(findstring clang,$(CC)),$(subst clang,clang++,$(CC)),$(CXX))

# SPDK's build system is in-tree even when it is consumed as a VPP external
# dependency.  The source directory is private to build/external; the generic
# package build directory is only used for the framework's stamp files.

SPDK_CONFIGURE_ARGS = \
	--prefix=$(spdk_install_dir) \
	--target-arch=$(spdk_target_arch) \
	--without-dpdk \
	--with-env=$(spdk_env_dir) \
	--disable-tests \
	--disable-unit-tests \
	--disable-examples \
	--disable-apps \
	--without-fsdev \
	--without-aio-fsdev \
	--without-isal \
	--without-isal-crypto \
	--without-nvme-cuse \
	--without-vhost \
	--without-virtio \
	--without-rdma \
	--without-vfio-user

ifeq ($(SPDK_DEBUG),y)
SPDK_CONFIGURE_ARGS += --enable-debug
endif

define spdk_config_cmds
	set -o pipefail; \
	cd $(spdk_src_dir) && \
	CC="$(CC)" CXX="$(spdk_cxx)" \
	./configure $(SPDK_CONFIGURE_ARGS) 2>&1 | tee $(spdk_config_log)
endef

define spdk_build_cmds
	set -o pipefail; \
	$(MAKE) $(MAKE_ARGS) CC="$(CC)" CXX="$(spdk_cxx)" \
		-C $(spdk_src_dir) 2>&1 | tee $(spdk_build_log)
endef

define spdk_install_cmds
	set -o pipefail; \
	{ for dir in lib module include; do \
		$(MAKE) $(MAKE_ARGS) CC="$(CC)" CXX="$(spdk_cxx)" \
			-C $(spdk_src_dir)/$$dir install || exit $$?; \
	done && \
	install -D -m 0644 $(spdk_src_dir)/include/spdk_internal/sock_module.h \
		$(spdk_install_dir)/include/spdk_internal/sock_module.h && \
	install -D -m 0644 $(spdk_src_dir)/include/spdk_internal/trace_defs.h \
		$(spdk_install_dir)/include/spdk_internal/trace_defs.h; } \
		2>&1 | tee $(spdk_install_log)
endef

$(eval $(call package,spdk))
