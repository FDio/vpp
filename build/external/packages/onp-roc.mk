# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

onp-roc_version             := 1.0
onp-roc_tarball             := onp-roc-v$(onp-roc_version).tar.gz
onp-roc_tarball_md5sum      := 51c10cb764fe7145396b9f8791ed8ea5

onp-roc_tarball_strip_dirs  := 1
onp-roc_url                 := https://github.com/MarvellEmbeddedProcessors/marvell-vpp/archive/refs/tags/$(onp-roc_tarball)

define  onp-roc_config_cmds
	@true
endef

define  onp-roc_build_cmds
	@cd ${onp-roc_src_dir} && ls > $(onp-roc_build_log)
endef

define  onp-roc_install_cmds
	@mkdir -p $(onp-roc_install_dir)/onp-roc/
	@cp -rf $(onp-roc_src_dir)/* $(onp-roc_install_dir)/onp-roc/
endef

$(eval $(call package,onp-roc))

