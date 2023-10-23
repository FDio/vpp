# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

octeon-roc_version             := 0.1
octeon-roc_tarball             := octeon-roc-v$(octeon-roc_version).tar.gz
octeon-roc_tarball_md5sum      := 646639c998258c47785931ef08ec3576

octeon-roc_tarball_strip_dirs  := 1
octeon-roc_url                 := https://github.com/MarvellEmbeddedProcessors/marvell-vpp/archive/refs/tags/$(octeon-roc_tarball)

define  octeon-roc_config_cmds
	@true
endef

define  octeon-roc_build_cmds
	@cd ${octeon-roc_src_dir} && rm -f $(octeon-roc_build_log) && $(CMAKE) ${octeon-roc_src_dir} >> $(octeon-roc_build_log)
	@$(MAKE) -C ${octeon-roc_src_dir} >> $(octeon-roc_build_log)
endef

define  octeon-roc_install_cmds
	@mkdir -p $(octeon-roc_install_dir)/octeon-roc/
	@mkdir -p $(octeon-roc_install_dir)/lib/
	@cp -rf $(octeon-roc_src_dir)/* $(octeon-roc_install_dir)/octeon-roc/
	@cp -rf $(octeon-roc_src_dir)/libocteon-roc.a $(octeon-roc_install_dir)/lib/
endef

$(eval $(call package,octeon-roc))

