# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

octeon-roc_version             := 0.2
octeon-roc_tarball             := octeon-roc-v$(octeon-roc_version).tar.gz
octeon-roc_tarball_md5sum      := a72bb3b27fd3bbaf58aadd99514620e1

octeon-roc_tarball_strip_dirs  := 1
octeon-roc_url                 := https://github.com/MarvellEmbeddedProcessors/marvell-vpp/archive/refs/tags/$(octeon-roc_tarball)

define  octeon-roc_config_cmds
	@true
endef

define  octeon-roc_build_cmds
	@cd ${octeon-roc_src_dir} && rm -f $(octeon-roc_build_log) && $(CMAKE) ${octeon-roc_src_dir} -DCMAKE_INSTALL_PREFIX='$(octeon-roc_install_dir)' >> $(octeon-roc_build_log)
	@$(MAKE) -C ${octeon-roc_src_dir} >> $(octeon-roc_build_log)
endef

define  octeon-roc_install_cmds
	@$(MAKE) -C ${octeon-roc_src_dir} install >> $(octeon-roc_install_log)
endef

$(eval $(call package,octeon-roc))

