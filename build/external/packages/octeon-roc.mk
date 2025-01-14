# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

octeon-roc_version             := 0.6
octeon-roc_tarball             := v$(octeon-roc_version).tar.gz
octeon-roc_tarball_sha256sum   := 5018e6da80c80898444b648482b4240cbf62591c64eb463b3f681cf68c07239c

octeon-roc_tarball_strip_dirs  := 1
octeon-roc_url                 := https://github.com/MarvellEmbeddedProcessors/marvell-octeon-roc/archive/refs/tags/$(octeon-roc_tarball)

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

