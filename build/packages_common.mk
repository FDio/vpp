# Copyright (c) 2024 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

define h1
	@echo "--- $(1)"
endef

define package
$1_tarball_strip_dirs ?= 0
$1_src_dir ?= $(B)/src-$1
$1_patch_dir ?= $(CURDIR)/patches/$1_$($1_version)
$1_build_dir ?= $(B)/build-$1
$1_install_dir ?= $(I)
$1_root_dir ?= $(R)
$1_config_log ?= $(L)/$1.config.log
$1_build_log ?= $(L)/$1.build.log
$1_install_log ?= $(L)/$1.install.log

##############################################################################
# Download
##############################################################################
$(D)/$($1_tarball):
	mkdir -p $(D)
	@if [ -e $(DL_CACHE_DIR)/$($1_tarball) ] ; \
		then cp $(DL_CACHE_DIR)/$($1_tarball) $$@ ; \
	else \
		echo "Downloading $($1_url)" ; \
		curl -o $$@ -LO $($1_url) ; \
	fi
	@rm -f $(B)/.$1.download.ok

$(B)/.$1.download.ok: $(D)/$($1_tarball)
	@mkdir -p $(B)
	$$(call h1,"validating $1 $($1_version) checksum")
	@SHA256SUM=$$(shell openssl sha256 $$< | cut -f 2 -d " " -) ; \
	(([ "$$$${SHA256SUM}" = "$($1_tarball_sha256sum)" ] && echo "SHA256 OK") || \
	( echo "==========================================================" && \
	  echo "Bad Checksum!" && \
	  echo "Expected SHA256:   $($1_tarball_sha256)" && \
	  echo "Calculated SHA256: $$$${SHA256SUM}" && \
	  echo "Please remove $$< and retry" && \
	  echo "==========================================================" && \
	  false ))
	@touch $$@

.PHONY: $1-download
$1-download: $(B)/.$1.download.ok

##############################################################################
# Extract
##############################################################################
$(B)/.$1.extract.ok: $(B)/.$1.download.ok
	$$(call h1,"extracting $1 $($1_version)")
	@mkdir -p $$($1_src_dir)
	@tar \
	  --directory $$($1_src_dir) \
	  --extract \
	  --strip-components=$$($1_tarball_strip_dirs) \
	  --file $(D)/$($1_tarball)
	@touch $$@

.PHONY: $1-extract
$1-extract: $(B)/.$1.extract.ok

##############################################################################
# Patch
##############################################################################
$(B)/.$1.patch.ok: $(B)/.$1.extract.ok
	$$(call h1,"patching $1 $($1_version)")
ifneq ($$(wildcard $$($1_patch_dir)/*.patch),)
	@for f in $$($1_patch_dir)/*.patch ; do \
		echo "Applying patch: $$$$(basename $$$$f)" ; \
		patch -p1 -d $$($1_src_dir) < $$$$f ; \
	done
endif
	@touch $$@

.PHONY: $1-patch
$1-patch: $(B)/.$1.patch.ok

##############################################################################
# Config
##############################################################################

ifeq ($$(call $1_config_cmds),)
define $1_config_cmds
	@cd $$($1_build_dir) && \
	  CFLAGS="$$($1_cflags)" \
	  $$($1_src_dir)/configure \
	    --prefix=$$($1_install_dir) \
	    $$($1_configure_args) > $$($1_config_log)
endef
endif

ifneq ($(filter $1,$(VPP_SKIP_EXTERNAL)), $1)
$(B)/.$1.config.ok: $(B)/.$1.patch.ok $(addprefix $(B)/.,$(addsuffix .install.ok,$($1_depends)))
	$$(call h1,"configuring $1 $($1_version) - log: $$($1_config_log)")
	@mkdir -p $$($1_build_dir)
	$$(call $1_config_cmds)
	@touch $$@
else
$(B)/.$1.config.ok:
	$$(call h1,"Skipping $1 $($1_version)")
	@mkdir -p $(B)
	@touch $$@
endif

.PHONY: $1-config
$1-config: $(B)/.$1.config.ok

##############################################################################
# Build
##############################################################################

ifeq ($$(call $1_build_cmds),)
define $1_build_cmds
	@$(MAKE) $(MAKE_ARGS) -C $$($1_build_dir) > $$($1_build_log)
endef
endif

ifneq ($(filter $1,$(VPP_SKIP_EXTERNAL)), $1)
$(B)/.$1.build.ok: $(B)/.$1.config.ok
	$$(call h1,"building $1 $($1_version) - log: $$($1_build_log)")
	$$(call $1_build_cmds)
	@touch $$@
else
$(B)/.$1.build.ok:
	$$(call h1,"Skipping $1 $($1_version)")
	@mkdir -p $(B)
	@touch $$@
endif

.PHONY: $1-build
$1-build: $(B)/.$1.build.ok

##############################################################################
# Install
##############################################################################

ifeq ($$(call $1_install_cmds),)
define $1_install_cmds
	@$(MAKE) $(MAKE_ARGS) -C $$($1_build_dir) install > $$($1_install_log)
endef
endif

ifneq ($(filter $1,$(VPP_SKIP_EXTERNAL)), $1)
$(B)/.$1.install.ok: $(B)/.$1.build.ok
	$$(call h1,"installing $1 $($1_version) - log: $$($1_install_log)")
	$$(call $1_install_cmds)
	@touch $$@
else
$(B)/.$1.install.ok:
	$$(call h1,"Skipping $1 $($1_version)")
	@mkdir -p $(B)
	@touch $$@
endif

.PHONY: $1-install
$1-install: $(B)/.$1.install.ok

.PHONY: $1-show-%
$1-show-%:
	@echo $$($$*)

ALL_TARGETS += $1-install
endef
