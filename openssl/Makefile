# Copyright (c) 2018 Intel and/or its affiliates.
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

# Scripts require non-POSIX parts of bash
SHELL := /bin/bash

OPENSSL_BUILD_DIR        ?= $(CURDIR)/_build
OPENSSL_INSTALL_DIR      ?= $(CURDIR)/_install
OPENSSL_DOWNLOAD_DIR     ?= $(HOME)/Downloads
OPENSSL_DEBUG            ?= n

B := $(OPENSSL_BUILD_DIR)
I := $(OPENSSL_INSTALL_DIR)
OPENSSL_VERSION ?= 1.1.0g
OPENSSL_BASE_URL ?= https://www.openssl.org/source
OPENSSL_TARBALL := openssl-1.1.0g.tar.gz
OPENSSL_TAR_URL := $(OPENSSL_BASE_URL)/$(OPENSSL_TARBALL)
OPENSSL_1.1.0g_TARBALL_SHA1_CKSUM := e8240a8be304d4317a750753321b073c664bfdd4
OPENSSL_SOURCE := $(B)/openssl-$(OPENSSL_VERSION)
MACHINE=$(shell uname -m)

# compiler/linker custom arguments
ifneq (,$(findstring clang,$(CC)))
OPENSSL_CC=clang
else ifneq (,$(findstring icc,$(CC)))
OPENSSL_CC=icc
else
OPENSSL_CC=gcc
endif

ifeq ($(OPENSSL_DEBUG),y)
OPENSSL_CONF_FLAGS := -d
endif

all: build

$(CURDIR)/$(OPENSSL_TARBALL):
	@if [ -e $(OPENSSL_DOWNLOAD_DIR)/$(OPENSSL_TARBALL) ] ; \
		then cp $(OPENSSL_DOWNLOAD_DIR)/$(OPENSSL_TARBALL) $(CURDIR) ; \
		else curl -o $(CURDIR)/$(OPENSSL_TARBALL) -LO $(OPENSSL_TAR_URL) ; \
        fi
	@rm -f $(B)/.download.ok

OPENSSL_DOWNLOADS = $(CURDIR)/$(OPENSSL_TARBALL)

$(B)/.download.ok: $(OPENSSL_DOWNLOADS)
	@mkdir -p $(B)
	@openssl sha1 $< | cut -f 2 -d " " - > $(B)/$(OPENSSL_TARBALL).sha1sum
	@([ "$$(<$(B)/$(OPENSSL_TARBALL).sha1sum)" = "$(OPENSSL_$(OPENSSL_VERSION)_TARBALL_SHA1_CKSUM)" ] || \
	( echo "Bad Checksum! Please remove $< and retry" && \
		rm $(B)/$(OPENSSL_TARBALL).sha1sum && false ))
	@touch $@

.PHONY: download
download: $(B)/.download.ok

$(B)/.extract.ok: $(B)/.download.ok
	@echo --- extracting $(OPENSSL_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(OPENSSL_TARBALL)
	@touch $@

.PHONY: extract
extract: $(B)/.extract.ok

$(B)/.patch.ok: $(B)/.extract.ok
ifneq ($(wildcard $(CURDIR)/openssl-$(OPENSSL_VERSION)_patches/*.patch),)
	@echo --- patching ---
	@for f in $(CURDIR)/openssl-$(OPENSSL_VERSION)_patches/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(OPENSSL_SOURCE) < $$f ; \
	done
endif
	@touch $@

.PHONY: patch
patch: $(B)/.patch.ok

$(B)/.config.ok: $(B)/.patch.ok
	@cd $(OPENSSL_SOURCE);./config $(OPENSSL_CONF_FLAGS) --prefix=$(I)
	@touch $@

.PHONY: config
config: $(B)/.config.ok

.PHONY: build-openssl
build-openssl: $(B)/.config.ok
	@make -C $(OPENSSL_SOURCE)
	@make -C $(OPENSSL_SOURCE) install

BUILD_TARGETS = build-openssl

$(B)/.build.ok: $(BUILD_TARGETS)
	@touch $@

.PHONY: build
build: $(B)/.build.ok

.PHONY: install
install: $(B)/.build.ok

.PHONY: install-deb
install-deb: $(B)/.build.ok

.PHONY: install-rpm
install-rpm: $(B)/.build.ok

.PHONY: ebuild-build
ebuild-build: $(B)/.build.ok

.PHONY: ebuild-install
ebuild-install: $(B)/.build.ok


.PHONY: clean
clean:
	@rm -rf $(B) $(I)

