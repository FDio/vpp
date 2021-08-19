# Copyright (c) 2021 Comcast Cable Communications Management, LLC.
#
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

#
# Build the documentation
#

# Default target
.PHONY: all
all: siphon

# These should be passed in by the root Makefile
WS_ROOT ?= $(CURDIR)/../..
BR ?= $(WS_ROOT)/build-root

# We support MacOS for docs generation
ifeq ($(shell uname),Darwin)
OS_ID = darwin
endif

# Work out the OS if we haven't already
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')

# Package dependencies
DOC_DEB_DEPENDS = python3-pyparsing python3-jinja2
DOC_RPM_DEPENDS = python3-pyparsing python3-jinja2
DOC_MAC_BIN_DEPENDS = git
DOC_MAC_PY_DEPENDS = pyparsing jinja2

# Doxygen configuration and our utility scripts
SIPHON_DIR ?= $(WS_ROOT)/docs/siphon

# Primary source directories
SIPHON_SRC ?= $(WS_ROOT)/src
SIPHON_SRC_DIRECTORIES = \
	$(shell find $(SIPHON_SRC) -name '*.md' -print | xargs dirname \
	| sort | uniq) \
	$(SIPHON_SRC)/vppinfra \
	$(SIPHON_SRC)/svm \
	$(SIPHON_SRC)/vlib \
	$(SIPHON_SRC)/vlibapi \
	$(SIPHON_SRC)/vlibmemory \
	$(SIPHON_SRC)/vnet \
	$(SIPHON_SRC)/vpp \
	$(SIPHON_SRC)/vpp-api \
	$(SIPHON_SRC)/examples

# Input directories and files
SIPHON_INPUT ?= \
	$(wildcard $(WS_ROOT)/*.md) \
	$(wildcard $(SIPHON_DIR)/*.md) \
	$(SIPHON_SRC_DIRECTORIES) \
	$(SIPHON_SRC)/plugins \
	extras

# Strip leading workspace path from input names
SIPHON_INPUT := $(subst $(WS_ROOT)/,,$(SIPHON_INPUT))

# Files to exclude, from pre-Doxygen steps, eg because they're
# selectively compiled.
# Examples would be to exclude non-DPDK related sources when
# there's a DPDK equivalent that conflicts.
# These must be left-anchored paths for the regexp below to work.
SIPHON_EXCLUDE ?= \
	$(SIPHON_SRC)/vpp-api/lua

# Generate a regexp for filenames to exclude
SIPHON_EXCLUDE_REGEXP = ($(subst .,\.,$(shell echo '$(strip $(SIPHON_EXCLUDE))' | sed -e 's/ /|/g')))

# Include all the normal source directories in the include file path
SIPHON_INCLUDE_PATH = $(SIPHON_SRC_DIRECTORIES)

# Find API header directories and include them in the header path.
# This is only useful if VPP and plugins are already built; nothing
# here depends on those targets. We don't build documentation for these
# header files, they're just added to the INCLUDE search path for Doxygen.
_vpp_br = $(shell find "$(BR)" -maxdepth 1 -type d \
	'(' -name build-vpp_debug-native -o -name build-vpp-native ')' -print \
	| sed -e 's@^$(WS_ROOT)/*@@' -e 1q)
ifneq ($(strip $(_vpp_br)),)
SIPHON_INCLUDE_PATH += \
	$(_vpp_br)/vlib-api \
	$(_vpp_br)/vpp
# Also include any plugin directories that exist
SIPHON_INCLUDE_PATH += \
	$(shell find $(WS_ROOT)/$(_vpp_br)/plugins -maxdepth 1 -type d | sed -e 's@^$(WS_ROOT)/*@@')
endif

# Discover if we have CPP available
_cpp = $(shell which cpp)
ifneq ($(strip $(_cpp)),)
# Add whatever directories CPP normally includes to the header path
SIPHON_INCLUDE_PATH += $(shell set -e; $(_cpp) -v </dev/null 2>&1 | awk 'f&&/^ /{print $$1} /^\#include/{f=1}')
endif

# docs root directory
DOCS_DIR ?= $(WS_ROOT)/docs

# Target directory for siphon output
SIPHON_OUTPUT ?= $(DOCS_DIR)/_siphon

# Siphoned fragments end up in here
SIPHON_INPUT_DIR ?= $(SIPHON_OUTPUT)/fragments

# Siphoned fragements are processed into here
SIPHON_OUTPUT_DIR ?= $(SIPHON_OUTPUT)

# All the siphon types we know about
SIPHONS ?= clicmd syscfg

SIPHON_FILES = $(addprefix $(SIPHON_INPUT_DIR)/,$(addsuffix .siphon,$(SIPHONS)))
SIPHON_DOCS = $(addprefix $(SIPHON_OUTPUT_DIR)/,$(addsuffix .rst,$(SIPHONS)))

# $(BR)/.siphon-bootstrap.ok: Makefile
# 	@echo "Checking whether dependencies for Doxygen are installed..."
# ifeq ($(OS_ID),ubuntu)
# 	@set -e; inst=; \
# 		for i in $(DOC_DEB_DEPENDS); do \
# 			dpkg-query --show $$i >/dev/null 2>&1 || inst="$$inst $$i"; \
# 		done; \
# 		if [ "$$inst" ]; then \
# 			sudo apt-get update; \
# 			sudo apt-get $(CONFIRM) $(FORCE) install $$inst; \
# 		fi
# 	@if [ ! -s /usr/lib/graphviz/config6a ]; then \
# 		echo "Rebuilding system Graphviz configuration."; \
# 		sudo dot -c; \
# 	fi
# else ifneq ("$(wildcard /etc/redhat-release)","")
# 	@sudo yum install $(CONFIRM) $(DOC_RPM_DEPENDS)
# else ifeq ($(OS_ID),darwin)
# 	@set -e; \
# 	for bin in $(DOC_MAC_BIN_DEPENDS); do \
# 		which -s $${bin} || (\
# 			echo "Program '$${bin}' not found, please install it."; \
# 			false; \
# 		); \
# 	done
# 	@set -e; \
# 	for py in $(DOC_MAC_PY_DEPENDS); do \
# 		python -c "import $${py}" >/dev/null 2>&1 || (\
# 			echo "Python package '$${py}' not found, please install it."; \
# 			false; \
# 		); \
# 	done
# else
# 	$(error "Building documentation currently works only on Ubuntu, CentOS, MacOS and OpenSUSE systems.")
# endif
# 	@touch $@

# .PHONY: bootstrap-siphon
# bootstrap-siphon: $(BR)/.siphon-bootstrap.ok

.DELETE_ON_ERROR: $(BR)/.siphon-siphon.dep
$(BR)/.siphon-siphon.dep: Makefile \
		$(addprefix,$(WSROOT),$(SIPHON_INPUT))
	@echo "Building siphon dependencies..."
	@rm -f "$@"; for input in $(SIPHON_INPUT); do \
		[ -e "$(WS_ROOT)/$$input" ] && \
		find "$(WS_ROOT)/$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^$(WS_ROOT)/$(SIPHON_EXCLUDE_REGEXP)' \
			| sed -e "s/^/\$$(SIPHON_FILES): /" \
			>> $@; \
	done

# Include the source -> siphon dependencies
# -include $(BR)/.siphon-siphon.dep

# Generate .siphon files that contain fragments of source file that
# relate to the siphons we support.
# $(BR)/.siphon-bootstrap.ok \
.NOTPARALLEL: $(SIPHON_FILES)
$(SIPHON_FILES): $(SIPHON_DIR)/siphon-generate \
		$(addprefix,$(WSROOT),$(SIPHON_INPUT)) \
		$(wildcard $(SIPHON_DIR)/siphon/*.py)
	@echo "Validating source tree..."
	@set -e; for input in $(SIPHON_INPUT); do \
		if [ ! -e "$(WS_ROOT)/$$input" ]; then \
			echo "ERROR: Input path '$$input' does not exist." >&2; \
			exit 1; \
		fi; \
	done
	@rm -rf "$(SIPHON_INPUT_DIR)" "$(SIPHON_OUTPUT_DIR)"
	@mkdir -p "$(SIPHON_INPUT_DIR)" "$(SIPHON_OUTPUT_DIR)"
	@touch $(SIPHON_INPUT_DIR)/files
	@echo "Collating source file list for siphoning..."
	@for input in $(SIPHON_INPUT); do \
		cd "$(WS_ROOT)"; \
		find "$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^src/examples/' \
			| grep -v -E '^$(SIPHON_EXCLUDE_REGEXP)' \
			>> $(SIPHON_INPUT_DIR)/files; \
	done
	@echo "Generating siphons..."
	@set -e; \
	cd "$(WS_ROOT)"; \
	$(SIPHON_DIR)/siphon-generate \
		--output="$(SIPHON_INPUT_DIR)" \
		"@$(SIPHON_INPUT_DIR)/files"

# Evaluate this to build a siphon doc output target for each desired
# output type:
# $(eval $(call siphon-process,file_extension,output_type_name))
define siphon-process
$(SIPHON_OUTPUT_DIR)/%.$(1): $(SIPHON_INPUT_DIR)/%.siphon \
		$(SIPHON_DIR)/siphon-process \
		$(wildcard $(SIPHON_DIR)/siphon/*.py) \
		$(wildcard $(SIPHON_DIR)/siphon_templates/$(2)/*/*.$(1))
	@echo "Processing siphon for $(2) from $$(notdir $$<)..."
	@set -e; \
	cd "$(WS_ROOT)"; \
	mkdir -p $(SIPHON_OUTPUT_DIR)/$$(basename $$(notdir $$<)).$(1).dir; \
	$(SIPHON_DIR)/siphon-process \
		--type=$$(basename $$(notdir $$<)) \
		--format=$(2) \
		--outdir=$(SIPHON_OUTPUT_DIR)/$$(basename $$(notdir $$<)).$(1).dir \
		--output="$$@" \
		"$$<"
endef

# Process the .siphon source fragments and render them into siphon flavored
# markdown documentation
.DELETE_ON_ERROR: $(SIPHON_DOCS)
$(eval $(call siphon-process,rst,markdown))

# This target can be used just to generate the siphoned things
.PHONY: siphon
siphon: $(SIPHON_DOCS)
	@rm -f $(DOCS_DIR)/cli-reference/index.rst
	@rm -rf $(DOCS_DIR)/cli-reference/clis
	@cp $(SIPHON_OUTPUT_DIR)/clicmd.rst $(DOCS_DIR)/cli-reference/index.rst
	@cp -r $(SIPHON_OUTPUT_DIR)/clicmd.rst.dir $(DOCS_DIR)/cli-reference/clis

.PHONY: wipe
wipe:
	@rm -rf $(BR)/.siphon.dep
	@rm -rf $(SIPHON_DIR)/siphon/__pycache__

.PHONY: clean
clean: wipe
