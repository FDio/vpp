# Copyright (c) 2016 Comcast Cable Communications Management, LLC.
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
all: doxygen

# These should be passed in by the root Makefile
WS_ROOT ?= $(CURDIR)/..
BR ?= $(WS_ROOT)/build-root

# We support MacOS for docs generation
ifeq ($(shell uname),Darwin)
OS_ID = darwin
endif

# Work out the OS if we haven't already
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')

# Package dependencies
DOC_DEB_DEPENDS = doxygen graphviz python-pyparsing python-jinja2
DOC_RPM_DEPENDS = doxygen graphviz pyparsing python-jinja2
DOC_SUSE_RPM_DEPENDS = doxygen graphviz python-pyparsing python-Jinja2
DOC_MAC_BIN_DEPENDS = doxygen dot git
DOC_MAC_PY_DEPENDS = pyparsing jinja2

# Doxygen configuration and our utility scripts
DOXY_DIR ?= $(WS_ROOT)/doxygen

# Primary source directories
DOXY_SRC ?= src
DOXY_SRC_DIRECTORIES = \
	$(DOXY_SRC)/vppinfra \
	$(DOXY_SRC)/svm \
	$(DOXY_SRC)/vlib \
	$(DOXY_SRC)/vlibapi \
	$(DOXY_SRC)/vlibmemory \
	$(DOXY_SRC)/vlibsocket \
	$(DOXY_SRC)/vnet \
	$(DOXY_SRC)/vpp \
	$(DOXY_SRC)/vpp-api \
	$(DOXY_SRC)/uri \
	$(DOXY_SRC)/examples

# Input directories and files
DOXY_INPUT ?= \
	$(wildcard $(WS_ROOT)/*.md) \
	$(wildcard $(DOXY_DIR)/*.md) \
	$(DOXY_SRC_DIRECTORIES) \
	$(DOXY_SRC)/plugins

# Strip leading workspace path from input names
DOXY_INPUT := $(subst $(WS_ROOT)/,,$(DOXY_INPUT))

# Files to exclude, from pre-Doxygen steps, eg because they're
# selectively compiled.
# Examples would be to exclude non-DPDK related sources when
# there's a DPDK equivalent that conflicts.
# These must be left-anchored paths for the regexp below to work.
DOXY_EXCLUDE ?= \
	$(DOXY_SRC)/vlib/buffer.c \
	$(DOXY_SRC)/vpp-api/lua

# Generate a regexp for filenames to exclude
DOXY_EXCLUDE_REGEXP = ($(subst .,\.,$(shell echo '$(strip $(DOXY_EXCLUDE))' | sed -e 's/ /|/g')))

# Include all the normal source directories in the include file path
DOXY_INCLUDE_PATH = $(DOXY_SRC_DIRECTORIES)

# Find API header directories and include them in the header path.
# This is only useful if VPP and plugins are already built; nothing
# here depends on those targets. We don't build documentation for these
# header files, they're just added to the INCLUDE search path for Doxygen.
_vpp_br = $(shell find "$(BR)" -maxdepth 1 -type d \
	'(' -name build-vpp_debug-native -o -name build-vpp-native ')' -print \
	| sed -e 's@^$(WS_ROOT)/*@@' -e 1q)
ifneq ($(strip $(_vpp_br)),)
DOXY_INCLUDE_PATH += \
	$(_vpp_br)/vlib-api \
	$(_vpp_br)/vpp
# Also include any plugin directories that exist
DOXY_INCLUDE_PATH += \
	$(shell find $(WS_ROOT)/$(_vpp_br)/plugins -maxdepth 1 -type d | sed -e 's@^$(WS_ROOT)/*@@')
endif

# Discover if we have CPP available
_cpp = $(shell which cpp)
ifneq ($(strip $(_cpp)),)
# Add whatever directories CPP normally includes to the header path
DOXY_INCLUDE_PATH += $(shell set -e; $(_cpp) -v </dev/null 2>&1 | awk 'f&&/^ /{print $$1} /^\#include/{f=1}')
endif

# Target directory for doxygen output
DOXY_OUTPUT ?= $(BR)/docs

# Siphoned fragments end up in here
SIPHON_INPUT ?= $(DOXY_OUTPUT)/siphon_fragments

# Siphoned fragements are processed into here
SIPHON_OUTPUT ?= $(DOXY_OUTPUT)/siphon_docs

# Extra document inputs that are processed in addition to DOXY_INPUT
EXTRA_DOXY_INPUT += $(SIPHON_OUTPUT)

# All the siphon types we know about
SIPHONS ?= clicmd syscfg

SIPHON_FILES = $(addprefix $(SIPHON_INPUT)/,$(addsuffix .siphon,$(SIPHONS)))
SIPHON_DOCS = $(addprefix $(SIPHON_OUTPUT)/,$(addsuffix .md,$(SIPHONS)))
SIPHON_ITEMLIST = $(addprefix $(SIPHON_OUTPUT)/,$(addsuffix .itemlist,$(filter clicmd,$(SIPHONS))))

$(BR)/.doxygen-bootstrap.ok: Makefile
	@echo "Checking whether dependencies for Doxygen are installed..."
ifeq ($(OS_ID),ubuntu)
	@set -e; inst=; \
		for i in $(DOC_DEB_DEPENDS); do \
			dpkg-query --show $$i >/dev/null 2>&1 || inst="$$inst $$i"; \
		done; \
		if [ "$$inst" ]; then \
			sudo apt-get update; \
			sudo apt-get $(CONFIRM) $(FORCE) install $$inst; \
		fi
	@if [ ! -s /usr/lib/graphviz/config6a ]; then \
		echo "Rebuilding system Graphviz configuration."; \
		sudo dot -c; \
	fi
else ifneq ("$(wildcard /etc/redhat-release)","")
	@sudo yum install $(CONFIRM) $(DOC_RPM_DEPENDS)
else ifeq ($(OS_ID),darwin)
	@set -e; \
	for bin in $(DOC_MAC_BIN_DEPENDS); do \
		which -s $${bin} || (\
			echo "Program '$${bin}' not found, please install it."; \
			false; \
		); \
	done
	@set -e; \
	for py in $(DOC_MAC_PY_DEPENDS); do \
		python -c "import $${py}" >/dev/null 2>&1 || (\
			echo "Python package '$${py}' not found, please install it."; \
			false; \
		); \
	done
else ifeq ($(OS_ID),opensuse)
	@sudo zypper install $(CONFIRM) $(DOC_SUSE_RPM_DEPENDS)
else
	$(error "Building documentation currently works only on Ubuntu, CentOS, MacOS and OpenSUSE systems.")
endif
	@touch $@

.PHONY: bootstrap-doxygen
bootstrap-doxygen: $(BR)/.doxygen-bootstrap.ok

.DELETE_ON_ERROR: $(BR)/.doxygen-siphon.dep
$(BR)/.doxygen-siphon.dep: Makefile \
		$(addprefix,$(WSROOT),$(DOXY_INPUT))
	@echo "Building siphon dependencies..."
	@rm -f "$@"; for input in $(DOXY_INPUT); do \
		[ -e "$(WS_ROOT)/$$input" ] && \
		find "$(WS_ROOT)/$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^$(WS_ROOT)/$(DOXY_EXCLUDE_REGEXP)' \
			| sed -e "s/^/\$$(SIPHON_FILES): /" \
			>> $@; \
	done

# Include the source -> siphon dependencies
-include $(BR)/.doxygen-siphon.dep

# Generate .siphon files that contain fragments of source file that
# relate to the siphons we support.
.NOTPARALLEL: $(SIPHON_FILES)
$(SIPHON_FILES): $(BR)/.doxygen-bootstrap.ok \
		$(DOXY_DIR)/siphon-generate \
		$(addprefix,$(WSROOT),$(DOXY_INPUT)) \
		$(wildcard $(DOXY_DIR)/siphon/*.py)
	@echo "Validating source tree..."
	@set -e; for input in $(DOXY_INPUT); do \
		if [ ! -e "$(WS_ROOT)/$$input" ]; then \
			echo "ERROR: Input path '$$input' does not exist." >&2; \
			exit 1; \
		fi; \
	done
	@rm -rf "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	@mkdir -p "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	@touch $(SIPHON_INPUT)/files
	@echo "Collating source file list for siphoning..."
	@for input in $(DOXY_INPUT); do \
		cd "$(WS_ROOT)"; \
		find "$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^src/examples/' \
			| grep -v -E '^$(DOXY_EXCLUDE_REGEXP)' \
			>> $(SIPHON_INPUT)/files; \
	done
	@echo "Generating siphons..."
	@set -e; \
	cd "$(WS_ROOT)"; \
	$(DOXY_DIR)/siphon-generate \
		--output="$(SIPHON_INPUT)" \
		"@$(SIPHON_INPUT)/files"

# Evaluate this to build a siphon doc output target for each desired
# output type:
# $(eval $(call siphon-process,file_extension,output_type_name))
define siphon-process
$(SIPHON_OUTPUT)/%.$(1): $(SIPHON_INPUT)/%.siphon \
		$(DOXY_DIR)/siphon-process \
		$(wildcard $(DOXY_DIR)/siphon/*.py) \
		$(wildcard $(DOXY_DIR)/siphon_templates/$(2)/*/*.$(1))
	@echo "Processing siphon for $(2) from $$(notdir $$<)..."
	@set -e; \
	cd "$(WS_ROOT)"; \
	$(DOXY_DIR)/siphon-process \
		--type=$$(basename $$(notdir $$<)) \
		--format=$(2) \
		--output="$$@" \
		"$$<"
endef

# Process the .siphon source fragments and render them into doxygen flavored
# markdown documentation
.DELETE_ON_ERROR: $(SIPHON_DOCS)
$(eval $(call siphon-process,md,markdown))

# Process the .siphon source fragments and render them into a list of cli
# commands.
.DELETE_ON_ERROR: $(SIPHON_ITEMLIST)
$(eval $(call siphon-process,itemlist,itemlist))

# This target can be used just to generate the siphoned things
.PHONY: doxygen-siphon
doxygen-siphon: $(SIPHON_DOCS) $(SIPHON_ITEMLIST)

# Generate the doxygen docs
.PHONY: doxygen
doxygen: $(SIPHON_DOCS)
	@mkdir -p "$(DOXY_OUTPUT)"
	@echo "Running Doxygen..."
	set -e; cd "$(WS_ROOT)"; \
	    ROOT="$(WS_ROOT)" \
	    BUILD_ROOT="$(BR)" \
	    INPUT="$(addprefix $(WS_ROOT)/,$(DOXY_INPUT)) $(EXTRA_DOXY_INPUT)" \
	    INCLUDE_PATH="$(DOXY_INCLUDE_PATH)" \
	    EXCLUDE="$(DOXY_EXCLUDE)" \
	    HTML=YES \
	    VERSION="`git describe --tags --dirty`" \
	    doxygen $(DOXY_DIR)/doxygen.cfg

.PHONY: wipe-doxygen
wipe-doxygen:
	rm -rf "$(BR)/docs" "$(BR)/.doxygen-siphon.d"

.PHONY: clean
clean: wipe-doxygen
