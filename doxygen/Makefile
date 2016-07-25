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

# These should be passed in by the root Makefile
WS_ROOT ?= $(CURDIR)/..
BR ?= $(WS_ROOT)/build-root
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')

# Package dependencies
DOC_DEB_DEPENDS = doxygen graphviz python-pyparsing
DOC_RPM_DEPENDS = doxygen graphviz pyparsing

# Doxygen configuration and our utility scripts
DOXY_DIR ?= $(WS_ROOT)/doxygen

# Input directories and files
DOXY_INPUT ?= \
	README.md \
	vppinfra \
	svm \
	vlib \
	vlib-api \
	vnet \
	vpp \
	vpp-api \
	plugins

# Files to exclude, from pre-Doxygen steps, eg because they're
# selectively compiled.
# Examples would be to exclude non-DPDK related sources when
# there's a DPDK equivalent that conflicts.
# This is specifically for the pre-Doxygen steps; Doxygen uses
# @cond for this instead.
DOXY_PRE_EXCLUDE ?= \
	vlib/vlib/buffer.c

# Generate a regexp for filenames to exclude
DOXY_PRE_EXCLUDE_REGEXP = ($(subst .,\.,$(shell echo '$(strip $(DOXY_PRE_EXCLUDE))' | sed -e 's/ /|/g')))

# Discover all the directories we might, possibly, maybe, have include files in
DOXY_INCLUDE_PATH = $(shell set -e; cd $(WS_ROOT); for item in $(DOXY_INPUT); do find $$item -type d; done)

# Discover if we have CPP available
CPP ?= $(shell which cpp)
ifneq ($(strip $(CPP)),)
# Add whatever directories CPP normally includes
DOXY_INCLUDE_PATH += $(shell set -e; $(CPP) -v </dev/null 2>&1 | grep -A 1000 '\#include' | awk '/^ /{print $$1}')
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
SIPHONS ?= clicmd

SIPHON_FILES = $(addprefix $(SIPHON_INPUT)/,$(addsuffix .siphon,$(SIPHONS)))
SIPHON_DOCS = $(addprefix $(SIPHON_OUTPUT)/,$(addsuffix .md,$(SIPHONS)))

$(BR)/.doxygen-bootstrap.ok:
ifeq ($(OS_ID),ubuntu)
	@set -e; inst=; \
		for i in $(DOC_DEB_DEPENDS); do \
			dpkg-query --show $$i >/dev/null 2>&1 || inst="$$inst $$i"; \
		done; \
		if [ "$$inst" ]; then sudo apt-get $(CONFIRM) $(FORCE) install $$inst; fi
else ifneq ("$(wildcard /etc/redhat-release)","")
	@sudo yum install $(CONFIRM) $(DOC_RPM_DEPENDS)
else
	$(error "This option currently works only on Ubuntu or Centos systems")
endif
	@touch $@

.PHONY: bootstrap-doxygen
bootstrap-doxygen: $(BR)/.doxygen-bootstrap.ok

.DELETE_ON_ERROR: $(BR)/.doxygen-siphon.dep
$(BR)/.doxygen-siphon.dep: Makefile
	set -e; rm -f "$@"; for input in $(DOXY_INPUT); do \
		find "$(WS_ROOT)/$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^$(WS_ROOT)/$(DOXY_PRE_EXCLUDE_REGEXP)$$' \
			| sed -e "s/^/\$$(SIPHON_FILES): /" \
			>> $@; \
	done

# Include the source -> siphon dependencies
-include $(BR)/.doxygen-siphon.dep

.NOTPARALLEL: $(SIPHON_FILES)
$(SIPHON_FILES): $(DOXY_DIR)/siphon_generate.py $(BR)/.doxygen-bootstrap.ok
	@rm -rf "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	@mkdir -p "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	@touch $(SIPHON_INPUT)/files
	for input in $(DOXY_INPUT); do \
		cd "$(WS_ROOT)"; \
		find "$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) -print \
			| grep -v -E '^$(DOXY_PRE_EXCLUDE_REGEXP)$$' \
			>> $(SIPHON_INPUT)/files; \
	done
	set -e; cd "$(WS_ROOT)"; $(DOXY_DIR)/siphon_generate.py \
		--output="$(SIPHON_INPUT)" \
		"@$(SIPHON_INPUT)/files"


.DELETE_ON_ERROR: $(SIPHON_DOCS)
$(SIPHON_OUTPUT)/%.md: $(SIPHON_INPUT)/%.siphon $(DOXY_DIR)/siphon_process.py
	set -e; cd "$(WS_ROOT)"; \
		$(DOXY_DIR)/siphon_process.py --type=$(basename $(notdir $<)) \
			--output="$(SIPHON_OUTPUT)" $< > $@

# This target can be used just to generate the siphoned docs
.PHONY: doxygen-siphon
doxygen-siphon: $(SIPHON_DOCS)

# Generate the doxygen docs
doxygen: $(SIPHON_DOCS)
	@mkdir -p "$(DOXY_OUTPUT)"
	set -e; cd "$(WS_ROOT)"; \
	    ROOT="$(WS_ROOT)" \
	    BUILD_ROOT="$(BR)" \
	    INPUT="$(addprefix $(WS_ROOT)/,$(DOXY_INPUT)) $(EXTRA_DOXY_INPUT)" \
	    INCLUDE_PATH="$(DOXY_INCLUDE_PATH)" \
	    HTML=YES \
	    VERSION="`git describe --tags --dirty`" \
	    doxygen $(DOXY_DIR)/doxygen.cfg

wipe-doxygen:
	rm -rf "$(BR)/docs" "$(BR)/.doxygen-siphon.d"

