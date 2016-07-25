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
	@sudo -E apt-get $(CONFIRM) $(FORCE) install $(DOC_DEB_DEPENDS)
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
			\( -name '*.[ch]' -or -name '*.dox' \) \
			-print | sed -e "s/^/\$$(SIPHON_FILES): /" >> $@; \
	done

# Include the source -> siphon dependencies
-include $(BR)/.doxygen-siphon.dep

.NOTPARALLEL: $(SIPHON_FILES)
$(SIPHON_FILES): $(DOXY_DIR)/siphon_generate.py $(BR)/.doxygen-bootstrap.ok
	@rm -rf "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	@mkdir -p "$(SIPHON_INPUT)" "$(SIPHON_OUTPUT)"
	set -e; for input in $(DOXY_INPUT); do \
		cd "$(WS_ROOT)"; \
		find "$$input" -type f \
			\( -name '*.[ch]' -or -name '*.dox' \) \
			-print >> $(SIPHON_INPUT)/files; \
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
	    HTML=YES \
	    VERSION="`git describe --tags --dirty`" \
	    doxygen $(DOXY_DIR)/doxygen.cfg

wipe-doxygen:
	rm -rf "$(BR)/docs" "$(BR)/.doxygen-siphon.d"

