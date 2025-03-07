# Copyright (c) 2021 Cisco and/or its affiliates.
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
# We support MacOS for docs generation
ifeq ($(shell uname),Darwin)
OS_ID = darwin
endif

# These should be passed in by the root Makefile
WS_ROOT ?= $(CURDIR)/..
BR ?= $(WS_ROOT)/build-root
DOCS_DIR ?= $(WS_ROOT)/docs
UV ?= $(WS_ROOT)/build-root/.local/bin/uv
SPHINX_SCRIPTS_DIR ?= $(WS_ROOT)/docs/scripts

# Work out the OS if we haven't already
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION ?= $(shell grep '^VERSION_ID=' /etc/os-release  | cut -f2- -d= | sed -e 's/\"//g')

# You can set these variables from the command line.
SPHINXOPTS        = --keep-going -n -W
SPHINXBUILD       = sphinx-build
SPHINXPROJ        = fdio-vpp
BUILDDIR          = ${BR}/docs
BUILDDIR_SRC      = ${BUILDDIR}/src
BUILDDIR_OUT      = ${BUILDDIR}/html
SCRIPTS_DIR       = _scripts
VENV_DIR          ?= $(BUILDDIR)/venv


# Put it first so that "make" without argument is like "make help".
.PHONY: help
help:
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  $(SPHINXBUILD) --help ;\
	)

.PHONY: spell
spell: venv
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  $(MAKE) -C ${SCRIPTS_DIR} generate && \
	  $(SPHINXBUILD) -b spelling $(SPHINXOPTS) $(BUILDDIR_SRC) $(BUILDDIR_OUT); \
	)

.PHONY: rebuild-spell
rebuild-spell: clean spell

.PHONY: docs
docs: venv
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  $(MAKE) -C ${SCRIPTS_DIR} generate && \
	  $(SPHINXBUILD) $(SPHINXOPTS) -b html $(BUILDDIR_SRC) $(BUILDDIR_OUT); \
	)

.PHONY: rebuild
rebuild: clean docs

.PHONY: clean
clean:
	@$(MAKE) -C ${SCRIPTS_DIR} clean

.PHONY: build
build: docs

# ========================= VENV =========================
INSTALL_MARKER := $(VENV_DIR)/.doc_installed
$(INSTALL_MARKER): pyproject.toml
	@echo "Installing package with dependencies... $(UV)"
	@$(UV) pip install --python=$(VENV_DIR)/bin/python -e ".[dev]"
	@touch $(INSTALL_MARKER)

.PHONY: venv
venv: $(INSTALL_MARKER)

.PHONY: sync-dependencies
sync-dependencies:
	@echo "Syncing dependencies..."
	@$(UV) pip sync pyproject.toml
# ========================= VENV =========================
