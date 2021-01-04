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

VENV_DIR ?= $(DOCS_DIR)/venv
SPHINX_SCRIPTS_DIR ?= $(WS_ROOT)/docs/scripts

# Work out the OS if we haven't already
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION ?= $(shell grep '^VERSION_ID=' /etc/os-release  | cut -f2- -d= | sed -e 's/\"//g')
PIP_VERSION ?= $(shell grep 'PIP_VERSION=' ${WS_ROOT}/test/Makefile | cut -d'=' -f2)
PIP_TOOLS_VERSION ?= $(shell grep 'PIP_TOOLS_VERSION=' ${WS_ROOT}/test/Makefile | cut -d'=' -f2)

PYTHON ?= "python3"
PYTHON_VERSION_OK := $(shell $(PYTHON) -c "exec('import sys\nif sys.hexversion >= 0x03070000: print(\"true\")\nelse: print(\"false\")')")
ifneq ($(PYTHON_VERSION_OK),true)
$(error "ERROR: docs build requires python version >= to 3.7")
endif

# You can set these variables from the command line.
SPHINXOPTS        = --keep-going -n -W
SPHINXBUILD       = sphinx-build
SPHINXPROJ        = fdio-vpp
SOURCEDIR         = .
BUILDDIR          = ${BR}/docs
BUILDDIR_SRC      = ${BUILDDIR}/src
BUILDDIR_OUT      = ${BUILDDIR}/html
SCRIPTS_DIR       = _scripts


# Put it first so that "make" without argument is like "make help".
.PHONY: help
help:
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  $(SPHINXBUILD) --help ;\
	)

.PHONY: checkdeps
checkdeps:
	@echo "Checking whether dependencies for Docs are installed..."
ifeq ($(OS_ID),ubuntu)
	@set -e; inst=; \
		for i in $(DOC_DEB_DEPENDS); do \
			dpkg-query --show $$i >/dev/null 2>&1 || inst="$$inst $$i"; \
		done; \
		if [ "$$inst" ]; then \
			sudo apt-get update; \
			sudo apt-get $(CONFIRM) $(FORCE) install $$inst; \
		fi
endif

.PHONY: spell
spell: clean checkdeps venv ${BUILDDIR_SRC}
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  make -C ${SCRIPTS_DIR} generate && \
	  $(SPHINXBUILD) -b spelling $(SPHINXOPTS) $(BUILDDIR_SRC) $(BUILDDIR_OUT); \
	)

.PHONY: venv
venv:
	@( \
	    if [ ! -d ${VENV_DIR} ]; then \
	      ${PYTHON} -m venv ${VENV_DIR}; \
	      . ${VENV_DIR}/bin/activate; \
	      ${PYTHON} -m pip install pip==${PIP_VERSION}; \
	      ${PYTHON} -m pip install pip-tools==${PIP_TOOLS_VERSION}; \
	      ${PYTHON} -m pip install -r ${WS_ROOT}/test/requirements-3.txt; \
	    fi; \
	)

${BUILDDIR_SRC}:
	@mkdir -p ${BUILDDIR_SRC}
	@cp -r $(SOURCEDIR) ${BUILDDIR_SRC}
	@cd ${BUILDDIR_SRC} && find . -type l -exec cp --remove-destination -L ${DOCS_DIR}/{} {} \;

.PHONY: docs
docs: clean venv ${BUILDDIR_SRC}
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  make -C ${SCRIPTS_DIR} generate && \
	  $(SPHINXBUILD) $(SPHINXOPTS) -b html $(BUILDDIR_SRC) $(BUILDDIR_OUT); \
	)

.PHONY: clean
clean:
	@rm -rf $(BUILDDIR) ${VENV_DIR}
	@make -C ${SCRIPTS_DIR} clean

.PHONY: build
build: docs
