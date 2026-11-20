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
# Thin wrapper: the docs build itself (sources, siphons, generated files,
# sphinx, spell check) is implemented in docs/docs.py and described by
# docs/docs.json, shared with the cmake build ("ninja docs"). This makefile only
# takes care of the python virtualenv, the cmake build has its own.

# These should be passed in by the root Makefile
WS_ROOT ?= $(CURDIR)/..
BR ?= $(WS_ROOT)/build-root

PYTHON ?= "python3"
PYTHON_VERSION_OK := $(shell $(PYTHON) -c "exec('import sys\nif sys.hexversion >= 0x03070000: print(\"true\")\nelse: print(\"false\")')")
ifneq ($(PYTHON_VERSION_OK),true)
$(error "ERROR: docs build requires python version >= to 3.7")
endif

PIP_VERSION ?= $(shell grep 'PIP_VERSION=' ${WS_ROOT}/test/Makefile | cut -d'=' -f2)
PIP_TOOLS_VERSION ?= $(shell grep 'PIP_TOOLS_VERSION=' ${WS_ROOT}/test/Makefile | cut -d'=' -f2)

OUT_DIR = $(BR)/.docs-build
VENV_DIR ?= $(OUT_DIR)/venv
DOCS_PY = $(VENV_DIR)/bin/python3 $(WS_ROOT)/docs/docs.py

.PHONY: help
help:
	@( \
	  . ${VENV_DIR}/bin/activate; \
	  sphinx-build --help ;\
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

# builds the html docs and fails on spelling errors
.PHONY: docs
docs: venv
	@$(DOCS_PY) build --out-dir $(OUT_DIR) --venv $(VENV_DIR)

.PHONY: spell
spell: docs

.PHONY: rebuild
rebuild: clean docs

.PHONY: rebuild-spell
rebuild-spell: rebuild

.PHONY: clean
clean:
	@rm -rf $(OUT_DIR)

.PHONY: build
build: docs
