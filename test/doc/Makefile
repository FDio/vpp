# Makefile for VPP Test documentation
#

SPHINXOPTS    =
SRC_DOC_DIR = $(TEST_DIR)/doc
SPHINXBUILD = sphinx-build
HTML_DOC_GEN_DIR = $(TEST_DOC_BR)/html
API_DOC_GEN_DIR = $(TEST_DOC_BR)/api

# Internal variables.
ALLSPHINXOPTS   = -d $(TEST_DOC_BR)/.sphinx-cache $(SPHINXOPTS) $(API_DOC_GEN_DIR) -c $(SRC_DOC_DIR)
IN_VENV:=$(shell if pip -V | grep "venv" 2>&1 > /dev/null; then echo 1; else echo 0; fi)

.PHONY: verify-virtualenv
verify-virtualenv:
ifndef TEST_DIR
	$(error TEST_DIR is not set)
endif
ifndef TEST_DOC_BR
	$(error TEST_DOC_BR is not set)
endif
ifndef BUILD_TEST_SRC
	$(error BUILD_TEST_SRC is not set)
endif
ifeq ($(IN_VENV),0)
	$(error "Not running inside virtualenv (are you running 'make test-doc' from root?)")
endif

.PHONY: regen-api-doc
regen-api-doc: verify-virtualenv
	@mkdir -p $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/index.rst $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/indices.rst $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/overview.rst $(API_DOC_GEN_DIR)
	sphinx-apidoc -o $(API_DOC_GEN_DIR) -H "Module documentation" $(BUILD_TEST_SRC)

.PHONY: html
html: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(HTML_DOC_GEN_DIR)
