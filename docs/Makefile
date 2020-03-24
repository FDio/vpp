# Minimal makefile for Sphinx documentation
#
# We support MacOS for docs generation
ifeq ($(shell uname),Darwin)
OS_ID = darwin
endif

# Work out the OS if we haven't already
OS_ID ?= $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')

DOC_DEB_DEPENDS = enchant
DOC_RPM_DEPENDS = enchant

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = fdio-vpp
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
# Generate dynamic content
	@python3 ./includes_renderer.py
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

spell:
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
else ifneq ("$(wildcard /etc/redhat-release)","")
	@sudo yum install $(CONFIRM) $(DOC_RPM_DEPENDS)
endif
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" -W -b spelling  $(O)
