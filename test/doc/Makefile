# Makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SRC_DOC_DIR = $(TEST_DIR)/doc
SPHINXBUILD = sphinx-build
PAPER         =
BUILD_DOC_ROOT = $(TEST_DIR)/doc
BUILD_DOC_DIR = $(BUILD_DOC_ROOT)/build
API_DOC_GEN_DIR = $(BUILD_DOC_ROOT)/apidoc

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILD_DOC_DIR)/.sphinx-cache $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) $(API_DOC_GEN_DIR) -c $(SRC_DOC_DIR)
# the i18n builder cannot share the environment and doctrees with the others
I18NSPHINXOPTS  = $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) .
IN_VENV:=$(shell if pip -V | grep "venv" 2>&1 > /dev/null; then echo 1; else echo 0; fi)

.PHONY: verify-virtualenv
verify-virtualenv:
ifeq ($(IN_VENV),0)
	$(error "Not running inside virtualenv (are you running 'make test-doc' from root?)")
endif

.PHONY: regen-api-doc
regen-api-doc: verify-virtualenv
	@mkdir -p $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/exceptions.rst $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/index.rst $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/indices.rst $(API_DOC_GEN_DIR)
	@cp $(SRC_DOC_DIR)/overview.rst $(API_DOC_GEN_DIR)
	sphinx-apidoc -o $(API_DOC_GEN_DIR) -H "Module documentation" ..

.PHONY: help
help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make standalone HTML files"
	@echo "  dirhtml    to make HTML files named index.html in directories"
	@echo "  singlehtml to make a single large HTML file"
	@echo "  pickle     to make pickle files"
	@echo "  json       to make JSON files"
	@echo "  htmlhelp   to make HTML files and a HTML help project"
	@echo "  qthelp     to make HTML files and a qthelp project"
	@echo "  applehelp  to make an Apple Help Book"
	@echo "  devhelp    to make HTML files and a Devhelp project"
	@echo "  epub       to make an epub"
	@echo "  epub3      to make an epub3"
	@echo "  latex      to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "  latexpdf   to make LaTeX files and run them through pdflatex"
	@echo "  latexpdfja to make LaTeX files and run them through platex/dvipdfmx"
	@echo "  text       to make text files"
	@echo "  man        to make manual pages"
	@echo "  texinfo    to make Texinfo files"
	@echo "  info       to make Texinfo files and run them through makeinfo"
	@echo "  gettext    to make PO message catalogs"
	@echo "  changes    to make an overview of all changed/added/deprecated items"
	@echo "  xml        to make Docutils-native XML files"
	@echo "  pseudoxml  to make pseudoxml-XML files for display purposes"
	@echo "  linkcheck  to check all external links for integrity"
	@echo "  doctest    to run all doctests embedded in the documentation (if enabled)"
	@echo "  coverage   to run coverage check of the documentation (if enabled)"
	@echo "  dummy      to check syntax errors of document sources"

.PHONY: wipe
wipe:
	rm -rf $(BUILD_DOC_ROOT)

.PHONY: html
html: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILD_DOC_DIR)/html."

.PHONY: dirhtml
dirhtml: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(BUILD_DOC_DIR)/dirhtml."

.PHONY: singlehtml
singlehtml: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(BUILD_DOC_DIR)/singlehtml."

.PHONY: pickle
pickle: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b pickle $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/pickle
	@echo
	@echo "Build finished; now you can process the pickle files."

.PHONY: json
json: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b json $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/json
	@echo
	@echo "Build finished; now you can process the JSON files."

.PHONY: htmlhelp
htmlhelp: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b htmlhelp $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/htmlhelp
	@echo
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      ".hhp project file in $(BUILD_DOC_DIR)/htmlhelp."

.PHONY: qthelp
qthelp: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b qthelp $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/qthelp
	@echo
	@echo "Build finished; now you can run "qcollectiongenerator" with the" \
	      ".qhcp project file in $(BUILD_DOC_DIR)/qthelp, like this:"
	@echo "# qcollectiongenerator $(BUILD_DOC_DIR)/qthelp/VPPtestframework.qhcp"
	@echo "To view the help file:"
	@echo "# assistant -collectionFile $(BUILD_DOC_DIR)/qthelp/VPPtestframework.qhc"

.PHONY: applehelp
applehelp: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b applehelp $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/applehelp
	@echo
	@echo "Build finished. The help book is in $(BUILD_DOC_DIR)/applehelp."
	@echo "N.B. You won't be able to view it unless you put it in" \
	      "~/Library/Documentation/Help or install it in your application" \
	      "bundle."

.PHONY: devhelp
devhelp: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b devhelp $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/devhelp
	@echo
	@echo "Build finished."
	@echo "To view the help file:"
	@echo "# mkdir -p $$HOME/.local/share/devhelp/VPPtestframework"
	@echo "# ln -s $(BUILD_DOC_DIR)/devhelp $$HOME/.local/share/devhelp/VPPtestframework"
	@echo "# devhelp"

.PHONY: epub
epub: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b epub $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/epub
	@echo
	@echo "Build finished. The epub file is in $(BUILD_DOC_DIR)/epub."

.PHONY: epub3
epub3:
	$(SPHINXBUILD) -b epub3 $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/epub3
	@echo
	@echo "Build finished. The epub3 file is in $(BUILD_DOC_DIR)/epub3."

.PHONY: latex
latex: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/latex
	@echo
	@echo "Build finished; the LaTeX files are in $(BUILD_DOC_DIR)/latex."
	@echo "Run \`make' in that directory to run these through (pdf)latex" \
	      "(use \`make latexpdf' here to do that automatically)."

.PHONY: latexpdf
latexpdf: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	$(MAKE) -C $(BUILD_DOC_DIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(BUILD_DOC_DIR)/latex."

.PHONY: latexpdfja
latexpdfja: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/latex
	@echo "Running LaTeX files through platex and dvipdfmx..."
	$(MAKE) -C $(BUILD_DOC_DIR)/latex all-pdf-ja
	@echo "pdflatex finished; the PDF files are in $(BUILD_DOC_DIR)/latex."

.PHONY: text
text: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b text $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/text
	@echo
	@echo "Build finished. The text files are in $(BUILD_DOC_DIR)/text."

.PHONY: man
man: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b man $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/man
	@echo
	@echo "Build finished. The manual pages are in $(BUILD_DOC_DIR)/man."

.PHONY: texinfo
texinfo: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/texinfo
	@echo
	@echo "Build finished. The Texinfo files are in $(BUILD_DOC_DIR)/texinfo."
	@echo "Run \`make' in that directory to run these through makeinfo" \
	      "(use \`make info' here to do that automatically)."

.PHONY: info
info: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/texinfo
	@echo "Running Texinfo files through makeinfo..."
	make -C $(BUILD_DOC_DIR)/texinfo info
	@echo "makeinfo finished; the Info files are in $(BUILD_DOC_DIR)/texinfo."

.PHONY: gettext
gettext: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b gettext $(I18NSPHINXOPTS) $(BUILD_DOC_DIR)/locale
	@echo
	@echo "Build finished. The message catalogs are in $(BUILD_DOC_DIR)/locale."

.PHONY: changes
changes: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b changes $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/changes
	@echo
	@echo "The overview file is in $(BUILD_DOC_DIR)/changes."

.PHONY: linkcheck
linkcheck: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b linkcheck $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/linkcheck
	@echo
	@echo "Link check complete; look for any errors in the above output " \
	      "or in $(BUILD_DOC_DIR)/linkcheck/output.txt."

.PHONY: doctest
doctest: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILD_DOC_DIR)/doctest/output.txt."

.PHONY: coverage
coverage: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b coverage $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/coverage
	@echo "Testing of coverage in the sources finished, look at the " \
	      "results in $(BUILD_DOC_DIR)/coverage/python.txt."

.PHONY: xml
xml: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b xml $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/xml
	@echo
	@echo "Build finished. The XML files are in $(BUILD_DOC_DIR)/xml."

.PHONY: pseudoxml
pseudoxml: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b pseudoxml $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/pseudoxml
	@echo
	@echo "Build finished. The pseudo-XML files are in $(BUILD_DOC_DIR)/pseudoxml."

.PHONY: dummy
dummy: regen-api-doc verify-virtualenv
	$(SPHINXBUILD) -b dummy $(ALLSPHINXOPTS) $(BUILD_DOC_DIR)/dummy
	@echo
	@echo "Build finished. Dummy builder generates no files."
