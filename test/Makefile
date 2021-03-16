ASAN_OPTIONS?=verify_asan_link_order=0:detect_leaks=0:abort_on_error=1:unmap_shadow_on_exit=1:disable_coredump=0
export ASAN_OPTIONS

.PHONY: verify-env
verify-env:
ifndef WS_ROOT
	$(error WS_ROOT is not set)
endif
ifndef BR
	$(error BR is not set)
endif
ifndef TEST_DIR
	$(error TEST_DIR is not set)
endif

export TEST_BR = $(BR)/build-test
export TEST_DOC_BR = $(TEST_BR)/doc
export BUILD_TEST_SRC = $(TEST_BR)/src
FAILED_DIR=/tmp/vpp-failed-unittests/
PLUGIN_TEST_DIRS=$(shell find $(PLUGIN_SRC_DIR) -type d -name test -exec echo -n " -d {}" \;)
CORE_TEST_DIRS=$(shell find $(WS_ROOT)/src -not \( -path $(INTERN_PLUGIN_SRC_DIR) -prune \) -type d -name test -exec echo -n " -d {}" \;)
VPP_TEST_DIRS=$(shell ls -d $(TEST_DIR)$(PLUGIN_TEST_DIRS)$(CORE_TEST_DIRS) $(EXTERN_TESTS))
VPP_TEST_SRC=$(shell for dir in $(VPP_TEST_DIRS) ; do ls $$dir/*.py; done)

FORCE_NO_WIPE=0
ifeq ($(DEBUG),gdb)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),gdbserver)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),gdb-all)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),gdbserver-all)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),core)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),attach)
FORCE_FOREGROUND=1
FORCE_NO_WIPE=1
else ifeq ($(STEP),yes)
FORCE_FOREGROUND=1
else ifeq ($(STEP),y)
FORCE_FOREGROUND=1
else ifeq ($(STEP),1)
FORCE_FOREGROUND=1
else
FORCE_FOREGROUND=0
endif

ifdef PROFILE_OUTPUT
PROFILE_OUTPUT_OPTS=-o $(PROFILE_OUTPUT)
endif

ifndef PROFILE_SORT_BY
PROFILE_SORT_BY=cumtime
endif

ifeq ($(PROFILE),1)
PYTHON_PROFILE_OPTS=-m cProfile $(PROFILE_OUTPUT_OPTS) -s $(PROFILE_SORT_BY)
FORCE_FOREGROUND=1
endif

UNITTEST_EXTRA_OPTS=
UNITTEST_FAILFAST_OPTS=

ifeq ($(FAILFAST),1)
UNITTEST_EXTRA_OPTS=-f
endif

ifneq ($(EXTERN_TESTS),)
UNITTEST_EXTRA_OPTS=$(UNITTEST_FAILFAST_OPTS) -d $(EXTERN_TESTS)
endif

VENV_PATH=$(TEST_BR)/venv

ifeq ($(TEST_DEBUG),1)
VENV_RUN_DIR:=$(VENV_PATH)/run-debug
else
VENV_RUN_DIR:=$(VENV_PATH)/run
endif

ifeq ($(PYTHON),)
PYTHON_INTERP=python3
else
PYTHON_INTERP=$(PYTHON)
endif

PYTHON_VERSION=$(shell $(PYTHON_INTERP) -c 'import sys; print(sys.version_info.major)')
PIP_VERSION=20.1.1
# Keep in sync with requirements.txt
PIP_TOOLS_VERSION=5.1.2
PYTHON_DEPENDS=requirements-$(PYTHON_VERSION).txt
SCAPY_SOURCE=$(shell find $(VENV_PATH)/lib/python* -name site-packages)
BUILD_COV_DIR=$(TEST_BR)/coverage

PIP_TOOLS_INSTALL_DONE=$(VENV_RUN_DIR)/pip-tools-install-$(PYTHON_VERSION)-$(PIP_TOOLS_VERSION).done
PIP_INSTALL_DONE=$(VENV_RUN_DIR)/pip-install-$(PYTHON_VERSION)-$(PIP_VERSION).done
PIP_PATCH_DONE=$(VENV_RUN_DIR)/pip-patch-$(PYTHON_VERSION).done
PAPI_INSTALL_DONE=$(VENV_RUN_DIR)/papi-install-$(PYTHON_VERSION).done
PAPI_PYTHON_SRC_DIR=$(WS_ROOT)/src/vpp-api/python
PAPI_WIPE_DIST=$(WS_ROOT)/src/vpp-api/vapi/__pycache__ \
	$(PAPI_PYTHON_SRC_DIR)/build \
	$(PAPI_PYTHON_SRC_DIR)/vpp_papi.egg-info \
	$(PAPI_PYTHON_SRC_DIR)/vpp_papi/__pycache__

$(PIP_TOOLS_INSTALL_DONE):
	@rm -rf $(VENV_PATH)
	@mkdir -p $(VENV_RUN_DIR)
	@virtualenv $(VENV_PATH) -p $(PYTHON_INTERP)
	# pip version pinning
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  $(PYTHON_INTERP) -m pip install pip===$(PIP_VERSION)"
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  $(PYTHON_INTERP) -m pip install pip-tools===$(PIP_TOOLS_VERSION)"
	@touch $@

$(PYTHON_DEPENDS): requirements.txt
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  CUSTOM_COMPILE_COMMAND='make test-refresh-deps (or update requirements.txt)' \
		  $(PYTHON_INTERP) -m piptools compile -q --generate-hashes requirements.txt --output-file $@"

$(PIP_INSTALL_DONE): $(PIP_TOOLS_INSTALL_DONE) $(PYTHON_DEPENDS)
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  $(PYTHON_INTERP) -m piptools sync $(PYTHON_DEPENDS)"
	@touch $@

$(PIP_PATCH_DONE): $(PIP_INSTALL_DONE)
	@echo --- patching ---
	@sleep 1 # Ensure python recompiles patched *.py files -> *.pyc
	for f in $(CURDIR)/patches/scapy-2.4.3/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch --forward -p1 -d $(SCAPY_SOURCE) < $$f ; \
		retCode=$$?; \
		[ $$retCode -gt 1 ] && exit $$retCode; \
	done; \
	touch $@

$(PAPI_INSTALL_DONE): $(PIP_PATCH_DONE)
	@bash -c "source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) -m pip install -e $(PAPI_PYTHON_SRC_DIR)"
	@touch $@

.PHONY: refresh-deps
refresh-deps: clean-deps $(PYTHON_DEPENDS)

.PHONY: clean-deps
clean-deps:
	@rm -f $(PYTHON_DEPENDS)

INTERN_PLUGIN_SRC_DIR=$(WS_ROOT)/src/plugins
ifneq ($(EXTERN_PLUGIN_SRC_DIR),)
PLUGIN_SRC_DIR=$(EXTERN_PLUGIN_SRC_DIR)
else
PLUGIN_SRC_DIR=$(INTERN_PLUGIN_SRC_DIR)
endif

define retest-func
@env VPP_IN_GDB=$(VPP_IN_GDB) FORCE_FOREGROUND=$(FORCE_FOREGROUND) FAILED_DIR=$(FAILED_DIR) VENV_PATH=$(VENV_PATH) scripts/setsid_wrapper.sh $(FORCE_FOREGROUND) $(VENV_PATH)/bin/activate $(PYTHON_INTERP) $(PYTHON_PROFILE_OPTS) $(BUILD_TEST_SRC)/run_tests.py -d $(BUILD_TEST_SRC) $(UNITTEST_EXTRA_OPTS) || env FAILED_DIR=$(FAILED_DIR) COMPRESS_FAILED_TEST_LOGS=$(COMPRESS_FAILED_TEST_LOGS) scripts/compress_failed.sh
endef

.PHONY: sanity

ifeq ($(SANITY),no)
SANITY_IMPORT_VPP_PAPI_CMD=true
SANITY_RUN_VPP_CMD=true
else
SANITY_IMPORT_VPP_PAPI_CMD=source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) $(BUILD_TEST_SRC)/sanity_import_vpp_papi.py
SANITY_RUN_VPP_CMD=source $(VENV_PATH)/bin/activate && PYTHONPATH=$(BUILD_TEST_SRC) $(PYTHON_INTERP) $(BUILD_TEST_SRC)/sanity_run_vpp.py
endif

ifndef TEST_JOBS
PARALLEL_ILLEGAL=0
else ifeq ($(FORCE_FOREGROUND),0)
PARALLEL_ILLEGAL=0
else ifeq ($(TEST_JOBS),auto)
PARALLEL_ILLEGAL=0
else ifeq ($(TEST_JOBS),1)
PARALLEL_ILLEGAL=0
else
PARALLEL_ILLEGAL=1
endif

sanity: test-dep
	@bash -c "test $(PARALLEL_ILLEGAL) -eq 0 ||\
	    (echo \"*******************************************************************\" &&\
		 echo \"* Sanity check failed, TEST_JOBS is not 1 or 'auto' and DEBUG, STEP or PROFILE is set\" &&\
	         echo \"*******************************************************************\" &&\
		 false)"
	@bash -c "$(SANITY_IMPORT_VPP_PAPI_CMD) ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Sanity check failed, cannot import vpp_papi\" &&\
		 echo \"* to debug: \" &&\
		 echo \"* 1. enter test shell:   make test-shell\" &&\
		 echo \"* 2. execute debugger:   gdb python -ex 'run sanity_import_vpp_papi.py'\" &&\
	         echo \"*******************************************************************\" &&\
		 false)"
	@bash -c "$(SANITY_RUN_VPP_CMD) ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Sanity check failed, cannot run vpp\" &&\
	         echo \"*******************************************************************\" &&\
		 false)"

.PHONY: ext-test-apps
ext-test-apps:
	make -C ext test-apps

$(BUILD_TEST_SRC): verify-env
	@mkdir -p $@
	@for file in $(VPP_TEST_SRC); do if [ ! -L $$file ] && [ ! -e $(BUILD_TEST_SRC)/$$(basename $$file) ] ; then ln -s $$file $(BUILD_TEST_SRC) ; fi ; done

$(FAILED_DIR): reset
	@mkdir -p $@

.PHONY: test-dep
test-dep: $(BUILD_TEST_SRC) $(PAPI_INSTALL_DONE) $(FAILED_DIR)

.PHONY: test
test: test-dep ext-test-apps sanity
	$(call retest-func)

.PHONY: retest
retest: verify-env sanity $(FAILED_DIR)
	$(call retest-func)

.PHONY: shell
shell: test-dep
	@echo "source $(VENV_PATH)/bin/activate;\
		cd $(BUILD_TEST_SRC);\
		export PYTHONPATH=$(BUILD_TEST_SRC);\
		export RND_SEED=$(RND_SEED);\
		echo '***';\
		echo PYTHONPATH=$(BUILD_TEST_SRC);\
		echo RND_SEED=$(RND_SEED);\
		echo VPP_BUILD_DIR=$(VPP_BUILD_DIR);\
		echo VPP_BIN=$(VPP_BIN);\
		echo VPP_PLUGIN_PATH=$(VPP_PLUGIN_PATH);\
		echo VPP_TEST_PLUGIN_PATH=$(VPP_TEST_PLUGIN_PATH);\
		echo VPP_INSTALL_PATH=$(VPP_INSTALL_PATH);\
		echo EXTERN_TESTS=$(EXTERN_TESTS);\
		echo EXTERN_PLUGINS=$(EXTERN_PLUGINS);\
                echo EXTERN_COV_DIR=$(EXTERN_COV_DIR);\
		echo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH);\
		echo '***';\
		exec </dev/tty" | bash -i

.PHONY: reset
reset:
	@if [ $(FORCE_NO_WIPE) -eq "0" ] ; then rm -rf /tmp/vpp-unittest-*;  fi
	@rm -f /tmp/api_post_mortem.*
	@rm -rf $(FAILED_DIR)

.PHONY: wipe
wipe: reset
	@make -C ext clean
	@rm -rf $(VENV_PATH)
	@rm -rf $(patsubst %,%/__pycache__, $(VPP_TEST_DIRS))
	@rm -rf  $(BUILD_TEST_SRC)

$(TEST_DOC_BR): $(PIP_INSTALL_DONE)
	@mkdir -p $@
	@bash -c "source $(VENV_PATH)/bin/activate && make -C doc html"

.PHONY: doc
doc: $(BUILD_TEST_SRC) $(PIP_PATCH_DONE) $(TEST_DOC_BR)
	@echo
	@echo "Test Documentation URL: $(TEST_DOC_BR)/html/index.html"
	@echo "Run 'make test-wipe-doc test-doc' to rebuild the test docs"
	@echo

.PHONY: wipe-doc
wipe-doc:
	@rm -rf $(TEST_DOC_BR)

$(BUILD_COV_DIR):
	@mkdir -p $@

.PHONY: cov
cov: wipe-cov test-dep ext $(BUILD_COV_DIR)
	@lcov --zerocounters --directory $(VPP_BUILD_DIR)
	@test -z "$(EXTERN_COV_DIR)" || lcov --zerocounters --directory $(EXTERN_COV_DIR)
	$(call retest-func)
	@lcov --capture --directory $(VPP_BUILD_DIR) --output-file $(BUILD_COV_DIR)/coverage.info
	@test -z "$(EXTERN_COV_DIR)" || lcov --capture --directory $(EXTERN_COV_DIR) --output-file $(BUILD_COV_DIR)/extern-coverage.info
	@genhtml $(BUILD_COV_DIR)/coverage.info --output-directory $(BUILD_COV_DIR)/html
	@test -z "$(EXTERN_COV_DIR)" || genhtml $(BUILD_COV_DIR)/extern-coverage.info --output-directory $(BUILD_COV_DIR)/extern-html
	@echo
	@echo "Build finished. Code coverage report is in $(BUILD_COV_DIR)/html/index.html"
	@test -z "$(EXTERN_COV_DIR)" || echo "Code coverage report for out-of-tree objects is in $(BUILD_COV_DIR)/extern-html/index.html"

.PHONY: wipe-cov
wipe-cov: wipe
	@rm -rf $(BUILD_COV_DIR)

.PHONY: wipe-papi
wipe-papi:
	@rm -rf $(PAPI_INSTALL_DONE) $(PAPI_WIPE_DIST)

.PHONY: wipe-all
wipe-all: wipe wipe-papi wipe-doc wipe-cov
	@rm -rf $(TEST_BR)

.PHONY: start-gdb
start-gdb: sanity
	$(eval VPP_IN_GDB=1)
	$(eval FORCE_FOREGROUND=1)
	$(call retest-func)

.PHONY: checkstyle
checkstyle: $(BUILD_TEST_SRC) $(PIP_INSTALL_DONE)
	@bash -c "source $(VENV_PATH)/bin/activate &&\
		  $(PYTHON_INTERP) -m pip install pycodestyle"
	@bash -c "source $(VENV_PATH)/bin/activate &&\
		pycodestyle --show-source --ignore=W504,E126,E241,E226,E305,E704,E741,E722 -v $(BUILD_TEST_SRC)/*.py ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Test framework PEP8 compliance check FAILED \" &&\
	         echo \"*******************************************************************\" &&\
		 false)"
	@echo "*******************************************************************"
	@echo "* Test framework PEP8 compliance check passed"
	@echo "*******************************************************************"

.PHONY: help
help:
	@echo "Running tests:"
	@echo ""
	@echo " test                   - build and run (basic) functional tests"
	@echo " test-debug             - build and run (basic) functional tests (debug build)"
	@echo " test-all               - build and run functional and extended tests"
	@echo " test-all-debug         - build and run functional and extended tests (debug build)"
	@echo " retest                 - run functional tests"
	@echo " retest-debug           - run functional tests (debug build)"
	@echo " retest-all             - run functional and extended tests"
	@echo " retest-all-debug       - run functional and extended tests (debug build)"
	@echo " test-cov               - generate code coverage report for test framework"
	@echo " test-gcov                      - build and run functional tests (gcov build)"
	@echo " test-wipe              - wipe (temporary) files generated by unit tests"
	@echo " test-wipe-cov          - wipe code coverage report for test framework"
	@echo " test-wipe-doc          - wipe documentation for test framework"
	@echo " test-wipe-papi         - rebuild vpp_papi sources"
	@echo " test-wipe-all          - wipe (temporary) files generated by unit tests, docs, and coverage"
	@echo " test-shell             - enter shell with test environment"
	@echo " test-shell-debug       - enter shell with test environment (debug build)"
	@echo " test-checkstyle        - check PEP8 compliance for test framework"
	@echo " test-refresh-deps      - refresh the Python dependencies for the tests"
	@echo ""
	@echo "Arguments controlling test runs:"
	@echo " V=[0|1|2]              - set test verbosity level"
	@echo "                          0=ERROR, 1=INFO, 2=DEBUG"
	@echo " TEST_JOBS=[<n>|auto]   - use <n> parallel processes for test execution or automatic discovery of maximum acceptable processes (default: 1)"
	@echo " CACHE_OUTPUT=[0|1]     - cache VPP stdout/stderr and log as one block after test finishes (default: 1)"
	@echo " FAILFAST=[0|1]         - fail fast if 1, complete all tests if 0"
	@echo " TIMEOUT=<timeout>      - fail test suite if any single test takes longer than <timeout> (in seconds) to finish (default: 600)"
	@echo " RETRIES=<n>            - retry failed tests <n> times"
	@echo " DEBUG=<type>           - set VPP debugging kind"
	@echo "    DEBUG=core          - detect coredump and load it in gdb on crash"
	@echo "    DEBUG=gdb           - allow easy debugging by printing VPP PID"
	@echo "                          and waiting for user input before running"
	@echo "                          and tearing down a testcase"
	@echo "    DEBUG=gdbserver     - run gdb inside a gdb server, otherwise"
	@echo "                          same as above"
	@echo "    DEBUG=attach        - attach test case to already running vpp in gdb (see test-start-gdb)"
	@echo ""
	@echo " STEP=[yes|no]          - ease debugging by stepping through a testcase"
	@echo " SANITY=[yes|no]        - perform sanity import of vpp-api/sanity vpp run before running tests (default: yes)"
	@echo " EXTENDED_TESTS=[1|y]   - used by '[re]test-all' & '[re]test-all-debug' to run extended tests"
	@echo " TEST=<filter>          - filter the set of tests:"
	@echo "    by file-name        - only run tests from specified file, e.g. TEST=test_bfd selects all tests from test_bfd.py"
	@echo "    by file-suffix      - same as file-name, but 'test_' is omitted e.g. TEST=bfd selects all tests from test_bfd.py"
	@echo "    by wildcard         - wildcard filter is <file>.<class>.<test function>, each can be replaced by '*'"
	@echo "                          e.g. TEST='test_bfd.*.*' is equivalent to above example of filter by file-name"
	@echo "                               TEST='bfd.*.*' is equivalent to above example of filter by file-suffix"
	@echo "                               TEST='bfd.BFDAPITestCase.*' selects all tests from test_bfd.py which are part of BFDAPITestCase class"
	@echo "                               TEST='bfd.BFDAPITestCase.test_add_bfd' selects a single test named test_add_bfd from test_bfd.py/BFDAPITestCase"
	@echo "                               TEST='*.*.test_add_bfd' selects all test functions named test_add_bfd from all files/classes"
	@echo ""
	@echo " VARIANT=<variant>      - specify which march node variant to unit test"
	@echo "                          e.g. VARIANT=skx test the skx march variants"
	@echo "                          e.g. VARIANT=icl test the icl march variants"
	@echo ""
	@echo " COREDUMP_SIZE=<size>   - pass <size> as unix { coredump-size <size> } argument to vpp"
	@echo "                          e.g. COREDUMP_SIZE=4g"
	@echo "                               COREDUMP_SIZE=unlimited"
	@echo " COREDUMP_COMPRESS=1    - compress core files if not debugging them"
	@echo " EXTERN_TESTS=<path>    - path to out-of-tree test_<name>.py files containing test cases"
	@echo " EXTERN_PLUGINS=<path>  - path to out-of-tree plugins to be loaded by vpp under test"
	@echo " EXTERN_COV_DIR=<path>  - path to out-of-tree prefix, where source, object and .gcda files can be found for coverage report"
	@echo ""
	@echo " PROFILE=1              - enable profiling of test framework via cProfile module"
	@echo " PROFILE_SORT_BY=opt    - sort profiling report by opt - consult cProfile documentation for possible values (default: cumtime)"
	@echo " PROFILE_OUTPUT=file    - output profiling info to file - use absolute path (default: stdout)"
	@echo ""
	@echo " TEST_DEBUG=1           - turn on debugging of the test framework itself (expert)"
	@echo ""
	@echo " SKIP_AARCH64=1         - skip tests that are failing on the ARM platorm in FD.io CI"
	@echo ""
	@echo " RND_SEED=seed          - Seed RND with given seed"
	@echo ""
	@echo "Starting VPP in GDB for use with DEBUG=attach:"
	@echo ""
	@echo " test-start-gdb         - start VPP in gdb"
	@echo ""
	@echo "Arguments controlling VPP in GDB runs:"
	@echo " "
	@echo " VPP_IN_GDB_TMP_DIR     - specify directory to run VPP IN (default: /tmp/vpp-unittest-attach-gdb)"
	@echo " VPP_IN_GDB_NO_RMDIR=0  - don't remove existing tmp dir but fail instead"
	@echo " VPP_IN_GDB_CMDLINE=1   - add 'interactive' to VPP arguments to run with command line"
	@echo ""
	@echo "Creating test documentation"
	@echo " test-doc               - generate documentation for test framework"
	@echo " test-wipe-doc          - wipe documentation for test framework"
	@echo ""
	@echo "Creating test code coverage report"
	@echo " test-cov               - generate code coverage report for test framework"
	@echo " test-wipe-cov          - wipe code coverage report for test framework"
	@echo ""
	@echo "Verifying code-style"
	@echo " test-checkstyle        - check PEP8 compliance"
	@echo ""
