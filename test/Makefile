.PHONY: verify-python-path

VPP_TEST_FAILED_DIR=/tmp/vpp-failed-unittests/

verify-python-path:
ifndef VPP_PYTHON_PREFIX
	$(error VPP_PYTHON_PREFIX is not set)
endif

.PHONY: verify-no-running-vpp

ifdef VPP_ZOMBIE_NOCHECK
VPP_PIDS=
else
VPP_PIDS=$(shell pgrep -d, -x vpp_main)
endif

ifeq ($(DEBUG),gdb)
FORCE_FOREGROUND=1
else ifeq ($(DEBUG),gdbserver)
FORCE_FOREGROUND=1
else
FORCE_FOREGROUND=0
endif

verify-no-running-vpp:
	@if [ "$(VPP_PIDS)" != "" ]; then \
		echo; \
		echo "*** Existing vpp processes detected (PID(s): $(VPP_PIDS)). Running tests under these conditions is not supported. ***"; \
		echo; \
		ps -fp $(VPP_PIDS);\
		echo; \
		false; \
	fi

UNITTEST_EXTRA_OPTS=
UNITTEST_FAILFAST_OPTS=

ifeq ($(FAILFAST),1)
UNITTEST_EXTRA_OPTS=-f
endif

ifneq ($(EXTERN_TESTS),)
UNITTEST_EXTRA_OPTS=$(UNITTEST_FAILFAST_OPTS) -d $(EXTERN_TESTS)
endif

PYTHON_VENV_PATH=$(VPP_PYTHON_PREFIX)/virtualenv
PYTHON_DEPENDS=faulthandler six scapy==2.3.3 pexpect subprocess32 cffi git+https://github.com/klement/py-lispnetworking@setup
SCAPY_SOURCE=$(shell find $(PYTHON_VENV_PATH) -name site-packages)
BUILD_COV_DIR=$(BR)/test-cov

GET_PIP_SCRIPT=$(VPP_PYTHON_PREFIX)/get-pip.py
PIP_INSTALL_DONE=$(VPP_PYTHON_PREFIX)/pip-install.done
PIP_PATCH_DONE=$(VPP_PYTHON_PREFIX)/pip-patch.done
PAPI_INSTALL_DONE=$(VPP_PYTHON_PREFIX)/papi-install.done

PAPI_INSTALL_FLAGS=$(PIP_INSTALL_DONE) $(PIP_PATCH_DONE) $(PAPI_INSTALL_DONE)

ifeq ($(PYTHON),)
PYTHON_INTERP=python2.7
else
PYTHON_INTERP=$(PYTHON)
endif

$(GET_PIP_SCRIPT):
	@mkdir -p $(VPP_PYTHON_PREFIX)
	@bash -c "cd $(VPP_PYTHON_PREFIX) && curl -O https://bootstrap.pypa.io/get-pip.py"

$(PIP_INSTALL_DONE): $(GET_PIP_SCRIPT)
	@virtualenv $(PYTHON_VENV_PATH) -p $(PYTHON_INTERP)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python $(GET_PIP_SCRIPT)"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install $(PYTHON_DEPENDS)"
	@touch $@

$(PIP_PATCH_DONE): $(PIP_INSTALL_DONE)
	@echo --- patching ---
	@sleep 1 # Ensure python recompiles patched *.py files -> *.pyc
	for f in $(CURDIR)/patches/scapy-2.3.3/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(SCAPY_SOURCE) < $$f ; \
	done
	@touch $@

$(PAPI_INSTALL_DONE): $(PIP_PATCH_DONE)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && cd $(WS_ROOT)/src/vpp-api/python && python setup.py install"
	@touch $@

define retest-func
	@env VPP_TEST_FAILED_DIR=$(VPP_TEST_FAILED_DIR) scripts/setsid_wrapper.sh $(FORCE_FOREGROUND) $(PYTHON_VENV_PATH)/bin/activate python run_tests.py -d $(TEST_DIR) $(UNITTEST_EXTRA_OPTS)
	@env VPP_TEST_FAILED_DIR=$(VPP_TEST_FAILED_DIR) scripts/compress_failed.sh
endef

.PHONY: sanity

sanity: verify-no-running-vpp
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python sanity_import_vpp_papi.py ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Sanity check failed, cannot import vpp_papi\" &&\
		 echo \"* to debug: \" &&\
		 echo \"* 1. enter test shell:   make test-shell\" &&\
		 echo \"* 2. execute debugger:   gdb python -ex 'run sanity_import_vpp_papi.py'\" &&\
	         echo \"*******************************************************************\" &&\
		 false)"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python sanity_run_vpp.py ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Sanity check failed, cannot run vpp\" &&\
	         echo \"*******************************************************************\" &&\
		 false)"

test: verify-python-path $(PAPI_INSTALL_DONE) sanity reset 
	$(call retest-func)

retest: verify-python-path sanity reset
	$(call retest-func)

shell: verify-python-path $(PAPI_INSTALL_DONE)
	@echo "source $(PYTHON_VENV_PATH)/bin/activate;\
		echo '***';\
		echo VPP_TEST_BUILD_DIR=$(VPP_TEST_BUILD_DIR);\
		echo VPP_TEST_BIN=$(VPP_TEST_BIN);\
		echo VPP_TEST_PLUGIN_PATH=$(VPP_TEST_PLUGIN_PATH);\
		echo VPP_TEST_INSTALL_PATH=$(VPP_TEST_INSTALL_PATH);\
		echo EXTERN_TESTS=$(EXTERN_TESTS);\
		echo EXTERN_PLUGINS=$(EXTERN_PLUGINS);\
                echo EXTERN_COV_DIR=$(EXTERN_COV_DIR);\
		echo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH);\
		echo '***';\
		exec </dev/tty" | bash -i

.PHONY: wipe doc

reset:
	@rm -f /dev/shm/vpp-unittest-*
	@rm -rf /tmp/vpp-unittest-*
	@rm -rf $(VPP_TEST_FAILED_DIR)
	@mkdir $(VPP_TEST_FAILED_DIR)

wipe: reset
	@rm -rf $(PYTHON_VENV_PATH)
	@rm -f $(PAPI_INSTALL_FLAGS)

doc: verify-python-path $(PIP_PATCH_DONE)
	@virtualenv $(PYTHON_VENV_PATH) -p $(PYTHON_INTERP)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install sphinx sphinx-rtd-theme"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && make -C doc WS_ROOT=$(WS_ROOT) BR=$(BR) NO_VPP_PAPI=1 html"

.PHONY: wipe-doc

wipe-doc:
	@make -C doc wipe BR=$(BR)

cov: wipe-cov reset verify-python-path $(PAPI_INSTALL_DONE)
	@lcov --zerocounters --directory $(VPP_TEST_BUILD_DIR)
	@test -z "$(EXTERN_COV_DIR)" || lcov --zerocounters --directory $(EXTERN_COV_DIR)
	$(call retest-func)
	@mkdir $(BUILD_COV_DIR)
	@lcov --capture --directory $(VPP_TEST_BUILD_DIR) --output-file $(BUILD_COV_DIR)/coverage.info
	@test -z "$(EXTERN_COV_DIR)" || lcov --capture --directory $(EXTERN_COV_DIR) --output-file $(BUILD_COV_DIR)/extern-coverage.info
	@genhtml $(BUILD_COV_DIR)/coverage.info --output-directory $(BUILD_COV_DIR)/html
	@test -z "$(EXTERN_COV_DIR)" || genhtml $(BUILD_COV_DIR)/extern-coverage.info --output-directory $(BUILD_COV_DIR)/extern-html
	@echo
	@echo "Build finished. Code coverage report is in $(BUILD_COV_DIR)/html/index.html"
	@test -z "$(EXTERN_COV_DIR)" || echo "Code coverage report for out-of-tree objects is in $(BUILD_COV_DIR)/extern-html/index.html"

.PHONY: wipe-cov

wipe-cov: wipe
	@rm -rf $(BUILD_COV_DIR)

.PHONY: checkstyle
checkstyle: verify-python-path
	@virtualenv $(PYTHON_VENV_PATH) -p $(PYTHON_INTERP)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install pep8"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate &&\
		pep8 --show-source -v $(WS_ROOT)/test/*.py ||\
		(echo \"*******************************************************************\" &&\
		 echo \"* Test framework PEP8 compliance check FAILED \" &&\
	         echo \"*******************************************************************\" &&\
		 false)"
	@echo "*******************************************************************"
	@echo "* Test framework PEP8 compliance check passed"
	@echo "*******************************************************************"

help:
	@echo "Running tests:"
	@echo ""
	@echo " test                - build and run (basic) functional tests"
	@echo " test-debug          - build and run (basic) functional tests (debug build)"
	@echo " test-all            - build and run (all) functional tests"
	@echo " test-all-debug      - build and run (all) functional tests (debug build)"
	@echo " retest              - run functional tests"
	@echo " retest-debug        - run functional tests (debug build)"
	@echo " test-wipe           - wipe (temporary) files generated by unit tests"
	@echo " test-shell          - enter shell with test environment"
	@echo " test-shell-debug    - enter shell with test environment (debug build)"
	@echo ""
	@echo "Arguments controlling test runs:"
	@echo " V=[0|1|2]            - set test verbosity level"
	@echo " FAILFAST=[0|1]       - fail fast if 1, complete all tests if 0"
	@echo " TIMEOUT=<timeout>    - fail test suite if any single test takes longer than <timeout> to finish"
	@echo " SINGLE_THREAD=[0|1]  - run tests against single-thread VPP (default: 1)"
	@echo " MULTI_WORKER=[0|1]   - run tests against multi-worker VPP (default: 1)"
	@echo " DEBUG=<type>         - set VPP debugging kind"
	@echo "    DEBUG=core        - detect coredump and load it in gdb on crash"
	@echo "    DEBUG=gdb         - allow easy debugging by printing VPP PID "
	@echo "                        and waiting for user input before running "
	@echo "                        and tearing down a testcase"
	@echo "    DEBUG=gdbserver   - run gdb inside a gdb server, otherwise "
	@echo "                        same as above"
	@echo " STEP=[yes|no]        - ease debugging by stepping through a testcase "
	@echo " TEST=<filter>        - filter the set of tests:"
	@echo "    by file-name      - only run tests from specified file, e.g. TEST=test_bfd selects all tests from test_bfd.py"
	@echo "    by file-suffix    - same as file-name, but 'test_' is omitted e.g. TEST=bfd selects all tests from test_bfd.py"
	@echo "    by wildcard       - wildcard filter is <file>.<class>.<test function>, each can be replaced by '*'"
	@echo "                        e.g. TEST='test_bfd.*.*' is equivalent to above example of filter by file-name"
	@echo "                             TEST='bfd.*.*' is equivalent to above example of filter by file-suffix"
	@echo "                             TEST='bfd.BFDAPITestCase.*' selects all tests from test_bfd.py which are part of BFDAPITestCase class"
	@echo "                             TEST='bfd.BFDAPITestCase.test_add_bfd' selects a single test named test_add_bfd from test_bfd.py/BFDAPITestCase"
	@echo "                             TEST='*.*.test_add_bfd' selects all test functions named test_add_bfd from all files/classes"
	@echo ""
	@echo " VPP_ZOMBIE_NOCHECK=1 - skip checking for vpp (zombie) processes (CAUTION)"
	@echo " COREDUMP_SIZE=<size> - pass <size> as unix { coredump-size <size> } argument to vpp"
	@echo "                        e.g. COREDUMP_SIZE=4g"
	@echo "                             COREDUMP_SIZE=unlimited"
	@echo " EXTERN_TESTS=<path>  - path to out-of-tree test_<name>.py files containing test cases"
	@echo " EXTERN_PLUGINS=<path>- path to out-of-tree plugins to be loaded by vpp under test"
	@echo " EXTERN_COV_DIR=<path>- path to out-of-tree prefix, where source, object and .gcda files can be found for coverage report"
	@echo ""
	@echo "Creating test documentation"
	@echo " test-doc            - generate documentation for test framework"
	@echo " test-wipe-doc       - wipe documentation for test framework"
	@echo ""
	@echo "Creating test code coverage report"
	@echo " test-cov            - generate code coverage report for test framework"
	@echo " test-wipe-cov       - wipe code coverage report for test framework"
	@echo ""
	@echo "Verifying code-style"
	@echo " test-checkstyle     - check PEP8 compliance"
	@echo ""
