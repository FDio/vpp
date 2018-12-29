.PHONY: verify-test-dir

FAILED_DIR=/tmp/vpp-failed-unittests/

verify-test-dir:
ifndef TEST_DIR
	$(error TEST_DIR is not set)
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
else ifeq ($(DEBUG),core)
FORCE_FOREGROUND=1
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

VENV_PATH=$(TEST_DIR)/run/venv

ifeq ($(TEST_DEBUG),1)
TEST_RUN_DIR:=$(VENV_PATH)/run-debug
PYTHON_EXTRA_DEPENDS=objgraph pympler
else
TEST_RUN_DIR:=$(VENV_PATH)/run
PYTHON_EXTRA_DEPENDS=
endif

PYTHON_DEPENDS=$(PYTHON_EXTRA_DEPENDS) -r requirements.txt
SCAPY_SOURCE=$(shell find $(VENV_PATH) -name site-packages)
BUILD_COV_DIR=$(TEST_DIR)/coverage

GET_PIP_SCRIPT=$(TEST_RUN_DIR)/get-pip.py
PIP_INSTALL_DONE=$(TEST_RUN_DIR)/pip-install.done
PIP_PATCH_DONE=$(TEST_RUN_DIR)/pip-patch.done
PAPI_INSTALL_DONE=$(TEST_RUN_DIR)/papi-install.done

PAPI_INSTALL_FLAGS=$(PIP_INSTALL_DONE) $(PIP_PATCH_DONE) $(PAPI_INSTALL_DONE)

ifeq ($(PYTHON),)
PYTHON_INTERP=python2.7
else
PYTHON_INTERP=$(PYTHON)
endif

$(GET_PIP_SCRIPT):
	@mkdir -p $(TEST_RUN_DIR)
	@bash -c "cd $(TEST_RUN_DIR) && curl -O https://bootstrap.pypa.io/get-pip.py"

$(PIP_INSTALL_DONE): $(GET_PIP_SCRIPT)
	@virtualenv $(VENV_PATH) -p $(PYTHON_INTERP)
	@bash -c "source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) $(GET_PIP_SCRIPT)"
	@bash -c "source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) -m pip install $(PYTHON_DEPENDS)"
	@touch $@

$(PIP_PATCH_DONE): $(PIP_INSTALL_DONE)
	@echo --- patching ---
	@sleep 1 # Ensure python recompiles patched *.py files -> *.pyc
	for f in $(CURDIR)/patches/scapy-2.4/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(SCAPY_SOURCE) < $$f ; \
	done
	@touch $@

$(PAPI_INSTALL_DONE): $(PIP_PATCH_DONE)
	@bash -c "source $(VENV_PATH)/bin/activate && cd $(WS_ROOT)/src/vpp-api/python && $(PYTHON_INTERP) setup.py install"
	@touch $@

define retest-func
@env FORCE_FOREGROUND=$(FORCE_FOREGROUND) FAILED_DIR=$(FAILED_DIR) VENV_PATH=$(VENV_PATH) scripts/setsid_wrapper.sh $(FORCE_FOREGROUND) $(VENV_PATH)/bin/activate $(PYTHON_INTERP) $(PYTHON_PROFILE_OPTS) run_tests.py -d $(TEST_DIR) $(UNITTEST_EXTRA_OPTS) || env FAILED_DIR=$(FAILED_DIR) COMPRESS_FAILED_TEST_LOGS=$(COMPRESS_FAILED_TEST_LOGS) scripts/compress_failed.sh
endef

.PHONY: sanity

ifeq ($(SANITY),no)
SANITY_IMPORT_VPP_PAPI_CMD=true
SANITY_RUN_VPP_CMD=true
else
SANITY_IMPORT_VPP_PAPI_CMD=source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) sanity_import_vpp_papi.py
SANITY_RUN_VPP_CMD=source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) sanity_run_vpp.py
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

sanity: verify-no-running-vpp
	@sys_req/dev_shm_size.sh
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

.PHONY: ext
ext:
	@if [ "$(EXTENDED_TESTS)" = "yes" ]; then\
		make -C ext;\
	fi

test-dep: verify-test-dir $(PAPI_INSTALL_DONE)

test: verify-test-dir $(PAPI_INSTALL_DONE) ext sanity reset
	$(call retest-func)

retest: verify-test-dir sanity reset
	$(call retest-func)

shell: verify-test-dir $(PAPI_INSTALL_DONE)
	@echo "source $(VENV_PATH)/bin/activate;\
		echo '***';\
		echo _BUILD_DIR=$(VPP_BUILD_DIR);\
		echo _BIN=$(VPP_BIN);\
		echo _PLUGIN_PATH=$(VPP_PLUGIN_PATH);\
		echo _INSTALL_PATH=$(VPP_INSTALL_PATH);\
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
	@rm -rf $(FAILED_DIR)
	@mkdir $(FAILED_DIR)

wipe: reset
	@make -C ext clean
	@rm -rf $(VENV_PATH)
	@rm -f $(PAPI_INSTALL_FLAGS)

doc: verify-test-dir $(PIP_PATCH_DONE)
	@virtualenv $(VENV_PATH) -p $(PYTHON_INTERP)
	@bash -c "source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) -m pip install sphinx sphinx-rtd-theme"
	@bash -c "source $(VENV_PATH)/bin/activate && make -C doc WS_ROOT=$(WS_ROOT) BR=$(BR) html"

.PHONY: wipe-doc

wipe-doc:
	@make -C doc wipe BR=$(BR)

cov: wipe-cov reset ext verify-test-dir $(PAPI_INSTALL_DONE)
	@lcov --zerocounters --directory $(_BUILD_DIR)
	@test -z "$(EXTERN_COV_DIR)" || lcov --zerocounters --directory $(EXTERN_COV_DIR)
	$(call retest-func)
	@mkdir $(BUILD_COV_DIR)
	@lcov --capture --directory $(_BUILD_DIR) --output-file $(BUILD_COV_DIR)/coverage.info
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
checkstyle: verify-test-dir
	@virtualenv $(VENV_PATH) -p python3
	@bash -c "source $(VENV_PATH)/bin/activate && python3 -m pip install pycodestyle"
	@bash -c "source $(VENV_PATH)/bin/activate &&\
		pycodestyle --show-source --ignore=W504,E126,E241,E226,E305,E704,E741,E722 --exclude=$(WS_ROOT)/test/_*.py -v $(WS_ROOT)/test/*.py ||\
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
	@echo " TEST_JOBS=[<n>|auto] - use <n> parallel processes for test execution or automatic discovery of maximum acceptable processes (default: 1)"
	@echo " CACHE_OUTPUT=[0|1]   - cache VPP stdout/stderr and log as one block after test finishes (default: 1)"
	@echo " FAILFAST=[0|1]       - fail fast if 1, complete all tests if 0"
	@echo " TIMEOUT=<timeout>    - fail test suite if any single test takes longer than <timeout> (in seconds) to finish (default: 600)"
	@echo " RETRIES=<n>          - retry failed tests <n> times"
	@echo " DEBUG=<type>         - set VPP debugging kind"
	@echo "    DEBUG=core        - detect coredump and load it in gdb on crash"
	@echo "    DEBUG=gdb         - allow easy debugging by printing VPP PID"
	@echo "                        and waiting for user input before running"
	@echo "                        and tearing down a testcase"
	@echo "    DEBUG=gdbserver   - run gdb inside a gdb server, otherwise"
	@echo "                        same as above"
	@echo " STEP=[yes|no]        - ease debugging by stepping through a testcase"
	@echo " SANITY=[yes|no]      - perform sanity import of vpp-api/sanity vpp run before running tests (default: yes)"
	@echo " EXTENDED_TESTS=[1|y] - run extended tests"
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
	@echo " PROFILE=1            - enable profiling of test framework via cProfile module"
	@echo " PROFILE_SORT_BY=opt  - sort profiling report by opt - consult cProfile documentation for possible values (default: cumtime)"
	@echo " PROFILE_OUTPUT=file  - output profiling info to file - use absolute path (default: stdout)"
	@echo ""
	@echo " TEST_DEBUG=1         - turn on debugging of the test framework itself (expert)"
	@echo ""
	@echo " SKIP_AARCH64=1       - skip tests that are failing on the ARM platorm in FD.io CI"
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
