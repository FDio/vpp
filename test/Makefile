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

export TEST_BR = $(TEST_DIR)
FAILED_DIR=/tmp/vpp-failed-unittests/
VPP_TEST_DIRS=$(shell ls -d $(TEST_DIR) $(EXTERN_TESTS))

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
PYTHON_OPTS="-m cProfile $(PROFILE_OUTPUT_OPTS) -s $(PROFILE_SORT_BY)"
FORCE_FOREGROUND=1
endif

VENV_BR_DIR=$(BR)/test
VENV_PATH=$(VENV_BR_DIR)/venv

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

ifeq ($(V),)
V=0
endif

PYTHON_VERSION=$(shell $(PYTHON_INTERP) -c 'import sys; print(sys.version_info.major)')
PIP_VERSION=22.0.4
# Keep in sync with requirements.txt
PIP_TOOLS_VERSION=6.6.0
PIP_SETUPTOOLS_VERSION=62.1.0
PYTHON_DEPENDS=requirements-$(PYTHON_VERSION).txt
SCAPY_SOURCE=$(shell find $(VENV_PATH)/lib/python* -name site-packages)
BUILD_COV_DIR=$(BR)/test-coverage

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
	@$(PYTHON_INTERP) -m venv $(VENV_PATH)
	# pip version pinning
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  python3 -m pip install pip===$(PIP_VERSION)"
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  python3 -m pip install pip-tools===$(PIP_TOOLS_VERSION)"
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  python3 -m pip install setuptools===$(PIP_SETUPTOOLS_VERSION)"
	@touch $@

$(PYTHON_DEPENDS): requirements.txt
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  CUSTOM_COMPILE_COMMAND='make test-refresh-deps (or update requirements.txt)' \
		  python3 -m piptools compile -q --generate-hashes requirements.txt --output-file $@"

$(PIP_INSTALL_DONE): $(PIP_TOOLS_INSTALL_DONE) $(PYTHON_DEPENDS)
	@bash -c "source $(VENV_PATH)/bin/activate && \
		  python3 -m piptools sync $(PYTHON_DEPENDS)"
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
	@bash -c "source $(VENV_PATH)/bin/activate && python3 -m pip install -e $(PAPI_PYTHON_SRC_DIR)"
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

.PHONY: sanity

ifndef TEST_JOBS
PARALLEL_ILLEGAL=0
TEST_JOBS=1
else ifeq ($(FORCE_FOREGROUND),0)
PARALLEL_ILLEGAL=0
else ifneq ($(findstring $(TEST_JOBS),1 auto),)
PARALLEL_ILLEGAL=0
else
PARALLEL_ILLEGAL=1
endif

ifneq ($(DEBUG),)
SANITY=no
endif

ifneq ($(findstring $(SANITY),0 n no),)
SANITY_IMPORT_VPP_PAPI_CMD=true
ARG0=
else
SANITY_IMPORT_VPP_PAPI_CMD=source $(VENV_PATH)/bin/activate && $(PYTHON_INTERP) sanity_import_vpp_papi.py
ARG0=--sanity
endif

ARG1=
ifneq ($(findstring $(FAILFAST),1 y yes),)
ARG1=--failfast
endif

ARG2=
ifneq ($(findstring $(EXTENDED_TESTS),1 y yes),)
ARG2=--extended
endif

ARG3=
ifneq ($(EXTERN_TESTS),)
ARG3=--test-src-dir $(EXTERN_TESTS)
endif

ARG4=
ifneq ($(findstring $(FORCE_FOREGROUND),1 y yes),)
ARG4=--force-foreground
endif

ARG5=
ifneq ($(findstring $(COREDUMP_COMPRESS),1 y yes),)
ARG5=--compress-core
endif

ARG6=
ifneq ($(findstring $(STEP),1 y yes),)
ARG6=--step
endif

ARG7=
ifneq ($(findstring $(TEST_GCOV),1 y yes),)
ARG7=--gcov
endif

ARG8=
ifneq ($(EXTERN_PLUGINS),)
ARG8=--extern-plugin-dir=$(EXTERN_PLUGINS)
endif

ARG9=
ifneq ($(DEBUG),)
ARG9=--debug=$(DEBUG)
endif

ARG10=
ifneq ($(COREDUMP_SIZE),)
ARG10=--coredump-size=$(COREDUMP_SIZE)
endif

ARG11=
ifneq ($(VARIANT),)
ARG11=--variant=$(VARIANT)
endif

ARG12=--cache-vpp-output
ifneq ($(findstring $(CACHE_OUTPUT),0 n no),)
ARG12=
endif

ARG13=
ifneq ($(MAX_VPP_CPUS),)
ARG13=--max-vpp-cpus=$(MAX_VPP_CPUS)
endif

ARG14=
ifneq ($(TIMEOUT),)
ARG14=--timeout=$(TIMEOUT)
endif

ARG15=
ifneq ($(findstring $(TEST_DEBUG),1 y yes),)
ARG15=--debug-framework
endif

ARG16=
ifneq ($(findstring $(API_FUZZ),1 y yes),)
ARG16=--api-fuzz=on
endif

ARG17=
ifneq ($(EXTERN_APIDIR),)
ARG17=--extern-apidir=$(EXTERN_APIDIR)
endif

EXTRA_ARGS=$(ARG0) $(ARG1) $(ARG2) $(ARG3) $(ARG4) $(ARG5) $(ARG6) $(ARG7) $(ARG8) $(ARG9) $(ARG10) $(ARG11) $(ARG12) $(ARG13) $(ARG14) $(ARG15) $(ARG16) $(ARG17)

RUN_TESTS_ARGS=--failed-dir=$(FAILED_DIR) --verbose=$(V) --jobs=$(TEST_JOBS) --filter=$(TEST) --retries=$(RETRIES) --venv-dir=$(VENV_PATH) --vpp-ws-dir=$(WS_ROOT) --vpp-tag=$(TAG) --rnd-seed=$(RND_SEED) --vpp-worker-count="$(VPP_WORKER_COUNT)" --keep-pcaps $(PLUGIN_PATH_ARGS) $(TEST_PLUGIN_PATH_ARGS) $(EXTRA_ARGS)
RUN_SCRIPT_ARGS=--python-opts=$(PYTHON_OPTS)

define retest-func
@scripts/run.sh $(RUN_SCRIPT_ARGS) $(RUN_TESTS_ARGS) || env FAILED_DIR=$(FAILED_DIR) COMPRESS_FAILED_TEST_LOGS=$(COMPRESS_FAILED_TEST_LOGS) scripts/compress_failed.sh
endef

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

$(FAILED_DIR): reset
	@mkdir -p $@

.PHONY: test-dep
test-dep: $(PAPI_INSTALL_DONE) $(FAILED_DIR)

.PHONY: test
test: test-dep sanity
	$(call retest-func)

.PHONY: retest
retest: verify-env sanity $(FAILED_DIR)
	$(call retest-func)

.PHONY: shell
shell: test-dep
	@echo "source $(VENV_PATH)/bin/activate;\
		export RND_SEED=$(RND_SEED);\
		echo '***';\
		echo PYTHONPATH=$(PYTHONPATH);\
		echo RND_SEED=$(RND_SEED);\
		echo VPP_BUILD_DIR=$(VPP_BUILD_DIR);\
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
	@rm -f /dev/shm/vpp-unittest-*
	@if [ $(FORCE_NO_WIPE) -eq "0" ] ; then rm -rf /tmp/vpp-unittest-*;  fi
	@rm -f /tmp/api_post_mortem.*
	@rm -rf $(FAILED_DIR)
	@rm -rf /tmp/vpp-vm-tests

.PHONY: wipe
wipe: reset
	@rm -rf $(VENV_BR_DIR)
	@rm -rf $(patsubst %,%/__pycache__, $(VPP_TEST_DIRS))

$(BUILD_COV_DIR):
	@mkdir -p $@

.PHONY: cov-prep
cov-prep: test-dep
	@lcov --zerocounters --directory $(VPP_BUILD_DIR)
	@test -z "$(EXTERN_COV_DIR)" || lcov --zerocounters --directory $(EXTERN_COV_DIR)

.PHONY: cov-post
cov-post: wipe-cov $(BUILD_COV_DIR)
	@lcov --capture \
		--directory $(VPP_BUILD_DIR) \
		--output-file $(BUILD_COV_DIR)/coverage.info
	@test -z "$(EXTERN_COV_DIR)" || \
		lcov --capture \
		--directory $(EXTERN_COV_DIR) \
		--output-file $(BUILD_COV_DIR)/extern-coverage.info
	@lcov --remove $(BUILD_COV_DIR)/coverage.info \
		"/usr/include/*" "*/build-root/*" "/opt/*" "/usr/lib/*" \
		-o $(BUILD_COV_DIR)/coverage-filtered.info
	@genhtml $(BUILD_COV_DIR)/coverage-filtered.info \
		--output-directory $(BUILD_COV_DIR)/html
	@test -z "$(EXTERN_COV_DIR)" || \
		genhtml $(BUILD_COV_DIR)/extern-coverage.info \
			--output-directory $(BUILD_COV_DIR)/extern-html
	@echo
	@echo "Build finished. Code coverage report is in $(BUILD_COV_DIR)/html/index.html"
	@test -z "$(EXTERN_COV_DIR)" || echo "Code coverage report for out-of-tree objects is in $(BUILD_COV_DIR)/extern-html/index.html"

.PHONY: cov
cov:
	make -C . cov-prep test cov-post

.PHONY: wipe-cov
wipe-cov: wipe
	@rm -rf $(BUILD_COV_DIR)

.PHONY: wipe-papi
wipe-papi:
	@rm -rf $(PAPI_INSTALL_DONE) $(PAPI_WIPE_DIST)

.PHONY: wipe-all
wipe-all: wipe wipe-papi wipe-cov
	@rm -rf $(TEST_BR)

.PHONY: start-gdb
start-gdb: sanity
	@bash -c "source $(VENV_PATH)/bin/activate && python3 -c 'from debug import start_vpp_in_gdb; start_vpp_in_gdb()' $(RUN_TESTS_ARGS)"

.PHONY: checkstyle-python-all
checkstyle-python-all: $(PIP_INSTALL_DONE)
	@bash -c "source $(VENV_PATH)/bin/activate &&\
		black -t py39 --check --diff $(WS_ROOT) ||\
		(echo \"*************************************************************************\" &&\
		echo \"* Test framework PEP8 compliance check FAILED (maybe: make fixstyle-python)\" &&\
		echo \"*************************************************************************\" &&\
		false)"
	@echo "*******************************************************************"
	@echo "* Test framework PEP8 compliance check passed"
	@echo "*******************************************************************"

.PHONY: checkstyle
checkstyle: checkstyle-python-all

.PHONY: fixstyle-python-all
fixstyle-python-all: $(PIP_INSTALL_DONE)
	@bash -c "source $(VENV_PATH)/bin/activate &&\
		black -t py39 $(WS_ROOT) ||\
		(echo \"*************************************************************************\" &&\
		echo \"* Test framework PEP8 compliance check FAILED (maybe: make fixstyle-python)\" &&\
		echo \"*************************************************************************\" &&\
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
	@echo " test-cov               - generate code coverage report for functional tests"
	@echo " test-cov-prep          - coverage phase #1 : prepare lcov"
	@echo " test-cov-build         - coverage phase #2 : build gcov image & run tests against it (use TEST=)"
	@echo " test-cov-post          - coverage phase #3 : generate lcov html report"
	@echo " test-all               - build and run functional and extended tests"
	@echo " test-all-debug         - build and run functional and extended tests (debug build)"
	@echo " test-all-cov           - generate code coverage report for functional and extended tests"
	@echo " retest                 - run functional tests"
	@echo " retest-debug           - run functional tests (debug build)"
	@echo " retest-all             - run functional and extended tests"
	@echo " retest-all-debug       - run functional and extended tests (debug build)"
	@echo " test-wipe              - wipe (temporary) files generated by unit tests"
	@echo " test-wipe-cov          - wipe code coverage report for test framework"
	@echo " test-wipe-papi         - rebuild vpp_papi sources"
	@echo " test-wipe-all          - wipe (temporary) files generated by unit tests, and coverage"
	@echo " test-shell             - enter shell with test environment"
	@echo " test-shell-debug       - enter shell with test environment (debug build)"
	@echo " test-refresh-deps      - refresh the Python dependencies for the tests"
	@echo ""
	@echo "Environment variables controlling test runs:"
	@echo ""
	@echo "   V=[0|1|2]"
	@echo "	      set test verbosity level: 0=ERROR, 1=INFO, 2=DEBUG"
	@echo ""
	@echo "   TEST_JOBS=[<n>|auto]"
	@echo "       use at most <n> parallel python processes for test"
	@echo "       execution, if auto, set to number of available cpus"
	@echo "       (default: 1)"
	@echo ""
	@echo "   MAX_VPP_CPUS=[<n>|auto]"
	@echo "       use at most <n> cpus for running vpp"
	@echo "       'auto' sets to number of available cpus"
	@echo "       (default: auto)"
	@echo ""
	@echo "   CACHE_OUTPUT=[0|n|no]"
	@echo "       disable caching VPP stdout/stderr and logging it"
	@echo "       as one block after test finishes"
	@echo "       (default: yes)"
	@echo ""
	@echo "   FAILFAST=[1|y|yes]"
	@echo "       if enabled, stop running tests on first failure"
	@echo "       otherwise finish running whole suite"
	@echo "       (default: no)"
	@echo ""
	@echo "   TIMEOUT=<timeout>"
	@echo "       fail test suite if any single test takes longer"
	@echo "       than <timeout> (in seconds) to finish"
	@echo "       (default: 600)"
	@echo ""
	@echo "   RETRIES=<n>"
	@echo "       retry failed tests <n> times"
	@echo "       (default: 0)"
	@echo ""
	@echo "   DEBUG=<type>"
	@echo "       configure VPP debugging:"
	@echo "       DEBUG=core"
	@echo "           detect coredump and load it in gdb on crash"
	@echo ""
	@echo "       DEBUG=gdb"
	@echo "           print VPP PID and wait for user input before"
	@echo "           running and tearing down a testcase, allowing"
	@echo "           easy gdb attach"
	@echo ""
	@echo "       DEBUG=gdbserver"
	@echo "           same as above, but run gdb inside a gdb server"
	@echo ""
	@echo "       DEBUG=attach"
	@echo "           attach to existing vpp in running in gdb"
	@echo "           (see test-start-vpp-in-gdb)"
	@echo "       (default: none)"
	@echo ""
	@echo "   STEP=[1|y|yes]"
	@echo "       enable stepping through a testcase"
	@echo "       (default: no)"
	@echo ""
	@echo "   SANITY=[0|n|no]"
	@echo "       disable sanity import of vpp-api/vpp sanity"
	@echo "       run before running tests"
	@echo "       (default: yes)"
	@echo ""
	@echo "   EXTENDED_TESTS=[1|y|yes]"
	@echo "       run extended tests"
	@echo "       (default: no)"
	@echo ""
	@echo "   TEST=<filter>,[<filter>],..."
	@echo "       only run tests matching one or more comma-delimited"
	@echo "       filter expressions"
	@echo ""
	@echo "       simple filter:"
	@echo "           file name or file suffix select all tests from a file"
	@echo "           examples:"
	@echo "               TEST=test_bfd"
	@echo "               TEST=bfd"
	@echo "                    equivalent expressions selecting all"
	@echo "                    tests defined in test_bfd.py"
	@echo ""
	@echo "       wildcard filter:"
	@echo "           advanced filtering based on test file, test class"
	@echo "           and test function"
	@echo "           each filter expression is in the form of"
	@echo "               <file>.<class>.<test function>"
	@echo "           each of the tokens can be left empty or replaced"
	@echo "           with '*' to select all objects available"
	@echo "           examples:"
	@echo "               TEST=test_bfd.*.*"
	@echo "               TEST=test_bfd.."
	@echo "               TEST=bfd.*.*"
	@echo "               TEST=bfd.."
	@echo "                    select all tests defined in test_bfd.py"
	@echo "               TEST=bfd.BFDAPITestCase.*"
	@echo "               TEST=bfd.BFDAPITestCase."
	@echo "                    select all tests from test_bfd.py"
	@echo "                    which are part of BFDAPITestCase class"
	@echo "               TEST=bfd.BFDAPITestCase.test_add_bfd"
	@echo "                    select a single test named test_add_bfd"
	@echo "                    from test_bfd.py/BFDAPITestCase"
	@echo "               TEST=..test_add_bfd"
	@echo "               TEST=*.*.test_add_bfd"
	@echo "                    select all test functions named test_add_bfd"
	@echo "                    from all files/classes"
	@echo "               TEST=bfd,ip4,..test_icmp_error"
	@echo "                    select all test functions in test_bfd.py,"
	@echo "                    test_ip4.py and all test functions named"
	@echo "                    'test_icmp_error' in all files"
	@echo "       (default: '')"
	@echo ""
	@echo "   VARIANT=<variant>"
	@echo "       specify which march node variant to unit test"
	@echo "           e.g. VARIANT=skx test the skx march variants"
	@echo "           e.g. VARIANT=icl test the icl march variants"
	@echo "       (default: '')"
	@echo ""
	@echo "   COREDUMP_SIZE=<size>"
	@echo "       pass <size> as unix { coredump-size <size> } argument"
	@echo "       to vpp, e.g. COREDUMP_SIZE=4g or COREDUMP_SIZE=unlimited"
	@echo "       (default: '')"
	@echo ""
	@echo "   COREDUMP_COMPRESS=[1|y|yes]"
	@echo "       if no debug option is set, compress any core files"
	@echo "       (default: no)"
	@echo ""
	@echo "   EXTERN_TESTS=<path>"
	@echo "       include out-of-tree test_*.py files under <path>"
	@echo "       (default: '')"
	@echo ""
	@echo "   EXTERN_PLUGINS=<path>"
	@echo "       load out-of-tree vpp plugins in <path>"
	@echo "       (default: '')"
	@echo ""
	@echo "   EXTERN_COV_DIR=<path>"
	@echo "       path to out-of-tree prefix, where source, object"
	@echo "       and .gcda files can be found for coverage report"
	@echo "       (default: '')"
	@echo ""
	@echo "   PROFILE=[1|y|yes]"
	@echo "       enable profiling of test framework via cProfile module"
	@echo "       (default: no)"
	@echo ""
	@echo "   PROFILE_SORT_BY=opt"
	@echo "       sort profiling report by opt - see cProfile documentation"
	@echo "       for possible values"
	@echo "       (default: cumtime)"
	@echo ""
	@echo "   PROFILE_OUTPUT=file"
	@echo "       output profiling info to file - use absolute path"
	@echo "       (default: stdout)"
	@echo ""
	@echo "   TEST_DEBUG=[1|y|yes]"
	@echo "       enable debugging of the test framework itself (expert)"
	@echo "       (default: no)"
	@echo ""
	@echo "   TEST_GCOV=[1|y|yes]"
	@echo "       enable tests specifically designed soley for code coverage"
	@echo "       (default: no)"
	@echo ""
	@echo "   API_FUZZ=[1|y|yes]"
	@echo "       enable VPP api fuzz testing"
	@echo "       (default: no)"
	@echo ""
	@echo "   RND_SEED=<seed>"
	@echo "       random seed used by test framework"
	@echo "       (default: time.time())"
	@echo ""
	@echo "Starting VPP in GDB for use with DEBUG=attach:"
	@echo ""
	@echo " test-start-vpp-in-gdb       - start VPP in gdb (release)"
	@echo " test-start-vpp-debug-in-gdb - start VPP in gdb (debug)"
	@echo ""
