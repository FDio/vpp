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
export PYTHONPYCACHEPREFIX=$(VENV_PATH)/__pycache__

ifeq ($(TEST_DEBUG),1)
VENV_RUN_DIR:=$(VENV_PATH)/run-debug
else
VENV_RUN_DIR:=$(VENV_PATH)/run
endif

ifeq ($(V),)
V=0
endif

# ========================= VENV =========================
export UV_LINK_MODE=copy
VENV_PATH := $(BR)/.venv
UV_DIR := $(BR)/.local
UV_CACHE := $(BR)/.uv-cache
UV := $(UV_DIR)/bin/uv
INSTALL_MARKER := $(VENV_PATH)/.installed

# Target to check if 'uv' is installed
check-uv-installed:
	@command -v $(UV) >/dev/null 2>&1 || { echo "uv is not installed."; exit 1; }

$(VENV_PATH): check-uv-installed
	@echo "Creating virtual environment..."
	UV_CACHE_DIR=$(UV_CACHE) $(UV) venv $(VENV_PATH) --python=3.13

$(INSTALL_MARKER): $(VENV_PATH) pyproject.toml
	@echo "Installing package with dependencies..."
	@$(UV) pip install --upgrade pip --python=$(VENV_PATH)/bin/python
	@$(VENV_PATH)/bin/pip install git+https://github.com/vpp-dev/scapy.git@v2.4.5+vpp1
	@$(UV) pip install --python=$(VENV_PATH)/bin/python -e ".[dev]"
	@touch $(INSTALL_MARKER)

.PHONY: venv
venv: $(UV) $(VENV_PATH)

.PHONY: install-dependencies
install-dependencies: $(INSTALL_MARKER)

.PHONY: sync-dependencies
sync-dependencies: venv
	@echo "Syncing dependencies..."
	@$(UV) pip sync pyproject.toml

# ========================= VENV =========================
BUILD_COV_DIR=$(BR)/test-coverage

.PHONY: refresh-deps
refresh-deps: clean-deps

.PHONY: clean-deps
clean-deps:
	@rm -rf $(VENV_DIR)
	@rm -rf *.egg-info
	@rm -rf dist/
	@rm -rf build/
	@rm -rf __pycache__/

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
SANITY_IMPORT_VPP_PAPI_CMD=source $(VENV_PATH)/bin/activate && python sanity_import_vpp_papi.py
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

ARG18=
ifneq ($(DECODE_PCAPS),)
ARG18=--decode-pcaps=$(DECODE_PCAPS)
endif

ifneq ($(findstring $(API_PRELOAD),1 y yes),)
ARG19=--api-preload
else
ARG19=
endif

EXC_PLUGINS_ARG=
ifneq ($(VPP_EXCLUDED_PLUGINS),)
# convert the comma-separated list into N invocations of the argument to exclude a plugin
EXC_PLUGINS_ARG=$(shell echo "${VPP_EXCLUDED_PLUGINS}" | sed 's/\([^,]*\)/--excluded-plugin=\1/g; s/,/ /g')
endif



EXTRA_ARGS=$(ARG0) $(ARG1) $(ARG2) $(ARG3) $(ARG4) $(ARG5) $(ARG6) $(ARG7) $(ARG8) $(ARG9) $(ARG10) $(ARG11) $(ARG12) $(ARG13) $(ARG14) $(ARG15) $(ARG16) $(ARG17) $(ARG18) $(ARG19)

RUN_TESTS_ARGS=--failed-dir=$(FAILED_DIR) --verbose=$(V) --jobs=$(TEST_JOBS) --filter=$(TEST) --retries=$(RETRIES) --venv-dir=$(VENV_PATH) --vpp-ws-dir=$(WS_ROOT) --vpp-tag=$(TAG) --rnd-seed=$(RND_SEED) --vpp-worker-count="$(VPP_WORKER_COUNT)" --keep-pcaps $(PLUGIN_PATH_ARGS) $(EXC_PLUGINS_ARG) $(TEST_PLUGIN_PATH_ARGS) $(EXTRA_ARGS)
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
test-dep: install-dependencies $(FAILED_DIR)

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

COV_REM_NOT_CODE="/usr/include/*" "*/build-root/*" "/opt/*" "/usr/lib/*" \
				 "*_test.*" "*test_*" "*vat*"  "*/vnet/unix/gdb_funcs.c" \
				 "*pg.c"

COV_REM_DRIVERS="*rdma*" "*/plugins/af_packet/*" "*/plugins/af_xdp/*" \
				"*/plugins/avf/*" "*/plugins/dma_intel/*" "*/vlib/pci/*" \
				"*/vnet/devices/*" "*/vlib/dma/*" "*/plugins/vmxnet3/*" \
				"*/vnet/devices/virtio/*" "*/plugins/perfmon/arm*" \
				"*/plugins/perfmon/intel/*" "*/vlib/vmbus/*" \
				"*/vnet/dev/*" "*/plugins/dev_ena/*" "*/plugins/dev_iavf/*"

COV_REM_UNUSED_FEAT="*/plugins/ioam/analyse/*" "*/plugins/ioam/lib-*/*" \
				    "*/plugins/ioam/export-common/*" "*/vnet/srp/*" \
					"*/lawful-intercept/*" "*/lisp/*" "*/vnet/osi/*" \
					"*/plugins/nsh/*"

COV_REM_TODO_NO_TEST="*/vpp-api/client/*" "*/plugins/prom/*" \
					 "*/plugins/tlspicotls/*" "*/plugins/tlsmbedtls/*" \
					 "*/vppinfra/perfmon/*" "*/plugins/ila/*" \
					 "*/vlib/linux/*" "*/vnet/util/radix.c" "*/vapi/vapi.hpp" \
					 "*/vpp/api/types.c" "*/vpp/api/json_format.c" \
					 "*/plugins/ioam/*/*.h" "*/linux/netns.c" "*/vnet/flow/*" \
					 "*/vppinfra/random.c" "*/vppinfra/ring.h" \
				 	 "*/vppinfra/bihash_vec8_8.h" "*/vppinfra/maplog.c" \
					 "*/vppinfra/format_table.c" "*/vppinfra/timing_wheel.c" \
					 "*/vppinfra/macros.c" "*/vppinfra/valloc.c" \
					 "*/vppinfra/jsonformat.c" "*/vppinfra/vector/array_mask.h" \
					 "*/vppinfra/vector/toeplitz.c" "*/plugins/vrrp/vrrp_packet.h" \
					 "*/vnet/srv6/sr.h" "*/vlibapi/api_format.c" \
					 "*/vlibapi/node_serialize.c" "*/plugins/quic/error.c" \
					 "*/vnet/ipfix-export/flow_report_classify.h" \
					 "*/vnet/ip/ip6_ll_types.c" "*/vnet/ip/ip_psh_cksum.h" \
					 "*/vnet/ip/ip6_hop_by_hop.h" "*/vnet/ip/ip_format_fns.h" \
					 "*/vnet/dpo/classify_dpo.h" "*/vnet/dpo/l3_proxy_dpo.h" \
					 "*/vnet/ipsec/esp_format.c" "*/vnet/ethernet/sfp.c" \
					 "*/vnet/ethernet/ethernet_format_fns.h" \
					 "*/plugins/ikev2/ikev2_format.c" "*/vnet/bier/bier_types.c"

.PHONY: cov-post
cov-post: wipe-cov $(BUILD_COV_DIR)
	@lcov --ignore-errors unused,empty,mismatch,gcov --capture \
		--directory $(VPP_BUILD_DIR) \
		--output-file $(BUILD_COV_DIR)/coverage$(HS_TEST).info
	@test -z "$(EXTERN_COV_DIR)" || \
		lcov --ignore-errors unused,empty,mismatch,gcov --capture \
		--directory $(EXTERN_COV_DIR) \
		--output-file $(BUILD_COV_DIR)/extern-coverage$(HS_TEST).info
	@lcov --ignore-errors unused,empty,mismatch,gcov --remove $(BUILD_COV_DIR)/coverage$(HS_TEST).info \
		$(COV_REM_NOT_CODE) \
		$(COV_REM_DRIVERS)  \
		$(COV_REM_TODO_NO_TEST) \
		$(COV_REM_UNUSED_FEAT) \
		-o $(BUILD_COV_DIR)/coverage-filtered$(HS_TEST).info
	@genhtml $(BUILD_COV_DIR)/coverage-filtered$(HS_TEST).info \
		--output-directory $(BUILD_COV_DIR)/html
	@test -z "$(EXTERN_COV_DIR)" || \
		genhtml $(BUILD_COV_DIR)/extern-coverage$(HS_TEST).info \
			--output-directory $(BUILD_COV_DIR)/extern-html
	@echo
	@echo "Build finished. Code coverage report is in $(BUILD_COV_DIR)/html/index.html"
	@test -z "$(EXTERN_COV_DIR)" || echo "Code coverage report for out-of-tree objects is in $(BUILD_COV_DIR)/extern-html/index.html"
	@mkdir -p $(BR)/test-coverage-merged
	@cp -f $(BUILD_COV_DIR)/coverage-filtered$(HS_TEST).info $(BR)/test-coverage-merged

.PHONY: cov
cov:
	$(MAKE) -C . cov-prep test cov-post

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
checkstyle-python-all: install-dependencies
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
fixstyle-python-all: install-dependencies
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
	@echo " test-cov-both          - generate and merge code coverage report for Python and Golang tests"
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
	@echo "   DECODE_PCAPS=[all|failed|none]"
	@echo "       decode pcap files using tshark - all, only failed or none"
	@echo "       (default: failed)"
	@echo ""
	@echo "Starting VPP in GDB for use with DEBUG=attach:"
	@echo ""
	@echo " test-start-vpp-in-gdb       - start VPP in gdb (release)"
	@echo " test-start-vpp-debug-in-gdb - start VPP in gdb (debug)"
	@echo ""

.PHONY: check-updates
check-updates: $(VENV_DIR)
	@echo "Checking for package updates..."
	@$(UV) pip list --outdated --format=columns

.PHONY: update-deps
update-deps:
	@echo "Updating dependencies in pyproject.toml..."
	@$(UV) pip list --outdated | \
		awk 'NR>2 {print $$1 "==" $$3}' > deps.tmp
	@if [ -s deps.tmp ]; then \
		echo "Found updates for:"; \
		cat deps.tmp; \
		echo "Updating dependencies..."; \
		while IFS== read pkg ver; do \
			sed -i.bak "s/\"$$pkg==.*\"/\"$$pkg==$$ver\"/" pyproject.toml; \
		done < deps.tmp; \
		rm -f deps.tmp *.bak; \
		echo "Dependencies updated. Please review changes in pyproject.toml"; \
	else \
		echo "All dependencies are up to date"; \
		rm -f deps.tmp; \
	fi

.PHONY: update-all
update-all: update-deps install
	@echo "Dependencies updated and installed"

.PHONY: list-deps
list-deps: $(VENV_PATH)
	@echo "Current package versions:"
	@$(UV) pip list

.PHONY: audit
audit: $(VENV_PATH)
	@echo "Auditing dependencies..."
	@$(UV) pip install pip-audit
	@$(VENV_PATH)/bin/pip-audit

.PHONY: find-imports
find-imports: $(VENV_PATH)
	@echo "Finding Python imports..."
	@$(UV) pip install pipreqs
	@$(VENV_PATH)/bin/pipreqs . --force --mode compat --ignore tests/,docs/

