export HS_ROOT=$(CURDIR)

# sets WS_ROOT if called from extras/hs-test
ifeq ($(WS_ROOT),)
export WS_ROOT=$(HS_ROOT)/../..
endif

ifeq ($(VERBOSE),)
VERBOSE=false
endif

ifeq ($(PERSIST),)
PERSIST=false
endif

ifeq ($(UNCONFIGURE),)
UNCONFIGURE=false
endif

ifeq ($(TEST),)
TEST=all
endif

ifeq ($(TEST-HS),)
TEST-HS=all
endif

ifeq ($(DEBUG),)
DEBUG=false
endif

ifeq ($(CPUS),)
CPUS=1
endif

ifeq ($(PARALLEL),)
PARALLEL=1
endif

ifeq ($(REPEAT),)
REPEAT=0
endif

ifeq ($(CPU0),)
CPU0=false
endif

ifeq ($(VPPSRC),)
VPPSRC=$(shell pwd)/../..
endif

ifeq ($(UBUNTU_CODENAME),)
UBUNTU_CODENAME=$(shell grep '^UBUNTU_CODENAME=' /etc/os-release | cut -f2- -d=)
endif

ifeq ($(ARCH),)
ARCH=$(shell dpkg --print-architecture)
endif

ifeq ($(NO_COLOR),)
VERBOSE=false
endif

FORCE_BUILD?=true

.PHONY: help
help:
	@echo "Make targets:"
	@echo " test                     - run tests"
	@echo " test-debug               - run tests (vpp debug image)"
	@echo " test-leak                - run memory leak tests (vpp debug image)"
	@echo " test-perf                - run performance tests (requires a running cluster)"
	@echo " build                    - build test infra"
	@echo " build-cov                - coverage build of VPP and Docker images"
	@echo " build-debug              - build test infra (vpp debug image)"
	@echo " build-go                 - just build golang files"
	@echo " setup-cluster            - setup KinD cluster for performance testing"
	@echo " checkstyle-go            - check style of .go source files"
	@echo " fixstyle-go              - format .go source files"
	@echo " cleanup-hst              - stops and removes all docker contaiers and namespaces"
	@echo " list-tests               - list all tests"
	@echo
	@echo "'make build' and 'make test' arguments:"
	@echo " UBUNTU_VERSION           - ubuntu version for docker image"
	@echo " FORCE_BUILD=[true|false] - force docker image building"
	@echo
	@echo "'make test' specific arguments:"
	@echo " PERSIST=[true|false]     - whether clean up topology and dockers after test"
	@echo " VERBOSE=[true|false]     - verbose output"
	@echo " UNCONFIGURE=[true|false] - unconfigure selected test"
	@echo " DEBUG=[true|false]       - attach VPP to GDB"
	@echo " TEST=[name1,name2...]    - specific test(s) to run"
	@echo " SKIP=[name1,name2...]    - specific test(s) to skip"
	@echo " CPUS=[n-cpus]            - number of cpus to allocate to VPP and containers"
	@echo " VPPSRC=[path-to-vpp-src] - path to vpp source files (for gdb)"
	@echo " PARALLEL=[n-cpus]        - number of test processes to spawn to run in parallel"
	@echo " REPEAT=[n]               - repeat tests up to N times or until a failure occurs"
	@echo " CPU0=[true|false]        - use cpu0"
	@echo " DRYRUN=[true|false]      - set up containers but don't run tests"
	@echo " NO_COLOR=[true|false]    - disables colorful Docker and Ginkgo output"

.PHONY: list-tests
list-tests:
	@go run github.com/onsi/ginkgo/v2/ginkgo --dry-run -v --no-color --seed=2 | head -n -1 | grep 'test.go' | \
		sed 's/^/* /; s/\(Suite\) /\1\//g'

.PHONY: build-vpp-release
build-vpp-release:
	@$(MAKE) -C ../.. build-release

.PHONY: build-vpp-debug
build-vpp-debug:
	@$(MAKE) -C ../.. build

.PHONY: build-vpp-gcov
build-vpp-gcov:
	@$(MAKE) -C ../.. build-gcov

.build.ok: build
	@touch .build.ok

.build.cov.ok: build-cov
	@touch .build.ok

.build_debug.ok: build-debug
	@touch .build.ok

.PHONY: test
test: FORCE_BUILD=false
test: .deps.ok .build.ok
	@bash ./hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --parallel=$(PARALLEL) --repeat=$(REPEAT) --cpu0=$(CPU0) \
		--dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR); \
		./script/compress.sh $$?

.PHONY: test-debug
test-debug: FORCE_BUILD=false
test-debug: .deps.ok .build_debug.ok
	@bash ./hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --parallel=$(PARALLEL) --repeat=$(REPEAT) --debug_build=true \
		--cpu0=$(CPU0) --dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR); \
		./script/compress.sh $$?

.PHONY: wipe-lcov
wipe-lcov:
	@lcov --zerocounters --directory $(WS_ROOT)/build-root/build-vpp_gcov-native/vpp

.PHONY: test-cov
test-cov: FORCE_BUILD=false
test-cov: .deps.ok .build.cov.ok wipe-lcov
	@bash ./hs_test.sh --coverage=true --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST-HS) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --cpu0=$(CPU0) --dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR); \
		./script/compress.sh $$?
	$(MAKE) -C ../.. test-cov-post-standalone HS_TEST=1

.PHONY: test-leak
test-leak: .deps.ok .build_debug.ok
	@bash ./hs_test.sh --test=$(TEST) --debug_build=true --leak_check=true --vppsrc=$(VPPSRC)

.PHONY: test-perf
test-perf: FORCE_BUILD=false
test-perf: .deps.ok .build.ok
	@bash ./hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--test=$(TEST) --vppsrc=$(VPPSRC) --repeat=$(REPEAT) \
		--skip=$(SKIP) --no_color=$(NO_COLOR) --perf=true; \
		./script/compress.sh $$?

.PHONY: setup-cluster
setup-cluster:
	@bash ./kubernetes/setupCluster.sh

.PHONY: build-go
build-go:
	go build ./tools/http_server

.PHONY: build
build: .deps.ok build-vpp-release build-go
	@rm -f .build.ok
	bash ./script/build_hst.sh release $(FORCE_BUILD)
	@touch .build.ok

.PHONY: build-cov
build-cov: .deps.ok build-vpp-gcov build-go
	@rm -f .build.cov.ok
	bash ./script/build_hst.sh gcov $(FORCE_BUILD)
	@touch .build.cov.ok

.PHONY: build-debug
build-debug: .deps.ok build-vpp-debug build-go
	@rm -f .build.ok
	bash ./script/build_hst.sh debug $(FORCE_BUILD)
	@touch .build.ok

.deps.ok:
	@$(MAKE) install-deps

.PHONY: install-deps
install-deps:
	@rm -f .deps.ok
	@sudo -E apt-get update
	@sudo -E apt-get install -y apt-transport-https ca-certificates curl software-properties-common \
		bridge-utils gpg
	@if [ ! -f /usr/share/keyrings/docker-archive-keyring.gpg ] ; then \
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; \
		echo "deb [arch=$(ARCH) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(UBUNTU_CODENAME) stable" \
			| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null ; \
		apt-get update; \
	fi
	@sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
	@touch .deps.ok

.goimports.ok:
	@rm -f .goimports.ok
	go install golang.org/x/tools/cmd/goimports@v0.25.0
	@touch .goimports.ok

.PHONY: checkstyle-go
checkstyle-go: .goimports.ok
	$(eval GOPATH := $(shell go env GOPATH))
	@output=$$($(GOPATH)/bin/goimports -d $${WS_ROOT}); \
	status=$$?; \
	if [ $$status -ne 0 ]; then \
		exit $$status; \
    elif [ -z "$$output" ]; then \
        echo "******************************************************************************"; \
        echo "* HST Golang Checkstyle OK."; \
        echo "******************************************************************************"; \
    else \
        echo "$$output"; \
        echo "******************************************************************************"; \
        echo "* HST Golang Checkstyle FAILED. Use 'make fixstyle-go' or fix errors manually."; \
        echo "******************************************************************************"; \
        exit 1; \
    fi

.PHONY: fixstyle-go
fixstyle-go: .goimports.ok
	$(eval GOPATH := $(shell go env GOPATH))
	@echo "Modified files:"
	@$(GOPATH)/bin/goimports -w -l $(WS_ROOT)
	@go mod tidy
	@echo "*******************************************************************"
	@echo "Fixstyle done."
	@echo "*******************************************************************"

.PHONY: cleanup-hst
cleanup-hst:
	@if [ ! -f ".last_hst_ppid" ]; then \
		echo "'.last_hst_ppid' file does not exist."; \
		exit 1; \
	fi
	@echo "****************************"
	@echo "Removing docker containers:"
	@# "-" ignores errors
	@-sudo docker rm $$(sudo docker stop $$(sudo docker ps -a -q --filter "name=$$(cat .last_hst_ppid)") -t 0)
	@echo "****************************"
	@echo "Removing IP address files:"
	@find . -type f -regextype egrep -regex '.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' -exec sudo rm -v {} \;
	@find . -type f -name "fd00:0*" -exec sudo rm -v {} \;
	@echo "****************************"
	@echo "Removing network namespaces:"
	@for ns in $$(ip netns list | grep $$(cat .last_hst_ppid) | awk '{print $$1}'); do \
		echo $$ns; \
    	sudo ip netns delete $$ns; \
	done
	@echo "****************************"
	@echo "Done."
	@echo "****************************"
