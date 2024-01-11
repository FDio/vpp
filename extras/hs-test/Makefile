
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

ifeq ($(DEBUG),)
DEBUG=false
endif

ifeq ($(CPUS),)
CPUS=1
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

list_tests = @(grep -r ') Test' *_test.go | cut -d '*' -f2 | cut -d '(' -f1 | \
		tr -d ' ' | tr ')' '/' | sed 's/Suite//')

.PHONY: help
help:
	@echo "Make targets:"
	@echo " test                 - run tests"
	@echo " build                - build test infra"
	@echo " build-cov			 - coverage build of VPP and Docker images"
	@echo " build-debug          - build test infra (vpp debug image)"
	@echo " build-go             - just build golang files"
	@echo " fixstyle             - format .go source files"
	@echo " list-tests           - list all tests"
	@echo
	@echo "make build arguments:"
	@echo " UBUNTU_VERSION           - ubuntu version for docker image"
	@echo " HST_EXTENDED_TESTS	 - build extended tests"
	@echo
	@echo "make test arguments:"
	@echo " PERSIST=[true|false]     - whether clean up topology and dockers after test"
	@echo " VERBOSE=[true|false]     - verbose output"
	@echo " UNCONFIGURE=[true|false] - unconfigure selected test"
	@echo " DEBUG=[true|false]       - attach VPP to GDB"
	@echo " TEST=[test-name]         - specific test to run"
	@echo " CPUS=[n-cpus]            - number of cpus to run with vpp"
	@echo " VPPSRC=[path-to-vpp-src] - path to vpp source files (for gdb)"
	@echo
	@echo "List of all tests:"
	$(call list_tests)

.PHONY: list-tests
list-tests:
	$(call list_tests)

build-vpp-release:
	@make -C ../.. build-release

build-vpp-debug:
	@make -C ../.. build

build-vpp-gcov:
	@make -C ../.. build-vpp-gcov

.PHONY: test
test: .deps.ok .build.vpp
	@bash ./test --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC)

.PHONY: test-cov
test-cov: .deps.ok .build.vpp
	@bash ./test --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST-HS) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC)
	@make -C ../.. test-cov-post HS_TEST=1

build-go:
	go build ./tools/http_server

build: .deps.ok build-vpp-release build-go
	@rm -f .build.vpp
	bash ./script/build_hst.sh release
	@touch .build.vpp

build-gcov: .deps.ok build-vpp-gcov build-go
	@rm -f .build.vpp
	bash ./script/build_hst.sh gcov
	@touch .build.vpp

build-debug: .deps.ok build-vpp-debug build-go
	@rm -f .build.vpp
	bash ./script/build_hst.sh debug
	@touch .build.vpp

.deps.ok:
	@sudo make install-deps

.PHONY: install-deps
install-deps:
	@rm -f .deps.ok
	@apt-get update \
		&& apt-get install -y apt-transport-https ca-certificates curl software-properties-common \
		&& apt-get install -y golang apache2-utils wrk bridge-utils
	@if [ ! -f /usr/share/keyrings/docker-archive-keyring.gpg ] ; then \
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; \
		echo "deb [arch=$(ARCH) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(UBUNTU_CODENAME) stable" \
			| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null ; \
		apt-get update; \
	fi
	@apt-get install -y docker-ce
	@touch .deps.ok

.PHONY: fixstyle
fixstyle:
	@gofmt -w .
	@go mod tidy
