export HS_ROOT=$(CURDIR)

# sets WS_ROOT if called from test/hs-test
ifeq ($(WS_ROOT),)
export WS_ROOT=$(HS_ROOT)/../..
endif

ifeq ($(VERBOSE),)
VERBOSE=0
endif

ifneq ($(V),)
VERBOSE=$(V)
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

ifeq ($(VPP_CPUS),)
VPP_CPUS=1
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
NO_COLOR=false
endif

ifeq ($(TIMEOUT),)
TIMEOUT=5
endif

ifeq ($(GINKGO_TIMEOUT),)
GINKGO_TIMEOUT=3h
endif

CORE_PATTERN := $(shell cat /proc/sys/kernel/core_pattern)
CORE_VOLUME:=
DOCKER_TTY:=

ifeq ($(shell expr "$(CORE_PATTERN)" : '^/'), 1)
CORE_VOLUME := -v $(CORE_PATTERN):$(CORE_PATTERN)
endif

ifeq ($(shell tty -s && echo $$?), 0)
DOCKER_TTY := -it
endif

ifeq ($(HT),)
HT=false
endif

# it's better to omit these if not set
SEED_ARG := $(if $(SEED),--seed=$(SEED))
LABEL_ARG := $(if $(LABEL),--label="$(LABEL)")

FORCE_BUILD?=true

# privileged is needed for "ip netns" otherwise we are not able to create namespace
DOCKER_CAPABILITIES:=--privileged
DOCKER_DEVICES:=--device /dev/vhost-net:/dev/vhost-net --device /dev/net/tun:/dev/net/tun
DOCKER_VOLUMES:=-v $(WS_ROOT):$(WS_ROOT) -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/hs-test:/tmp/hs-test \
	-v /etc/localtime:/etc/localtime:ro $(CORE_VOLUME) -v $(HS_ROOT)/.go_cache/mod:/root/go/pkg/mod \
	-v $(HS_ROOT)/.go_cache/build:/root/.cache/go-build
DOCKER_PROXY:=-e HTTP_PROXY=$(HTTP_PROXY) -e HTTPS_PROXY=$(HTTPS_PROXY) -e NO_PROXY=$(NO_PROXY)
DOCKER_COMMON_ARGS:=$(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e GITHUB_REPO_URL=$(GITHUB_REPO_URL) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --parallel=$(PARALLEL) --repeat=$(REPEAT) --cpu0=$(CPU0) \
		--dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR) --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT) \
		$(LABEL_ARG) --host_ppid=$$PPID $(SEED_ARG) --hyperthread=$(HT)

.PHONY: help
help:
	@echo "Make targets:"
	@echo " test                     - run tests"
	@echo " test-debug               - run tests (vpp debug image)"
	@echo " test-leak                - run memory leak tests (vpp debug image)"
	@echo " build                    - build test infra"
	@echo " build-cov                - coverage build of VPP and Docker images"
	@echo " build-debug              - build test infra (vpp debug image)"
	@echo " checkstyle-go            - check style of .go source files"
	@echo " fixstyle-go              - format .go source files"
	@echo " cleanup-hst              - removes all docker containers and namespaces from last test run"
	@echo " list-tests               - list all tests"
	@echo " install-deps             - install software dependencies"
	@echo " clean-hst-registry       - delete images and repositories from local registry"
	@echo
	@echo "'make build' and 'make test' arguments:"
	@echo " UBUNTU_VERSION           - ubuntu version for docker image"
	@echo " FORCE_BUILD=[true|false] - force docker image building"
	@echo
	@echo "'make test' specific arguments:"
	@echo " PERSIST=[true|false]     - whether clean up topology and dockers after test"
	@echo " V or VERBOSE=[0|1|2]     - verbose output"
	@echo " UNCONFIGURE=[true|false] - unconfigure selected test"
	@echo " DEBUG=[true|false]       - attach VPP to GDB"
	@echo " TEST=[name1,name2...]    - specific test(s) to run"
	@echo " LABEL=[suite labels]     - filter by suite labels, case insensitive (https://onsi.github.io/ginkgo/#spec-labels)"
	@echo " SKIP=[name1,name2...]    - specific test(s) to skip"
	@echo " HT=[true|false]          - enable or disable hyperthread allocation (false by default)"
	@echo " CPUS=[n]                 - number of cpus to allocate to each non-VPP container (default = 1)"
	@echo " VPP_CPUS=[n]             - number of cpus to allocate to each VPP container (default = 1)"
	@echo " VPPSRC=[path-to-vpp-src] - path to vpp source files (for gdb)"
	@echo " PARALLEL=[n]             - number of test processes to spawn to run in parallel"
	@echo " REPEAT=[n]               - repeat tests up to N times or until a failure occurs"
	@echo " CPU0=[true|false]        - use cpu0"
	@echo " DRYRUN=[true|false]      - set up containers but don't run tests"
	@echo " NO_COLOR=[true|false]    - disables colorful Docker and Ginkgo output"
	@echo " TIMEOUT=[minutes]        - test timeout override (5 minutes by default)"
	@echo " GINKGO_TIMEOUT=[Ns/m/h]  - Ginkgo timeout override (3h by default)"
	@echo " SEED=[n]                 - set Ginkgo seed"

.PHONY: list-tests
list-tests:
	@go run github.com/onsi/ginkgo/v2/ginkgo --dry-run -v --no-color --seed=2 | head -n -1 | grep 'test.go' | \
		sed 's/^/* /; s/\(Suite\) /\1\//g'

.PHONY: .set-core-pattern
.set-core-pattern:
	-if [ -n "$(GITHUB_REPO_URL)" ]; then \
        echo /var/lib/vpp/vppcore.%e.%p | sudo tee /proc/sys/kernel/core_pattern; \
    fi

.PHONY: build-vpp-release
build-vpp-release: .set-core-pattern
	@$(MAKE) -C ../.. build-release

.PHONY: build-vpp-debug
build-vpp-debug: .set-core-pattern
	@$(MAKE) -C ../.. build

.PHONY: build-vpp-gcov
build-vpp-gcov: .set-core-pattern
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
	docker run $(DOCKER_COMMON_ARGS) --test=$(TEST); \
		./script/compress.sh $$?

.PHONY: test-debug
test-debug: FORCE_BUILD=false
test-debug: .deps.ok .build_debug.ok
	docker run $(DOCKER_COMMON_ARGS) --test=$(TEST) --debug_build=true; \
		./script/compress.sh $$?

.PHONY: wipe-lcov
wipe-lcov:
	@lcov --zerocounters --directory $(WS_ROOT)/build-root/build-vpp_gcov-native/vpp

.PHONY: test-cov
test-cov: FORCE_BUILD=false
test-cov: .deps.ok .build.cov.ok wipe-lcov
	-docker run $(DOCKER_COMMON_ARGS) --test=$(TEST-HS) --coverage=true; \
		./script/compress.sh $$?
	$(MAKE) -C ../.. test-cov-post-standalone HS_TEST=1

.PHONY: test-leak
test-leak: FORCE_BUILD=false
test-leak: .deps.ok .build_debug.ok
	docker run $(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e GITHUB_REPO_URL=$(GITHUB_REPO_URL) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --test=$(TEST) --debug_build=true --leak_check=true --vppsrc=$(VPPSRC) \
		--timeout=$(TIMEOUT) --ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT) \
		$(LABEL_ARG) --host_ppid=$$PPID $(SEED_ARG); \

.PHONY: build
build: .deps.ok build-vpp-release
	@rm -f .build.ok
	bash ./script/build_hst.sh release $(FORCE_BUILD)
	@touch .build.ok

.PHONY: build-cov
build-cov: .deps.ok build-vpp-gcov
	@rm -f .build.cov.ok
	bash ./script/build_hst.sh gcov $(FORCE_BUILD)
	@touch .build.cov.ok

.PHONY: build-debug
build-debug: .deps.ok build-vpp-debug
	@rm -f .build.ok
	bash ./script/build_hst.sh debug $(FORCE_BUILD)
	@touch .build.ok

.deps.ok:
	@$(MAKE) install-deps

.PHONY: install-deps
install-deps:
	@rm -f .deps.ok
	@if [ -d "/usr/local/go" ]; then \
        echo "Go is already installed. You may have to update it manually if version < 1.25.4"; \
		go version; \
    else \
        echo "Installing Go 1.25.4"; \
		wget -t 2 https://go.dev/dl/go1.25.4.linux-$(ARCH).tar.gz -O /tmp/go1.25.4.linux-$(ARCH).tar.gz && sudo tar -C /usr/local -xzf /tmp/go1.25.4.linux-$(ARCH).tar.gz; \
		sudo ln -s /usr/local/go/bin/go /usr/bin/go ; \
	fi
	@if ! command -v docker >/dev/null 2>&1; then \
        echo "Docker not found. Installing..."; \
        sudo -E apt-get update; \
        sudo -E apt-get install -y apt-transport-https ca-certificates curl software-properties-common bridge-utils gpg; \
        if [ ! -f /usr/share/keyrings/docker-archive-keyring.gpg ] ; then \
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; \
            echo "deb [arch=$(ARCH) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(UBUNTU_CODENAME) stable" \
                | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null ; \
            sudo apt-get update; \
        fi; \
        sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; \
    else \
        echo "Docker is already installed. You may have to update manually."; \
    fi
	@touch .deps.ok

.PHONY: checkstyle-go
checkstyle-go:
	@output=$$(find . -type f -name '*.go' -not -path './.go_cache/*' -exec go run golang.org/x/tools/cmd/goimports@v0.39.0 -d {} +); \
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
fixstyle-go:
	@echo "Modified files:"
	@find . -type f -name '*.go' -not -path './.go_cache/*' -exec go run golang.org/x/tools/cmd/goimports@v0.39.0 -w -l {} +
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
	@-sudo docker rm -f ginkgo
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

.PHONY: clear-hst-registry
clear-hst-registry:
	@bash ./script/clean_registry.sh
