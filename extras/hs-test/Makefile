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
VERBOSE=false
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

FORCE_BUILD?=true
BUILD_AS:=$(strip $(shell echo $${SUDO_USER:-$${USER:-root}}))

# privileged is needed for "ip netns" otherwise we are not able to create namespace
DOCKER_CAPABILITIES:=--privileged
DOCKER_DEVICES:=--device /dev/vhost-net:/dev/vhost-net --device /dev/net/tun:/dev/net/tun
DOCKER_VOLUMES:=-v $(WS_ROOT):$(WS_ROOT) -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/hs-test:/tmp/hs-test \
	-v /etc/localtime:/etc/localtime:ro $(CORE_VOLUME) -v $(HS_ROOT)/.go_cache/mod:/root/go/pkg/mod \
	-v $(HS_ROOT)/.go_cache/build:/root/.cache/go-build
DOCKER_PROXY:=-e HTTP_PROXY=$(HTTP_PROXY) -e HTTPS_PROXY=$(HTTPS_PROXY) -e NO_PROXY=$(NO_PROXY)

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
	@echo " cluster-help             - print info about KinD cluster setup (perf testing)"
	@echo " master-cluster           - setup KinD cluster for performance testing (master CalicoVPP + VPP)"
	@echo " rebuild-master-cluster   - rebuild VPP and update related pods without shutting down the cluster"
	@echo " release-cluster          - setup KinD cluster for performance testing (latest CalicoVPP release)"
	@echo " checkstyle-go            - check style of .go source files"
	@echo " fixstyle-go              - format .go source files"
	@echo " cleanup-hst              - removes all docker containers and namespaces from last test run"
	@echo " cleanup-perf             - removes all kubernetes pods and namespaces from last test run"
	@echo " list-tests               - list all tests"
	@echo " install-deps             - install software dependencies"
	@echo " install-kind-deps        - install software dependencies for cluster"
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
	@echo
	@echo "'make setup-cluster' arguments:"
	@echo " BASE=[master|latest]     - build master CalicoVPP with master VPP or use latest release of CalicoVPP (default = latest)"

.PHONY: list-tests
list-tests:
	@go run github.com/onsi/ginkgo/v2/ginkgo --dry-run -v --no-color --seed=2 | head -n -1 | grep 'test.go' | \
		sed 's/^/* /; s/\(Suite\) /\1\//g'

.PHONY: build-msg
build-msg:
	@echo "Building VPP as '$(BUILD_AS)'"
	@echo "****************************************************************"
	@echo "If you wish to build VPP as root, use 'make ... BUILD_AS=root'"
	@echo "or"
	@echo "'[sudo] SUDO_USER=root make ...'"
	@echo "****************************************************************"

.PHONY: build-vpp-release
build-vpp-release: build-msg
	@sudo -u $(BUILD_AS) $(MAKE) -C ../.. build-release

.PHONY: build-vpp-debug
build-vpp-debug: build-msg
	@sudo -u $(BUILD_AS) $(MAKE) -C ../.. build

.PHONY: build-vpp-gcov
build-vpp-gcov: build-msg
	@sudo -u $(BUILD_AS) $(MAKE) -C ../.. build-gcov

.build.ok: build
	@touch .build.ok

.build.cov.ok: build-cov
	@touch .build.ok

.build_debug.ok: build-debug
	@touch .build.ok

.PHONY: test
test: FORCE_BUILD=false
test: .deps.ok .build.ok
	docker run $(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e BUILD_NUMBER=$(BUILD_NUMBER) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --parallel=$(PARALLEL) --repeat=$(REPEAT) --cpu0=$(CPU0) \
		--dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR) --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT); \
		./script/compress.sh $$?

.PHONY: test-debug
test-debug: FORCE_BUILD=false
test-debug: .deps.ok .build_debug.ok
	docker run $(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e BUILD_NUMBER=$(BUILD_NUMBER) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --parallel=$(PARALLEL) --repeat=$(REPEAT) --debug_build=true \
		--cpu0=$(CPU0) --dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR) --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT); \
		./script/compress.sh $$?

.PHONY: wipe-lcov
wipe-lcov:
	@lcov --zerocounters --directory $(WS_ROOT)/build-root/build-vpp_gcov-native/vpp

.PHONY: test-cov
test-cov: FORCE_BUILD=false
test-cov: .deps.ok .build.cov.ok wipe-lcov
	-docker run $(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e BUILD_NUMBER=$(BUILD_NUMBER) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --coverage=true --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--unconfigure=$(UNCONFIGURE) --debug=$(DEBUG) --test=$(TEST-HS) --cpus=$(CPUS) \
		--vppsrc=$(VPPSRC) --cpu0=$(CPU0) --dryrun=$(DRYRUN) --skip=$(SKIP) --no_color=$(NO_COLOR) \
		--timeout=$(TIMEOUT) --ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT); \
		./script/compress.sh $$?
	$(MAKE) -C ../.. test-cov-post-standalone HS_TEST=1

.PHONY: test-leak
test-leak: FORCE_BUILD=false
test-leak: .deps.ok .build_debug.ok
	docker run $(DOCKER_TTY) --rm $(DOCKER_CAPABILITIES) $(DOCKER_DEVICES) $(DOCKER_PROXY)\
		-e BUILD_NUMBER=$(BUILD_NUMBER) $(DOCKER_VOLUMES) --name ginkgo hs-test/ginkgo \
		.$(HS_ROOT)/hs_test.sh --test=$(TEST) --debug_build=true --leak_check=true --vppsrc=$(VPPSRC) --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT) --vpp_cpus=$(VPP_CPUS) --hs_root=$(HS_ROOT);

.PHONY: test-perf
test-perf: FORCE_BUILD=false
test-perf: .deps.ok .build.ok
	@bash ./hs_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--test=$(TEST) --vppsrc=$(VPPSRC) --repeat=$(REPEAT) \
		--skip=$(SKIP) --no_color=$(NO_COLOR) --perf=true --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT); \
		./script/compress.sh $$?

.PHONY: cluster-help
cluster-help:
	@bash ./kubernetes/setup-cluster.sh help

.PHONY: release-cluster
release-cluster: .kind_deps.ok
	@bash ./kubernetes/setup-cluster.sh release-cluster

.PHONY: master-cluster
master-cluster: .kind_deps.ok
	@bash ./kubernetes/setup-cluster.sh master-cluster

.PHONY: rebuild-master-cluster
rebuild-master-cluster: .kind_deps.ok
	@bash ./kubernetes/setup-cluster.sh rebuild-master-cluster

# this is executed in a container by hs-test.sh
.PHONY: build-go
build-go:
	go build --buildvcs=false ./tools/http_server

.PHONY: build
build: .deps.ok build-vpp-release
	@rm -f .build.ok
	bash ./script/build_hst.sh release $(FORCE_BUILD) $(BUILD_AS)
	@touch .build.ok

.PHONY: build-cov
build-cov: .deps.ok build-vpp-gcov
	@rm -f .build.cov.ok
	bash ./script/build_hst.sh gcov $(FORCE_BUILD) $(BUILD_AS)
	@touch .build.cov.ok

.PHONY: build-debug
build-debug: .deps.ok build-vpp-debug
	@rm -f .build.ok
	bash ./script/build_hst.sh debug $(FORCE_BUILD) $(BUILD_AS)
	@touch .build.ok

.deps.ok:
	@$(MAKE) install-deps

.kind_deps.ok:
	@$(MAKE) install-kind-deps

.PHONY: install-kind-deps
install-kind-deps: .deps.ok
	-@if ! command -v kind >/dev/null 2>&1; then \
		echo "Installing KinD"; \
		go install sigs.k8s.io/kind@v0.29.0; \
		echo "Creating symlink from '$(HOME)/go/bin/kind' to '/usr/bin/kind'"; \
		sudo ln -s $(HOME)/go/bin/kind /usr/bin/kind; \
	else \
		echo "KinD is already installed. Skipping."; \
	fi
	@if ! command -v kubectl >/dev/null 2>&1; then \
        echo "kubectl not found. Installing kubectl..."; \
        sudo -E apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gnupg; \
        curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg; \
        sudo -E chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg; \
        echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list; \
        sudo -E chmod 644 /etc/apt/sources.list.d/kubernetes.list; \
        sudo apt-get update && sudo apt-get install -y kubectl; \
    else \
        echo "kubectl is already installed. Skipping."; \
	fi
	@touch .kind_deps.ok

.PHONY: install-deps
install-deps:
	@rm -f .deps.ok
	@if [ -d "/usr/local/go" ]; then \
        echo "Go is already installed. You may have to update it manually if version < 1.23.10"; \
		go version; \
    else \
        echo "Installing Go 1.23"; \
		wget https://go.dev/dl/go1.23.10.linux-$(ARCH).tar.gz -O /tmp/go1.23.10.linux-$(ARCH).tar.gz && sudo tar -C /usr/local -xzf /tmp/go1.23.10.linux-$(ARCH).tar.gz; \
		sudo ln -s /usr/local/go/bin/go /usr/bin/go ; \
	fi
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

.PHONY: checkstyle-go
checkstyle-go:
	@output=$$(find . -type f -name '*.go' -not -path './.go_cache/*' -exec go run golang.org/x/tools/cmd/goimports@v0.35.0 -d {} +); \
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
	@find . -type f -name '*.go' -not -path './.go_cache/*' -exec go run golang.org/x/tools/cmd/goimports@v0.35.0 -w -l {} +
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

.PHONY: cleanup-perf
cleanup-perf:
	@if [ ! -f ".last_hst_ppid" ]; then \
		echo "'.last_hst_ppid' file does not exist."; \
		exit 1; \
	fi
	@echo "****************************"
	@echo "Removing kubernetes pods:"
	@kubectl delete pods --all --grace-period=0 -n namespace$$(cat .last_hst_ppid)
	@echo "****************************"
	@echo "Removing kubernetes namespace:"
	@kubectl delete namespace namespace$$(cat .last_hst_ppid)
	@echo "****************************"
	@echo "Done."
	@echo "****************************"
