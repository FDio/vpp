ifeq ($(VERBOSE),)
VERBOSE=false
endif

ifeq ($(PERSIST),)
PERSIST=false
endif

ifeq ($(TEST),)
TEST=all
endif

ifeq ($(REPEAT),)
REPEAT=0
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
TIMEOUT=30
endif

ifeq ($(GINKGO_TIMEOUT),)
GINKGO_TIMEOUT=3h
endif

FORCE_BUILD?=true

.PHONY: help
help:
	@echo "Make targets:"
	@echo " test                     - run kube-test (requires a running cluster)"
	@echo " build                    - build test infra"
	@echo " build-debug              - build test infra (vpp debug image)"
	@echo " cluster-help             - print info about KinD cluster setup (perf testing)"
	@echo " master-cluster           - setup KinD cluster for performance testing (master CalicoVPP + VPP)"
	@echo " rebuild-master-cluster   - rebuild VPP and update related pods without shutting down the cluster"
	@echo " release-cluster          - setup KinD cluster for performance testing (latest CalicoVPP release)"
	@echo " checkstyle-go            - check style of .go source files"
	@echo " fixstyle-go              - format .go source files"
	@echo " cleanup-kube             - removes all kubernetes pods and namespaces from last test run"
	@echo " list-tests               - list all tests"
	@echo " install-deps             - install software dependencies"
	@echo " install-kube-deps        - install software dependencies for kind cluster"
	@echo
	@echo "'make build' and 'make test' arguments:"
	@echo " UBUNTU_VERSION                       - ubuntu version for docker image"
	@echo " FORCE_BUILD=[true|false]             - force docker image building"
	@echo " NO_REGISTRY=[true|false]             - attempts to build docker images without using a local registry"
	@echo "'make test' args:"
	@echo " SKIP_CONFIG=[true|false]             - skips cluster config update. Useful if running the same test/suite back to back"
	@echo " when testing on a bare metal cluster:"
	@echo " CALICOVPP_INTERFACE=[interface name] - uplink interface name for CalicoVPP"
	@echo " CALICOVPP_VERSION=[version]          - CalicoVPP VPP and Agent versions"
	@echo " KUBE_WRK1 and KUBE_WRK2=[name]       - cluster worker names"
	@echo
	@echo "'make test' specific arguments:"
	@echo " PERSIST=[true|false]     - whether clean up topology and dockers after test"
	@echo " VERBOSE=[true|false]     - verbose output"
	@echo " TEST=[name1,name2...]    - specific test(s) to run"
	@echo " SKIP=[name1,name2...]    - specific test(s) to skip"
	@echo " REPEAT=[n]               - repeat tests up to N times or until a failure occurs"
	@echo " NO_COLOR=[true|false]    - disables colorful Docker and Ginkgo output"
	@echo " TIMEOUT=[minutes]        - test timeout override (30 minutes by default)"
	@echo " GINKGO_TIMEOUT=[Ns/m/h]  - Ginkgo timeout override (3h by default)"

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

.build.ok: build
	@touch .build.ok

.build_debug.ok: build-debug
	@touch .build.ok

.PHONY: test
test: FORCE_BUILD=false
test: .deps.ok .build.ok
	@bash ./kube_test.sh --persist=$(PERSIST) --verbose=$(VERBOSE) \
		--test=$(TEST) --repeat=$(REPEAT) --skip=$(SKIP) \
		--no_color=$(NO_COLOR) --timeout=$(TIMEOUT) \
		--ginkgo_timeout=$(GINKGO_TIMEOUT); \
		./script/compress.sh $$?

.PHONY: cluster-help
cluster-help:
	@bash ./script/setup-cluster.sh help

.PHONY: release-cluster
release-cluster: .kube_deps.ok
	@bash ./script/setup-cluster.sh release-cluster

.PHONY: master-cluster
master-cluster: .kube_deps.ok
	@bash ./script/setup-cluster.sh master-cluster

.PHONY: rebuild-master-cluster
rebuild-master-cluster: .kube_deps.ok
	@bash ./script/setup-cluster.sh rebuild-master-cluster

.PHONY: build
build: .deps.ok build-vpp-release
	@rm -f .build.ok
	bash ./script/build_kube.sh release $(FORCE_BUILD)
	@touch .build.ok

.PHONY: build-debug
build-debug: .deps.ok build-vpp-debug
	@rm -f .build.ok
	bash ./script/build_kube.sh debug $(FORCE_BUILD)
	@touch .build.ok

.deps.ok:
	@$(MAKE) install-deps

.kube_deps.ok:
	@$(MAKE) install-kube-deps

.PHONY: install-kube-deps
install-kube-deps: .deps.ok
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
	@touch .kube_deps.ok

.PHONY: install-deps
install-deps:
	@rm -f .deps.ok
	@if [ -d "/usr/local/go" ]; then \
        echo "Go is already installed. You may have to update it manually if version < 1.23.10"; \
		go version; \
    else \
        echo "Installing Go 1.23"; \
		wget -t 2 https://go.dev/dl/go1.23.10.linux-$(ARCH).tar.gz -O /tmp/go1.23.10.linux-$(ARCH).tar.gz && sudo tar -C /usr/local -xzf /tmp/go1.23.10.linux-$(ARCH).tar.gz; \
		echo "Go installed successfully. Add it to your PATH by running:"; \
        echo "echo 'export PATH=/usr/local/go/bin:\$$PATH' >> ~/.bashrc && source ~/.bashrc"; \
	fi
	@if ! command -v docker >/dev/null 2>&1; then \
		sudo -E apt-get update; \
		sudo -E apt-get install -y apt-transport-https ca-certificates curl software-properties-common; \
		if [ ! -f /usr/share/keyrings/docker-archive-keyring.gpg ] ; then \
			curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; \
			echo "deb [arch=$(ARCH) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(UBUNTU_CODENAME) stable" \
				| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null ; \
			apt-get update; \
		fi; \
		sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; \
	else \
		echo "Docker already installed. You may need to update."; \
	fi
	@touch .deps.ok

.PHONY: checkstyle-go
checkstyle-go:
	@output=$$(find . -type f -name '*.go' -not -path './.go_cache/*' -exec go run golang.org/x/tools/cmd/goimports@v0.35.0 -d {} +); \
	status=$$?; \
	if [ $$status -ne 0 ]; then \
		exit $$status; \
    elif [ -z "$$output" ]; then \
        echo "******************************************************************************"; \
        echo "* Kube-Test Golang Checkstyle OK."; \
        echo "******************************************************************************"; \
    else \
        echo "$$output"; \
        echo "******************************************************************************"; \
        echo "* Kube-Test Golang Checkstyle FAILED. Use 'make fixstyle-go' or fix errors manually."; \
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

.PHONY: cleanup-kube
cleanup-kube:
	@if [ ! -f ".last_ppid" ]; then \
		echo "'.last_ppid' file does not exist."; \
		exit 1; \
	fi
	@echo "****************************"
	@echo "Removing kubernetes pods:"
	@kubectl delete pods --all --grace-period=0 -n kube-test$$(cat .last_ppid)
	@echo "****************************"
	@echo "Removing kubernetes namespace:"
	@kubectl delete namespace kube-test$$(cat .last_ppid)
	@echo "****************************"
	@echo "Done."
	@echo "****************************"
