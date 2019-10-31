
CROSS_DISTRO_NAME?=ubuntu
CROSS_DISTRO_VER?=18.04
CROSS_TARGET?=release
CROSS_ARCH?=$(shell uname -m)
CROSS_PROXY=$(shell apt-config dump | sed -nEe 's/Acquire::http::Proxy.*"(.*)".*/\1/p')

CROSS_IMAGE=$(CROSS_DISTRO_NAME):$(CROSS_DISTRO_VER)
CROSS_NAME=vpp-dev-env-$(CROSS_DISTRO_NAME)-$(CROSS_DISTRO_VER)-$(CROSS_ARCH)
CROSS_BUILD_DIR=$(PWD)/build/$(CROSS_DISTRO_NAME)-$(CROSS_DISTRO_VER)-$(CROSS_ARCH)-$(CROSS_TARGET)/build

define docker_exec
	@echo "### $(1)"
	@docker container exec $(CROSS_NAME) sh -c "$(1)"
endef

cross-env-init:
	docker run -td \
	  --name $(CROSS_NAME) \
	  --privileged \
	  --net host \
	  -v $(HOME):$(HOME) \
	  -v /dev:/dev \
	  -v/lib/modules:/lib/modules/host:ro \
	  $(CROSS_DISTRO_NAME):$(CROSS_DISTRO_VER) \
	  /bin/bash
	$(call docker_exec,groupadd -g $(shell id -rg) $(USER))
	$(call docker_exec,useradd -u $(shell id -ru) -g $(shell id -rg) -M -d $(HOME) -s /bin/bash $(USER))
	$(call docker_exec,echo $(CROSS_NAME) > /etc/debian_chroot)
	$(call docker_exec,echo 'Acquire::http::Proxy \"$(CROSS_PROXY)\";' >> /etc/apt/apt.conf)
	$(call docker_exec,apt-get -qy update)
	$(call docker_exec,apt-get -qy install -qy sudo make)
	$(call docker_exec,echo '$(USER) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers)
	$(call docker_exec,make -C $(PWD) UNATTENDED=y install-dep install-ext-deps)

cross-env-update:
	$(call docker_exec,make -C $(PWD) UNATTENDED=y install-dep install-ext-deps)


cross-shell:
	@docker container exec -w $(PWD) -it $(CROSS_NAME) su $(USER)

cross-env-destroy:
	-docker kill $(CROSS_NAME)
	-docker rm $(CROSS_NAME)

cross-build:
	$(call docker_exec,mkdir -p $(CROSS_BUILD_DIR) && cd $(CROSS_BUILD_DIR) && cmake -G Ninja -DCMAKE_PREFIX_PATH:PATH=/opt/vpp/external/$(CROSS_ARCH) $(PWD)/src)
	$(call docker_exec,cmake --build $(CROSS_BUILD_DIR))

cross-package: cross-build
	$(call docker_exec,cmake --build $(CROSS_BUILD_DIR) -- package-deb)

cross-rebuild: cross-wipe cross-build

cross-wipe:
	$(call docker_exec, rm -rf $(CROSS_BUILD_DIR))

