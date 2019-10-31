
cross-env-init:
	docker run -td \
	  --name $(CROSS_NAME) \
	  --privileged \
	  --net host \
	  -v $(HOME):$(HOME) \
	  -v /dev:/dev \
	  -v /opt:/opt \
	  -v/lib/modules:/lib/modules/host:ro \
	  $(TARGET_DISTRO_NAME):$(TARGET_DISTRO_VER) \
	  /bin/bash
	$(call exec,groupadd -g $(shell id -rg) $(USER))
	$(call exec,useradd -u $(shell id -ru) -g $(shell id -rg) -M -d $(HOME) -s /bin/bash $(USER))
	$(call exec,echo $(CROSS_NAME) > /etc/debian_chroot)
	$(call exec,echo 'Acquire::http::Proxy \"$(CROSS_PROXY)\";' >> /etc/apt/apt.conf)
	$(call exec,apt-get -qy update)
	$(call exec,apt-get -qy install -qy sudo make)
	$(call exec,echo '$(USER) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers)
	$(call exec,make -C $(PWD) UNATTENDED=y install-dep install-ext-deps)

cross-env-update:
	$(call exec,make -C $(PWD) UNATTENDED=y install-dep install-ext-deps)


cross-shell:
	@docker container exec -w $(PWD) -it $(CROSS_NAME) su $(USER)

cross-env-destroy:
	-docker kill $(CROSS_NAME)
	-docker rm $(CROSS_NAME)
