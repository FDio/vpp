################################################################################
# @brief:       Makefile for building the VPP testbench example.
# @author:      Matthew Giassa.
# @copyright:   (C) Cisco 2021.
################################################################################
#------------------------------------------------------------------------------#
# Constants and settings.
#------------------------------------------------------------------------------#
SHELL=/bin/bash
.DEFAULT_GOAL: all

# Image names.
# TODO: semver2 format if we want to publish these to a registry.
DOCKER_CLIENT_IMG               := vpp-testbench-client
DOCKER_CLIENT_REL               := local
DOCKER_CLIENT_IMG_FULL          := $(DOCKER_CLIENT_IMG):$(DOCKER_CLIENT_REL)
DOCKER_SERVER_IMG               := vpp-testbench-server
DOCKER_SERVER_REL               := local
DOCKER_SERVER_IMG_FULL          := $(DOCKER_SERVER_IMG):$(DOCKER_SERVER_REL)
# Docker build-time settings (and run-time settings as well).
DOCKER_HEALTH_PROBE_PORT        := $(shell bash -c ". vpp_testbench_helpers.sh; host_only_get_docker_health_probe_port")

#------------------------------------------------------------------------------#
# Functions.
#------------------------------------------------------------------------------#
#------------------------------------------------------------------------------#
# Cleanup running containers, Docker networks, etc.; from previous runs.
define cleanup_everything
	# Terminate the containers.
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_kill_testbench_client_container $(DOCKER_CLIENT_IMG_FULL); \
		host_only_kill_testbench_server_container $(DOCKER_SERVER_IMG_FULL); \
		"

	# Cleanup Docker bridge network.
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_destroy_docker_networks; \
		"
endef

#------------------------------------------------------------------------------#
# Launch our containers and connect them to a private Docker network for
# testing.
define launch_testbench
	# Create Docker bridge network.
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_create_docker_networks; \
		"

	# Launch the containers.
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_run_testbench_client_container $(DOCKER_CLIENT_IMG_FULL); \
		host_only_run_testbench_server_container $(DOCKER_SERVER_IMG_FULL); \
		"

	# Entrypoint scripts will bring up the various links.
	# Use "docker ps" to check status of containers, see if their health
	# probes are working as expected (i.e. "health"), etc.
endef

#------------------------------------------------------------------------------#
# Goals.
#------------------------------------------------------------------------------#
#------------------------------------------------------------------------------#
# Default goal.
.PHONY: all
all: docker
	@echo Done.

#------------------------------------------------------------------------------#
# Build all docker images.
.PHONY: docker
docker: Dockerfile.vpp_testbench Dockerfile.vpp_testbench.dockerignore \
	entrypoint_client.sh entrypoint_server.sh \
	vpp_testbench_helpers.sh
	# Client image.
	DOCKER_BUILDKIT=1 docker build \
			--file Dockerfile.vpp_testbench \
			--build-arg HEALTHCHECK_PORT=$(DOCKER_HEALTH_PROBE_PORT) \
			--tag $(DOCKER_CLIENT_IMG_FULL) \
			--target client_img \
			.
	# Server image.
	DOCKER_BUILDKIT=1 docker build \
			--file Dockerfile.vpp_testbench \
			--build-arg HEALTHCHECK_PORT=$(DOCKER_HEALTH_PROBE_PORT) \
			--tag $(DOCKER_SERVER_IMG_FULL) \
			--target server_img \
			.

#------------------------------------------------------------------------------#
# Execute end-to-end test via containers.
.PHONY: test
test:
	# Cleanup anything from previous runs.
	$(call cleanup_everything)

	# Launch our testbench.
	$(call launch_testbench)

	# Final cleanup.
	$(call cleanup_everything)

#------------------------------------------------------------------------------#
# For manually cleaning up a test that fails partway through its execution.
.PHONY: clean
clean:
	$(call cleanup_everything)

#------------------------------------------------------------------------------#
# For manually launching our testbench for interactive testing.
.PHONY: start
start:
	$(call launch_testbench)

#------------------------------------------------------------------------------#
# For manually stopping (and cleaning up) our testbench.
.PHONY: stop
stop:
	$(call cleanup_everything)

#------------------------------------------------------------------------------#
# Create an interactive shell session connected to the client container (for
# manual testing). Typically preceded by "make start", and concluded with
# "make stop" after exiting the shell.
.PHONY: shell_client
shell_client:
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_shell_client_container; \
		"

#------------------------------------------------------------------------------#
# Create an interactive shell session connected to the server container (for
# manual testing). Typically preceded by "make start", and concluded with
# "make stop" after exiting the shell.
.PHONY: shell_server
shell_server:
	bash -c "\
		. vpp_testbench_helpers.sh; \
		host_only_shell_server_container; \
		"

