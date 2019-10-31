
##############################################################################
# Host Quad
##############################################################################
HOST_DISTRO_NAME=$(shell cat /etc/lsb-release | sed -nEe 's/DISTRIB_ID=(.*)/\L\1/p')
HOST_DISTRO_VER=$(shell cat /etc/lsb-release | sed -nEe 's/DISTRIB_RELEASE=(.*)/\1/p')
HOST_ARCH?=$(shell uname -m)
HOST_PLATFORM?=generic
HOST_QUAD=$(HOST_DISTRO_NAME)-$(HOST_DISTRO_VER)-$(HOST_ARCH)-$(HOST_PLATFORM)

##############################################################################
# Target Quad
##############################################################################
TARGET_DISTRO_NAME?=$(HOST_DISTRO_NAME)
TARGET_DISTRO_VER?=$(HOST_DISTRO_VER)
TARGET_ARCH?=$(HOST_ARCH)
TARGET_PLATFORM?=$(HOST_PLATFORM)
BUILD_TYPE?=release
TARGET_QUAD=$(TARGET_DISTRO_NAME)-$(TARGET_DISTRO_VER)-$(TARGET_ARCH)-$(TARGET_PLATFORM)


ifeq ($(HOST_QUAD),$(TARGET_QUAD))
##############################################################################
# native compilation
##############################################################################
BUILD_DIR=$(PWD)/build/native-$(BUILD_TYPE)/build
define exec
	@echo "### $(1)"
	$(1)
endef
else
##############################################################################
# cross compilation
##############################################################################
BUILD_DIR=$(PWD)/build/$(TARGET_QUAD)-$(BUILD_TYPE)/build
CROSS_PROXY?=$(shell apt-config dump | sed -nEe 's/Acquire::http::Proxy.*"(.*)".*/\1/p')
CROSS_IMAGE=$(TARGET_DISTRO_NAME):$(TARGET_DISTRO_VER)
CROSS_NAME=$(shell echo vpp-dev-env-${TARGET_DISTRO_NAME} | sed  's/\//-/g')
define exec
	@echo "### $(1)"
	@docker container exec $(CROSS_NAME) sh -c "$(1)"
endef
include build/cross_env.mk
endif

CMAKE_ARGS = -G Ninja
CMAKE_ARGS += -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)
CMAKE_ARGS += -DCMAKE_PREFIX_PATH:PATH=/opt/vpp/external/$(TARGET_ARCH)

xbuild cross-build:
	@mkdir -p $(BUILD_DIR)
	@$(call exec,cd $(BUILD_DIR) && cmake $(CMAKE_ARGS) $(PWD)/src)
	@$(call exec,cmake --build $(BUILD_DIR))

pkg cross-package: cross-build
	@$(call exec,cmake --build $(BUILD_DIR) -- package-deb)

xrebuild cross-rebuild: cross-wipe cross-build

xwipe cross-wipe:
	@$(call exec, rm -rf $(BUILD_DIR))

