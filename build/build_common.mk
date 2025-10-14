# Copyright (c) 2024 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Scripts require non-POSIX parts of bash
SHELL := $(shell which bash)

ifneq ($(NOMAD_TASK_NAME),)
WORKSPACE ?= $(shell dirname $(shell dirname $(CURDIR)))
endif
DL_CACHE_DIR = $(HOME)/Downloads
MAKE_ARGS ?= -j
BUILD_DIR        ?= $(CURDIR)/_build
INSTALL_DIR      ?= $(CURDIR)/_install
ROOT_DIR 		 ?= $(DESTDIR)
DOWNLOAD_DIR     ?= $(CURDIR)/downloads
PKG_VERSION ?= $(shell git describe --abbrev=0 --match 'v[0-9]*' | cut -d- -f1 | cut -dv -f2 | cut -d. -f1,2)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct .)
ifeq ($(shell uname), FreeBSD)
JOBS := $(shell nproc)
else
JOBS := $(if $(shell [ -f /proc/cpuinfo ] && head /proc/cpuinfo),\
	$(shell grep -c ^processor /proc/cpuinfo), 2)
endif	# FreeBSD

B := $(BUILD_DIR)
I := $(INSTALL_DIR)
R := $(ROOT_DIR)
D := $(DOWNLOAD_DIR)
ifeq ($(WORKSPACE),)
L := $(B)
else
L := $(WORKSPACE)/archives/install-deps-logs
$(shell rm -rf $(L) && mkdir -p $(L))
endif

ifneq ($(shell which cmake3 2>/dev/null),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

ARCH_X86_64=$(filter x86_64,$(shell uname -m))
AARCH64=$(filter aarch64,$(shell uname -m))
