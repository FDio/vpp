# Copyright (c) 2015 Cisco and/or its affiliates.
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

#
# Copyright (c) 2007-2008 Eliot Dresselhaus
#
#  Permission is hereby granted, free of charge, to any person obtaining
#  a copy of this software and associated documentation files (the
#  "Software"), to deal in the Software without restriction, including
#  without limitation the rights to use, copy, modify, merge, publish,
#  distribute, sublicense, and/or sell copies of the Software, and to
#  permit persons to whom the Software is furnished to do so, subject to
#  the following conditions:
#
#  The above copyright notice and this permission notice shall be
#  included in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

######################################################################
# Collect makefile fragments
######################################################################

# Scripts require non-POSIX parts of bash
SHELL := /bin/bash

# Where this makefile lives
MU_BUILD_ROOT_DIR = $(shell pwd)
MU_BUILD_NAME = $(shell basename $(MU_BUILD_ROOT_DIR))

# Search path (e.g. multiple directories) where sources are found.
SOURCE_PATH =

# Pick up user's definitions for variables e.g. SOURCE_PATH, etc.
-include build-config.mk

MU_BUILD_ROOT_NAME = $(shell basename $(MU_BUILD_ROOT_DIR))
MU_BUILD_DATA_DIR_NAME = build-data

ABSOLUTE_SOURCE_PATH = $(foreach d,$(SOURCE_PATH),$(shell cd $(d) && pwd))

SOURCE_PATH_BUILD_ROOT_DIRS = $(addsuffix /$(MU_BUILD_NAME),$(ABSOLUTE_SOURCE_PATH))
SOURCE_PATH_BUILD_DATA_DIRS = $(addsuffix /$(MU_BUILD_DATA_DIR_NAME),$(ABSOLUTE_SOURCE_PATH))

# For tools use build-root as source path, otherwise use given source path
FIND_SOURCE_PATH =						\
  $(if $(is_build_tool),					\
    $(SOURCE_PATH_BUILD_ROOT_DIRS) $(MU_BUILD_ROOT_DIR),	\
    $(SOURCE_PATH_BUILD_DATA_DIRS))

# First search given source path, then default to build-root
FULL_SOURCE_PATH = $(SOURCE_PATH_BUILD_DATA_DIRS) $(MU_BUILD_ROOT_DIR)

# Misc functions
is_in_fn = $(strip $(filter $(1),$(2)))
last_fn = $(lastword $1)
chop_fn = $(wordlist 2,$(words $1),x $1)
uniq_fn = $(strip $(if $1,$(call uniq_fn,$(call chop_fn,$1)) \
            $(if $(filter $(call last_fn,$1),$(call chop_fn,$1)),,$(call last_fn,$1))))
ifdef3_fn = $(if $(patsubst undefined,,$(origin $(1))),$(3),$(2))
ifdef_fn = $(call ifdef3_fn,$(1),$(2),$($(1)))

_mu_debug = $(warning "$(1) = $($(1))")

$(foreach d,$(FIND_SOURCE_PATH),					\
  $(eval _mu_package_mk_in_$(d) = $(shell find $(d)/packages/*.mk 2> /dev/null))	\
  $(eval _mu_srcdirs_in_$(d) =						\
    $(shell find $(d)/..						\
      -maxdepth 1							\
      -type d								\
      -and -not -name ".."						\
      -and -not -name $(MU_BUILD_ROOT_NAME)				\
      -and -not -name $(MU_BUILD_DATA_DIR_NAME)))			\
  $(eval _mu_non_package_files_in_$(d) =				\
    $(shell find $(d)/packages						\
      -type f								\
      -and -not -name '*.mk'						\
      -and -not -name '*~' 2> /dev/null))				\
  $(foreach p,$(patsubst %.mk,%,$(notdir $(_mu_package_mk_in_$(d)))),	\
    $(eval _mu_package_dir_$(p) = $(d))					\
    $(eval _mu_package_mk_$(p) = $(d)/packages/$(p).mk)			\
  )									\
  $(foreach p,$(notdir $(_mu_srcdirs_in_$(d))),				\
    $(eval _mu_package_srcdir_$(p) = $(shell cd $(d)/../$(p) && pwd))	\
  )									\
)

# Find root directory for package based on presence of package .mk
# makefile fragment on source path.
_find_build_data_dir_for_package_fn = $(shell			\
  set -eu$(BUILD_DEBUG) ;					\
  for d in $(FIND_SOURCE_PATH) ; do				\
    f="$${d}/packages/$(1).mk" ;				\
    [[ -f $${f} ]] && echo `cd $${d} && pwd` && exit 0 ;	\
  done ;							\
  echo "")
find_build_data_dir_for_package_fn = $(call ifdef_fn,_mu_package_dir_$(1),)

# dir/PACKAGE
_find_source_fn = $(shell				\
  set -eu$(BUILD_DEBUG) ;				\
  d="$(call find_build_data_dir_for_package_fn,$(1))" ;	\
  [[ -n "$${d}" ]] && d="$${d}/../$(1)" ;		\
  echo "$${d}")
find_source_fn = $(call ifdef3_fn,_mu_package_dir_$(1),,$(_mu_package_dir_$(1))/../$(1))

# Find given FILE in source path as build-data/packages/FILE
find_package_file_fn = $(shell				\
  set -eu$(BUILD_DEBUG) ;				\
  d="$(call find_build_data_dir_for_package_fn,$(1))" ;	\
  [[ -n "$${d}" ]] && d="$${d}/packages/$(2)" ;		\
  [[ -f "$${d}" ]] && echo "$${d}")

# Find first FILE in source path with name PATH/build-data/FILE
find_build_data_file_fn = $(shell				\
  set -eu$(BUILD_DEBUG) ;					\
  for d in $(FIND_SOURCE_PATH) ; do				\
    f="$${d}/$(1)" ;						\
    [[ -f $${f} ]] && echo `cd $${d} && pwd`/$(1) && exit 0 ;	\
  done ;							\
  echo "")

######################################################################
# ARCH, PLATFORM
######################################################################

NATIVE_ARCH = $(shell gcc -dumpmachine | sed -e 's/\([a-zA-Z_0-9]*\)-.*/\1/')

# Find all platforms.mk that we can, including those from build-root
$(foreach d,$(FULL_SOURCE_PATH), \
  $(eval -include $(d)/platforms.mk))

# Platform should be defined somewhere by specifying $($(PLATFORM)_arch)
ARCH = $(strip $($(PLATFORM)_arch))
ifeq ($(ARCH),)
  $(error "Unknown platform `$(PLATFORM)'")
endif

# map e.g. ppc7450 -> ppc
BASIC_ARCH = \
   ${shell case '$(ARCH)' in \
      (native) echo $(NATIVE_ARCH) ;; \
      (i*86*) echo i386 ;; \
      (ppc*|powerpc*) echo ppc ;; \
      (*) echo '$(ARCH)' ;; \
     esac }

# x86_64 can be either 32/64.  set BIACH=32 to get 32 bit libraries.
BIARCH = 64

aarch64_libdir = 64
x86_64_libdir = $(BIARCH)
native_libdir = $($(NATIVE_ARCH)_libdir)

# lib or lib64 depending
arch_lib_dir = lib$($(BASIC_ARCH)_libdir)

# OS to configure for.  configure --host will be set to $(ARCH)-$(OS)
# Allow per-platform overrides

OS = $(strip $($(PLATFORM)_os))
ifeq ($(OS),)
  OS = mu-linux
endif

spu_target = spu
native_target =

is_native = $(if $(ARCH:native=),,true)
not_native = $(if $(ARCH:native=),true,)

ARCH_TARGET_tmp = $(call ifdef_fn,$(ARCH)_target,$(ARCH)-$(OS))
TARGET = $(call ifdef_fn,$(PLATFORM)_target,$(ARCH_TARGET_tmp))
TARGET_PREFIX = $(if $(not_native),$(TARGET)-,)

# CPU microarchitecture detection.
# Either set <platform>_march in build-data/platforms/<platform>.mk,
# or detect and use the build-host instruction set

MARCH = $(strip $($(PLATFORM)_march))
ifeq ($(MARCH),)
  ifneq ($(wildcard $(TOOL_INSTALL_DIR)/bin/$(TARGET)-gcc),)
    TARGET_GCC = $(TOOL_INSTALL_DIR)/bin/$(TARGET)-gcc
  else ifneq ($(wildcard $(MU_BUILD_ROOT_DIR)/tools/bin/$(TARGET)-gcc),)
    TARGET_GCC = $(MU_BUILD_ROOT_DIR)/tools/bin/$(TARGET)-gcc
  endif
  ifneq ($(TARGET_GCC),)
    MARCH = $(shell $(TARGET_GCC) -Q --help=target -march=native | grep march | sed -e 's/.*march=[[:space:]]*//')
  else
    MARCH = native
  endif
else
  ifeq ($(MARCH),nehalem)
    override MARCH = corei7
  else ifeq ($(MARCH),westmere)
    override MARCH = corei7
  else ifeq ($(MARCH),sandybridge)
    override MARCH = corei7-avx
  else ifeq ($(MARCH),ivybridge)
    override MARCH = core-avx-i
  else ifeq ($(MARCH),haswell)
    override MARCH = core-avx2
  endif
endif
export MARCH

MTUNE = $(strip $($(PLATFORM)_mtune))
ifeq ($(MTUNE),)
  MTUNE = generic
endif

######################################################################
# Generic build stuff
######################################################################

# The package we are currently working on
PACKAGE = $*

# Build/install tags.  This lets you have different CFLAGS/CPPFLAGS/LDFLAGS
# for e.g. debug versus optimized compiles.  Each tag has its own set of build/install
# areas.
TAG =
TAG_PREFIX = $(if $(TAG),$(TAG)-)

# yes you need the space
tag_var_with_added_space_fn = $(if $($(TAG)_TAG_$(1)),$($(TAG)_TAG_$(1)) )

# TAG=debug for debugging
debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -D_FORTIFY_SOURCE=2 -march=$(MARCH) \
		   -fstack-protector-all -fPIC
debug_TAG_CXXFLAGS = -g -O0 -DCLIB_DEBUG -D_FORTIFY_SOURCE=2 -march=$(MARCH) \
		   -fstack-protector-all -fPIC
debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -D_FORTIFY_SOURCE=2 -march=$(MARCH) \
		   -fstack-protector-all -fPIC

BUILD_PREFIX_package = build-$(TAG_PREFIX)
BUILD_PREFIX_tool = build-tool-$(TAG_PREFIX)
INSTALL_PREFIX = install-$(TAG_PREFIX)
IMAGES_PREFIX = images-$(TAG_PREFIX)

# Whether we are building a tool or not
tool_or_package_fn = $(if $(is_build_tool),tool,package)

# Directory where packages are built & installed
BUILD_DIR = $(MU_BUILD_ROOT_DIR)/$(BUILD_PREFIX_$(call tool_or_package_fn))$(ARCH)
INSTALL_DIR = $(MU_BUILD_ROOT_DIR)/$(INSTALL_PREFIX)$(ARCH)

PLATFORM_IMAGE_DIR = $(MU_BUILD_ROOT_DIR)/$(IMAGES_PREFIX)$(PLATFORM)

# $(call VAR,DEFAULT)
override_var_with_default_fn = $(if $($(1)),$($(1)),$(2))

# $(call if_directory_exists_fn,D1,D2) returns D1 if it exists else D2
define if_directory_exists_fn
$(shell if test -d $(1); then echo $(1); else echo $(2); fi)
endef

# $(call if_file_exists_fn,F1,F2) returns F1 if it exists else F2
define if_file_exists_fn
$(shell if test -f $(1); then echo $(1); else echo $(2); fi)
endef

# Default VAR, package specified override of default PACKAGE_VAR
package_var_fn = $(call override_var_with_default_fn,$(1)_$(2),$(1))

package_build_dir_fn = $(call package_var_fn,$(1),build_dir)

package_install_dir_fn = \
  $(if $(is_build_tool),$(TOOL_INSTALL_DIR),$(INSTALL_DIR)/$(call package_build_dir_fn,$(1)))

PACKAGE_BUILD_DIR = \
  $(BUILD_DIR)/$(call package_build_dir_fn,$(PACKAGE))
PACKAGE_INSTALL_DIR = \
  $(call package_install_dir_fn,$(PACKAGE))

# Tools (gcc, binutils, glibc...) are installed here
TOOL_INSTALL_DIR = $(MU_BUILD_ROOT_DIR)/tools

# Target specific tools go here e.g. mu-build/tools/ppc-mu-linux
TARGET_TOOL_INSTALL_DIR = $(TOOL_INSTALL_DIR)/$(TARGET)

# Set BUILD_DEBUG to vx or x enable shell command tracing.
BUILD_DEBUG =

# Message from build system itself (as opposed to make or shell commands)
build_msg_fn = echo "@@@@ $(1) @@@@"

# Allow CCACHE_DIR to be overridden, e.g. in .../build-root/build-config.mk
ifeq ($(CCACHE_DIR),)
  CCACHE_DIR=$(MU_BUILD_ROOT_DIR)/.ccache
endif

# Always prefer our own tools to those installed on system.
# Note: ccache-bin must be before tool bin.
#
# Removed LD_LIBRARY_PATH from BUILD_ENV (drb, 10/31/17):
# export LD_LIBRARY_PATH=$(TOOL_INSTALL_DIR)/lib64:$(TOOL_INSTALL_DIR)/lib
#   Reported to cause trouble. Only of historical interest, since we no longer
#   build a full tool chain from source.

BUILD_ENV =										\
    export CCACHE_DIR=$(CCACHE_DIR) ;					\
    export PATH=$(wildcard /usr/lib*/ccache):$(TOOL_INSTALL_DIR)/bin:$${PATH} ;		\
    $(if $(call configure_var_fn,PATH), export PATH=$${PATH}:$(call configure_var_fn,PATH);,)	\
    export PATH="`echo $${PATH} | sed -e s/[.]://`" ;					\
    $(if $(not_native),export CONFIG_SITE=$(MU_BUILD_ROOT_DIR)/config.site ;,)	\
    set -eu$(BUILD_DEBUG) ;							        \
    set -o pipefail

######################################################################
# Package build generic definitions
######################################################################

package_dir_fn = \
  $(call find_build_data_dir_for_package_fn,$(1))/packages

package_mk_fn = $(call package_dir_fn,$(1))/$(1).mk

# Pick up built-root/pre-package-include.mk for all source directories
$(foreach d,$(SOURCE_PATH_BUILD_ROOT_DIRS),	\
  $(eval -include $(d)/pre-package-include.mk))

$(foreach d,$(addsuffix /packages,$(FIND_SOURCE_PATH)),			\
  $(eval -include $(d)/*.mk)						\
  $(eval ALL_PACKAGES += $(patsubst $(d)/%.mk,%,$(wildcard $(d)/*.mk)))	\
)

# Pick up built-root/post-package-include.mk for all source directories
$(foreach d,$(SOURCE_PATH_BUILD_ROOT_DIRS),	\
  $(eval -include $(d)/post-package-include.mk))

# Linux specific native build tools
NATIVE_TOOLS_LINUX =				\
  e2fsimage					\
  e2fsprogs					\
  fakeroot					\
  jffs2						\
  mkimage					\
  zlib						\
  xz						\
  squashfs

IS_LINUX = $(if $(findstring no,$($(PLATFORM)_uses_linux)),no,yes)

NATIVE_TOOLS_$(IS_LINUX) += $(NATIVE_TOOLS_LINUX)

# only build glibc for linux installs
CROSS_TOOLS_$(IS_LINUX) += glibc gcc

# must be first for bootstrapping
NATIVE_TOOLS = findutils make

# basic tools needed for build system
NATIVE_TOOLS += git automake autoconf libtool texinfo tar

# needed to compile gcc
NATIVE_TOOLS += mpfr gmp mpc

# Tool to sign binaries
NATIVE_TOOLS += sign

# ccache
NATIVE_TOOLS += ccache

# Tools needed on native host to build for platform
NATIVE_TOOLS += $(call ifdef_fn,$(PLATFORM)_native_tools,)

# Tools for cross-compiling from native -> ARCH
CROSS_TOOLS = binutils gcc-bootstrap gdb

# Tools needed on native host to build for platform
CROSS_TOOLS += $(call ifdef_fn,$(PLATFORM)_cross_tools,)

NATIVE_TOOLS += $(NATIVE_TOOLS_yes)
CROSS_TOOLS += $(CROSS_TOOLS_yes)

timestamp_name_fn = .mu_build_$(1)_timestamp
CONFIGURE_TIMESTAMP = $(call timestamp_name_fn,configure)
BUILD_TIMESTAMP = $(call timestamp_name_fn,build)
INSTALL_TIMESTAMP = $(call timestamp_name_fn,install)

TIMESTAMP_DIR = $(PACKAGE_BUILD_DIR)

find_newer_files_fn =						\
  "`for i in $(2) ; do						\
      [[ -f $$i && $$i -nt $(1) ]] && echo "$$i" && exit 0;	\
    done ;							\
    exit 0;`"

find_filter = -not -name '*~'
find_filter += -and -not -path '*/.git*'
find_filter += -and -not -path '*/.svn*'
find_filter += -and -not -path '*/.CVS*'
find_filter += -and -not -path '*/manual/*'
find_filter += -and -not -path '*/autom4te.cache/*'
find_filter += -and -not -path '*/doc/all-cfg.texi'
find_filter += -and -not -path '*/.mu_build_*'

find_newer_filtered_fn =			\
  (! -f $(1)					\
    || -n $(call find_newer_files_fn,$(1),$(3))	\
    || -n "`find -L $(2) 			\
	      -type f				\
              -and -newer $(1)			\
	      -and \( $(4) \)			\
              -print -quit`")

find_newer_fn =							\
  $(call find_newer_filtered_fn,$(1),$(2),$(3),$(find_filter))

######################################################################
# Package dependencies
######################################################################

# This must come before %-configure, %-build, %-install pattern rules
# or else dependencies will not work.

package_dependencies_fn =				\
  $(patsubst %-install, %,				\
    $(filter %-install,$($(1)_configure_depend)))

PACKAGE_DEPENDENCIES = $(call package_dependencies_fn,$(PACKAGE))

# package specific configure, build, install dependencies
add_package_dependency_fn = \
  $(if $($(1)_$(2)_depend), \
       $(eval $(1)-$(2) : $($(1)_$(2)_depend)))

$(foreach p,$(ALL_PACKAGES), \
    $(call add_package_dependency_fn,$(p),configure) \
    $(call add_package_dependency_fn,$(p),build) \
    $(call add_package_dependency_fn,$(p),install))

TARGETS_RESPECTING_DEPENDENCIES = image_install wipe diff push-all pull-all find-source

# carry over packages dependencies to image install, wipe, pull-all, push-all
$(foreach p,$(ALL_PACKAGES),							\
  $(if $($(p)_configure_depend),						\
    $(foreach s,$(TARGETS_RESPECTING_DEPENDENCIES),				\
      $(eval $(p)-$(s):								\
	     $(addsuffix -$(s), $(call package_dependencies_fn,$(p)))))))

# recursively resolve dependencies
resolve_dependencies2_fn = $(strip					\
  $(eval __added = $(filter-out $(4),					\
    $(call uniq_fn,							\
      $(foreach l,$(3),							\
       $(call ifdef3_fn,$(l)$(1),,$(call $(2),$($(l)$(1))))		\
      ))))								\
  $(eval __known = $(call uniq_fn,$(4) $(3) $(__added)))		\
  $(if $(__added),							\
    $(call resolve_dependencies2_fn,$(1),$(2),$(__added),$(__known)),	\
    $(__known))								\
)

resolve_dependencies_null_fn = $(1)

resolve_dependencies_fn = $(call resolve_dependencies2_fn,$(1),resolve_dependencies_null_fn,$(2))

######################################################################
# Package configure
######################################################################

# x86_64 can be either 32/64.  set BIACH=32 to get 32 bit libraries.
BIARCH = 64

x86_64_libdir = $(BIARCH)
native_libdir = $($(NATIVE_ARCH)_libdir)

# lib or lib64 depending
arch_lib_dir = lib$($(BASIC_ARCH)_libdir)

# find dynamic linker as absolute path
TOOL_INSTALL_LIB_DIR=$(TOOL_INSTALL_DIR)/$(TARGET)/$(arch_lib_dir)
DYNAMIC_LINKER=${shell cd $(TOOL_INSTALL_LIB_DIR); echo ld*.so.*}

# Pad dynamic linker & rpath so elftool will never have to change ELF section sizes.
# Yes, this is a kludge.
lots_of_slashes_to_pad_names = "/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////"

# When PLATFORM != native we *always* use our own versions of GLIBC and dynamic linker
# Allow per-platform overrides
CROSS_LDFLAGS = $(strip $($(PLATFORM)_cross_ldflags))
ifeq ($(CROSS_LDFLAGS),)
  CROSS_LDFLAGS =											\
    -Wl,--dynamic-linker=$(lots_of_slashes_to_pad_names)$(TOOL_INSTALL_LIB_DIR)/$(DYNAMIC_LINKER)	\
    -Wl,-rpath -Wl,$(lots_of_slashes_to_pad_names)$(TOOL_INSTALL_LIB_DIR)
endif

cross_ldflags = $(if $(is_native)$(is_build_tool),,$(CROSS_LDFLAGS) )

# $(call installed_libs_fn,PACKAGE)
# Return install library directory for given package.
# Some packages (e.g. openssl) don't install under lib64; instead they use lib
define installed_lib_fn
$(call if_directory_exists_fn,
  $(call package_install_dir_fn,$(1))/$(arch_lib_dir),
  $(call package_install_dir_fn,$(1))/lib)
endef

# Set -L and rpath to point to dependent libraries previously built by us.
installed_libs_fn =					\
  $(foreach i,$(1),					\
    -L$(call installed_lib_fn,$(i))			\
    -Wl,-rpath -Wl,$(call installed_lib_fn,$(i)))

# As above for include files
installed_include_fn = $(call package_install_dir_fn,$(1))/include

installed_includes_fn = $(foreach i,$(1),-I$(call installed_include_fn,$(i)))

# By default package CPPFLAGS (to set include path -I) and LDFLAGS (to set link path -L)
# point at dependent install directories.
DEFAULT_CPPFLAGS = $(call installed_includes_fn, $(PACKAGE_DEPENDENCIES))
DEFAULT_LDFLAGS = $(call installed_libs_fn, $(PACKAGE_DEPENDENCIES))

configure_var_fn = \
  $(call tag_var_with_added_space_fn,$(1))$(call override_var_with_default_fn,$(PACKAGE)_$(1),$(DEFAULT_$(1)))
configure_ldflags_fn = \
  $(cross_ldflags)$(call configure_var_fn,LDFLAGS)

# Allow packages to override CPPFLAGS, CFLAGS, and LDFLAGS
CONFIGURE_ENV =								\
    $(if $(call configure_var_fn,CPPFLAGS),				\
	 CPPFLAGS="$(CPPFLAGS) $(call configure_var_fn,CPPFLAGS)")	\
    $(if $(call configure_var_fn,CXXFLAGS),				\
	 CXXFLAGS="$(CXXFLAGS) $(call configure_var_fn,CXXFLAGS)")	\
    $(if $(call configure_var_fn,CFLAGS),				\
	 CFLAGS="$(CFLAGS) $(call configure_var_fn,CFLAGS)")		\
    $(if $(call configure_var_fn,CCASFLAGS),				\
	 CCASFLAGS="$(CCASFLAGS) $(call configure_var_fn,CCASFLAGS)")	\
    $(if $(call configure_ldflags_fn),					\
	 LDFLAGS="$(LDFLAGS) $(call configure_ldflags_fn)")		\
    $(if $($(PACKAGE)_configure_env),$($(PACKAGE)_configure_env))

# only partially used now (used in a few .mk files)
ifeq ($(is_build_tool),yes)
prefix     = $(PACKAGE_INSTALL_DIR)
libdir     = $(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)
libexecdir = $(PACKAGE_INSTALL_DIR)/usr/libexec
DESTDIR     = /
else
# Eventually simplify this with no per package DESTDIR or prefix
ppdMacro = $(if $(PER_PACKAGE_DESTDIR),$(call package_build_dir_fn,$(1)))
pppMacro = $(if $(PER_PACKAGE_PREFIX),$(call package_build_dir_fn,$(1)))
prefixMacro     = $($(PLATFORM)_PREFIX_BASE)/$(pppMacro)
prefix = $(call prefixMacro,$(PACKAGE))
libdir     = $($(PLATFORM)_LIBDIR)
libexecdir = $($(PLATFORM)_LIBEXECDIR)
destdirMacro  = $($(PLATFORM)_DESTDIR_BASE)$(ppdMacro)
DESTDIR  = $(call destdirMacro,$(PACKAGE))
endif

configure_package_gnu =						\
  s=$(call find_source_fn,$(PACKAGE_SOURCE))$(PACKAGE_SUBDIR) ;	\
  if [ ! -f $$s/configure ] ; then				\
    autoreconf -i -f $$s ;					\
  fi ;								\
  cd $(PACKAGE_BUILD_DIR) ;					\
  env $(CONFIGURE_ENV)						\
    $$s/configure						\
      $(if $($(PACKAGE)_configure_host_and_target),		\
           $($(PACKAGE)_configure_host_and_target),		\
           $(if $(not_native),--host=$(TARGET),))		\
      $(if $($(PACKAGE)_configure_prefix),			\
           $($(PACKAGE)_configure_prefix),			\
           --libdir=$(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)	\
           --prefix=$(PACKAGE_INSTALL_DIR))			\
      $($(PACKAGE)_configure_args) 				\
      $($(PACKAGE)_configure_args_$(PLATFORM))

configure_package =							\
  $(call build_msg_fn,Configuring $(PACKAGE) in $(PACKAGE_BUILD_DIR)) ;	\
  mkdir -p $(PACKAGE_BUILD_DIR) ;					\
  $(if $($(PACKAGE)_configure),						\
       $($(PACKAGE)_configure),						\
       $(configure_package_gnu))

# Tools (e.g. gcc, binutils, gdb) required a platform to build for
check_platform =								\
  is_tool="$(is_build_tool)" ;							\
  is_cross_package="$(findstring $(PACKAGE),$(CROSS_TOOLS))" ;			\
  is_arch_native="$(if $(subst native,,$(ARCH)),,yes)" ;			\
  if [ "$${is_tool}" == "yes"							\
       -a "$${is_cross_package}" != ""						\
       -a "$${is_arch_native}" != "" ]; then					\
    $(call build_msg_fn,You must specify PLATFORM for building tools) ;		\
    exit 1 ;									\
  fi ;										\
  : check that platform gcc can be found ;					\
  target_gcc=gcc ;								\
  if [ "$${is_arch_native}" != "yes" ] ; then					\
    target_gcc=$(TARGET)-gcc ;							\
  fi ;										\
  if [ "$${is_tool}" != "yes"							\
       -a "$${is_arch_native}" != "yes"						\
       -a ! -x "`which 2> /dev/null $${target_gcc}`" ] ; then			\
    $(call build_msg_fn,							\
	   No cross-compiler found for platform $(PLATFORM) target $(TARGET);	\
	     try make PLATFORM=$(PLATFORM) install-tools) ;			\
    exit 1 ;									\
  fi

configure_check_timestamp =						\
  @$(BUILD_ENV) ;							\
  $(check_platform) ;							\
  mkdir -p $(PACKAGE_BUILD_DIR) ;					\
  mkdir -p $(PACKAGE_INSTALL_DIR) ;					\
  conf="$(TIMESTAMP_DIR)/$(CONFIGURE_TIMESTAMP)" ;			\
  dirs="$(call package_mk_fn,$(PACKAGE))				\
	$(SOURCE_PATH_BUILD_DATA_DIRS)/platforms/$(PLATFORM).mk		\
	$(wildcard $(call find_source_fn,$(PACKAGE_SOURCE))/cmake)	\
	$(shell find $(call find_source_fn,$(PACKAGE_SOURCE))		\
			-name CMakeLists.txt)				\
	$(wildcard $(call find_source_fn,				\
	             $(PACKAGE_SOURCE))$(PACKAGE_SUBDIR)/configure)	\
       $(MU_BUILD_ROOT_DIR)/config.site" ;				\
  if [[ $(call find_newer_fn, $${conf}, $${dirs}, $?) ]]; then		\
    $(configure_package) ;						\
    touch $${conf} ;							\
  else									\
    $(call build_msg_fn,Configuring $(PACKAGE): nothing to do) ;	\
  fi

.PHONY: %-configure
%-configure: %-find-source
	$(configure_check_timestamp)

######################################################################
# Package build
######################################################################

# /proc/cpuinfo does not exist on platforms without a /proc and on some
# platforms, notably inside containers, it has no content. In those cases
# we assume there's 1 processor; we use 2*ncpu for the -j option.
# NB: GNU Make 4.2 will let us use '$(file </proc/cpuinfo)' to both test
# for file presence and content; for now this will have to do.
ifndef MAKE_PARALLEL_JOBS
MAKE_PARALLEL_JOBS = $(if $(shell [ -f /proc/cpuinfo ] && head /proc/cpuinfo), \
	$(shell grep -c ^processor /proc/cpuinfo), 2)
endif
MAKE_PARALLEL_FLAGS ?= $(if $($(PACKAGE)_make_parallel_fails),,-j $(MAKE_PARALLEL_JOBS))

# Make command shorthand for packages & tools.
PACKAGE_MAKE =					\
  $(MAKE)					\
    -C $(PACKAGE_BUILD_DIR)			\
    $($(PACKAGE)_make_args)			\
    $(MAKE_PARALLEL_FLAGS)

build_package =							\
  $(call build_msg_fn,Building $* in $(PACKAGE_BUILD_DIR)) ;	\
  mkdir -p $(PACKAGE_BUILD_DIR) ;				\
  cd $(PACKAGE_BUILD_DIR) ;					\
  $(if $($(PACKAGE)_build),					\
       $($(PACKAGE)_build),					\
       $(PACKAGE_MAKE))

build_check_timestamp =									\
  @$(BUILD_ENV) ;									\
  comp="$(TIMESTAMP_DIR)/$(BUILD_TIMESTAMP)" ;						\
  conf="$(TIMESTAMP_DIR)/$(CONFIGURE_TIMESTAMP)" ;					\
  dirs="$(call find_source_fn,$(PACKAGE_SOURCE))					\
	$($(PACKAGE)_build_timestamp_depends)						\
	$(if $(is_build_tool),,$(addprefix $(INSTALL_DIR)/,$(PACKAGE_DEPENDENCIES)))" ;	\
  if [[ $${conf} -nt $${comp}								\
        || $(call find_newer_fn, $${comp}, $${dirs}, $?) ]]; then			\
    $(build_package) ;									\
    touch $${comp} ;									\
  else											\
    $(call build_msg_fn,Building $(PACKAGE): nothing to do) ;				\
  fi

.PHONY: %-build
%-build: %-configure
	$(build_check_timestamp)

.PHONY: %-rebuild
%-rebuild: %-wipe %-build
	@ :

######################################################################
# Package install
######################################################################

install_package =								\
    : by default, for non-tools, remove any previously installed bits ;		\
    $(if $(is_build_tool)$($(PACKAGE)_keep_instdir),				\
         true,									\
         rm -rf $(PACKAGE_INSTALL_DIR));					\
    mkdir -p $(PACKAGE_INSTALL_DIR) ;						\
    $(if $($(PACKAGE)_pre_install),$($(PACKAGE)_pre_install),true);		\
    $(if $($(PACKAGE)_install),							\
	 $($(PACKAGE)_install),							\
	 $(PACKAGE_MAKE)							\
	    $($(PACKAGE)_install_args)						\
	    install) ;								\
    $(if $($(PACKAGE)_post_install),$($(PACKAGE)_post_install),true)

install_check_timestamp =					\
  @$(BUILD_ENV) ;						\
  inst=$(TIMESTAMP_DIR)/$(INSTALL_TIMESTAMP) ;			\
  dirs="$(PACKAGE_BUILD_DIR)					\
	$($(PACKAGE)_install_dependencies)" ;			\
  if [[ $(call find_newer_fn, $${inst}, $${dirs}, $?) ]]; then	\
    $(call build_msg_fn,Installing $(PACKAGE)) ;		\
    $(install_package) ;					\
    touch $${inst} ;						\
  else								\
    $(call build_msg_fn,Installing $(PACKAGE): nothing to do) ;	\
  fi

.PHONY: %-install
%-install: %-build
	$(install_check_timestamp)

######################################################################
# Source code managment
######################################################################

GIT = git

# Maps package name to source directory root.
# Multiple packages may use a single source tree.
# For example, gcc-bootstrap package shares gcc source.
PACKAGE_SOURCE = $(if $($(PACKAGE)_source),$($(PACKAGE)_source),$(PACKAGE))
PACKAGE_SUBDIR = $(if $($(PACKAGE)_configure_subdir),/$($(PACKAGE)_configure_subdir),)

# Use git to download source if directory is not found
find_source_for_package =									\
  @$(BUILD_ENV) ;										\
  $(call build_msg_fn,Arch for platform '$(PLATFORM)' is $(ARCH)) ;				\
  $(call build_msg_fn,Finding source for $(PACKAGE)) ;						\
  s="$(call find_source_fn,$(PACKAGE_SOURCE))" ;						\
  [[ -z "$${s}" ]]										\
    && $(call build_msg_fn,Package $(PACKAGE) not found with path $(SOURCE_PATH))		\
    && exit 1;											\
  mk="$(call find_build_data_dir_for_package_fn,$(PACKAGE_SOURCE))/packages/$(PACKAGE).mk";	\
  $(call build_msg_fn,Makefile fragment found in $${mk}) ;					\
  if [ ! -d "$${s}" ] ; then									\
    d=`dirname $${mk}` ;									\
    i=`cd $${d}/.. && ($(GIT) config remote.origin.url ||					\
                    awk '/URL/ { print $$2; }' .git/remotes/origin)`;				\
    g=`dirname $${i}` ;										\
    $(call build_msg_fn,Fetching source: $(GIT) clone $${g}/$(PACKAGE_SOURCE) $$s) ;		\
    if ! $(GIT) clone $${g}/$(PACKAGE_SOURCE) $$s; then						\
      $(call build_msg_fn,No source for $(PACKAGE) in $${g});					\
      exit 1;											\
    fi ;											\
    $(call build_msg_fn,Fix file dates in $${g}/$(PACKAGE_SOURCE)) ;					\
    : the timestamp-adjustment script used to be invoked at this point ;			\
  fi ;												\
  s=`cd $${s} && pwd` ;										\
  $(call build_msg_fn,Source found in $${s})

.PHONY: %-find-source
%-find-source:
	$(find_source_for_package)

.PHONY: %-push %-pull %-push-all %-pull-all
%-push %-pull %-push-all %-pull-all:
	@$(BUILD_ENV) ;								\
	push_or_pull=$(patsubst %-all,%,$(subst $(PACKAGE)-,,$@)) ;		\
	$(call build_msg_fn,Git $${push_or_pull} source for $(PACKAGE)) ;	\
	s=$(call find_source_fn,$(PACKAGE_SOURCE)) ;				\
	if [ "x$$s" = "x" ]; then						\
	     $(call build_msg_fn,No source for $(PACKAGE)) ;			\
	     exit 1;								\
	fi ;									\
	cd $$s && $(GIT) $${push_or_pull}

# Pull all packages for platform
.PHONY: pull-all
pull-all:
	@$(BUILD_ENV) ;								\
	$(call build_msg_fn,Git pull build system) ;				\
	for d in $(MU_BUILD_ROOT_DIR)						\
		 $(SOURCE_PATH_BUILD_ROOT_DIRS)					\
	 	 $(SOURCE_PATH_BUILD_DATA_DIRS); do				\
	  $(call build_msg_fn,Git pull $${d}) ;					\
	  pushd $${d} >& /dev/null && $(GIT) pull && popd >& /dev/null ;	\
	done ;									\
	$(call build_msg_fn,Git pull build tools) ;				\
	$(call tool_make_target_fn,pull-all) ;					\
	$(call build_msg_fn,Git pull packages for platform $(PLATFORM)) ;	\
	make PLATFORM=$(PLATFORM) $(patsubst %,%-pull-all,$(ROOT_PACKAGES))

.PHONY: %-diff
%-diff:
	@$(BUILD_ENV) ;							\
	d=$(call find_source_fn,$(PACKAGE_SOURCE)) ;			\
	$(call build_msg_fn,Git diff $(PACKAGE)) ;			\
	if [ -d $${d}/.git ] ; then 					\
	 cd $${d} && $(GIT) --no-pager diff 2>/dev/null; 		\
        else								\
	 $(call build_msg_fn, $(PACKAGE) not a git directory) ;		\
	fi



# generate diffs for everything in source path
.PHONY: diff-all
diff-all:
	@$(BUILD_ENV) ;							\
	$(call build_msg_fn,Generate diffs) ;				\
	for r in $(ABSOLUTE_SOURCE_PATH); do				\
	  for d in $${r}/* ; do						\
	    if [ -d $${d} ] ; then					\
	      $(call build_msg_fn,Git diff $${d}) ;			\
	      if [ -d $${d}/.git ] ; then				\
		cd $${d} && $(GIT) --no-pager diff 2>/dev/null;		\
	      else							\
		$(call build_msg_fn, $${d} not a git directory) ;	\
	      fi ;							\
	    fi ; 							\
	  done ;							\
	done

######################################################################
# System images
######################################################################

IMAGE_DIR = $(MU_BUILD_ROOT_DIR)/image-$(PLATFORM)

# Reports shared libraries in given directory
find_shared_libs_fn =				\
  find $(1)					\
    -maxdepth 1					\
       -regex '.*/lib[a-z0-9_]+\+?\+?.so'		\
    -o -regex '.*/lib[a-z0-9_]+-[0-9.]+\+?\+?.so'	\
    -o -regex '.*/lib[a-z0-9_]+\+?\+?.so.[0-9.]+'

# By default pick up files from binary directories and /etc.
# Also include shared libraries.
DEFAULT_IMAGE_INCLUDE =					\
  for d in bin sbin libexec				\
           usr/bin usr/sbin usr/libexec			\
           etc; do					\
    [[ -d $$d ]] && echo $$d;				\
  done ;						\
  [[ -d $(arch_lib_dir) ]]				\
    && $(call find_shared_libs_fn,$(arch_lib_dir))

# Define any shell functions needed by install scripts
image_install_functions =			\
  $(foreach p,$(ALL_PACKAGES),			\
    $(if $($(p)_image_install_functions),	\
	 $($(p)_image_install_functions)))

# Should always be over-written by temp dir in %-root-image rule
IMAGE_INSTALL_DIR = $(error you need to set IMAGE_INSTALL_DIR)

image_install_fn =								\
  @$(BUILD_ENV) ;								\
  $(call build_msg_fn,Image-install $(1) for platform $(PLATFORM)) ;		\
  inst_dir=$(IMAGE_INSTALL_DIR) ;						\
  mkdir -p $${inst_dir} ;							\
  cd $(2) ;									\
  : select files to include in image ;						\
  image_include_files="								\
    `$(call ifdef_fn,$(1)_image_include,$(DEFAULT_IMAGE_INCLUDE)) ;		\
     echo "" ;									\
     exit 0 ; `";								\
  : select files regexps to exclude from image ;				\
  image_exclude_files="" ;							\
  if [ ! -z "$($(1)_image_exclude)" ] ; then					\
    image_exclude_files="${image_exclude_files}					\
                         $(patsubst %,--exclude=%,$($(1)_image_exclude))" ;	\
  fi ;										\
  [[ -z "$${image_include_files}" || $${image_include_files} == " " ]]		\
    || tar cf - $${image_include_files} $${image_exclude_files}			\
       | tar xf - -C $${inst_dir} ;						\
  : copy files from copyimg directories on source path if present ;		\
  for build_data_dir in $(SOURCE_PATH_BUILD_DATA_DIRS) ; do			\
    d="$${build_data_dir}/packages/$(1).copyimg" ;				\
    if [ -d "$${d}" ] ; then							\
      env $($(PLATFORM)_copyimg_env)						\
	$(MU_BUILD_ROOT_DIR)/copyimg $${d} $${inst_dir} ;			\
    fi ;									\
  done ;									\
  : run package dependent install script ;					\
  $(if $($(1)_image_install),							\
       $(image_install_functions)						\
       cd $${inst_dir} ;							\
       $($(1)_image_install))

.PHONY: %-image_install
%-image_install: %-install
	$(call image_install_fn,$(PACKAGE),$(PACKAGE_INSTALL_DIR))

basic_system_image_include =					\
  $(call ifdef_fn,$(PLATFORM)_basic_system_image_include, 	\
  echo bin/ldd ;						\
  echo $(arch_lib_dir)/ld*.so* ;				\
  $(call find_shared_libs_fn, $(arch_lib_dir)))

basic_system_image_install =				\
  mkdir -p bin lib mnt proc root sbin sys tmp etc ;	\
  mkdir -p usr usr/{bin,sbin} usr/lib ;			\
  mkdir -p var var/{lib,lock,log,run,tmp} ;		\
  mkdir -p var/lock/subsys var/lib/urandom

.PHONY: basic_system-image_install
basic_system-image_install: # linuxrc-install
	$(if $(not_native),							\
	     $(call image_install_fn,basic_system,$(TARGET_TOOL_INSTALL_DIR)),)

ROOT_PACKAGES = $(if $($(PLATFORM)_root_packages),$($(PLATFORM)_root_packages),$(default_root_packages))

.PHONY: install-packages
install-packages: $(patsubst %,%-find-source,$(ROOT_PACKAGES))
	@$(BUILD_ENV) ;							        \
	set -eu$(BUILD_DEBUG) ;							\
	d=$(MU_BUILD_ROOT_DIR)/packages-$(PLATFORM) ;				\
	rm -rf $${d} ;								\
	mkdir -p $${d};								\
	$(MAKE) -C $(MU_BUILD_ROOT_DIR) IMAGE_INSTALL_DIR=$${d}			\
	    $(patsubst %,%-image_install,					\
	      basic_system							\
	      $(ROOT_PACKAGES))	|| exit 1;					\
	$(call build_msg_fn, Relocating ELF executables to run in $${d}) ;	\
	scripts/set-rpath $${d} $${d}/$(arch_lib_dir) ;				\
	: strip symbols from files ;						\
	if [ $${strip_symbols:-no} = 'yes' ] ; then				\
	    $(call build_msg_fn, Stripping symbols from files) ;		\
	    find $${d} -type f							\
		-exec								\
		  $(TARGET_PREFIX)strip						\
		    --strip-unneeded '{}' ';'					\
		    >& /dev/null ;						\
	else									\
	    $(call build_msg_fn, NOT stripping symbols) ;			\
	fi

# readonly root squashfs image
# Note: $(call build_msg_fn) does not seem to work inside of fakeroot so we use echo
.PHONY: ro-image
$(PLATFORM_IMAGE_DIR)/ro.img ro-image: $(patsubst %,%-find-source,$(ROOT_PACKAGES))
	@$(BUILD_ENV) ;							\
	d=$(PLATFORM_IMAGE_DIR) ;					\
	mkdir -p $$d;							\
	ro_image=$$d/ro.img ;						\
	rm -f $${ro_image} ;						\
	tmp_dir="`mktemp -d $$d/ro-image-XXXXXX`" ;			\
	chmod 0755 $${tmp_dir} ;					\
	cd $${tmp_dir} ;						\
	trap "rm -rf $${tmp_dir}" err ;					\
	fakeroot /bin/bash -c "{					\
	  set -eu$(BUILD_DEBUG) ;					\
	  $(MAKE) -C $(MU_BUILD_ROOT_DIR) IMAGE_INSTALL_DIR=$${tmp_dir}	\
	    $(patsubst %,%-image_install,				\
	      basic_system						\
	      $(ROOT_PACKAGES)) ;					\
	  : make dev directory ;					\
	  $(linuxrc_makedev) ;						\
	  echo @@@@ Relocating ELF executables to run in / @@@@ ;	\
	  scripts/set-rpath /$(arch_lib_dir):/lib ;			\
	  : strip symbols from files ;					\
	  if [ '$${strip_symbols:-yes}' = 'yes' ] ; then		\
	      echo @@@@ Stripping symbols from files @@@@ ;		\
	      find $${tmp_dir} -type f					\
		-exec							\
		  $(TARGET_PREFIX)strip					\
		    --strip-unneeded '{}' ';'				\
		    >& /dev/null ;					\
	  else								\
	      echo @@@@ NOT stripping symbols @@@@ ;			\
	  fi ;								\
	  if [ $${sign_executables:-yes} = 'yes'			\
	       -a -n "$($(PLATFORM)_public_key)" ] ; then		\
	      echo @@@@ Signing executables @@@@ ;			\
	      find $${tmp_dir} -type f					\
		| xargs sign $($(PLATFORM)_public_key)			\
			     $($(PLATFORM)_private_key_passphrase) ;	\
	  fi ;								\
	  : make read-only file system ;				\
	  mksquashfs							\
	    $${tmp_dir} $${ro_image}					\
	    -no-exports -no-progress -no-recovery ;			\
	}" ;								\
	: cleanup tmp directory ;					\
	rm -rf $${tmp_dir}

MKFS_JFFS2_BYTE_ORDER_x86_64 = -l
MKFS_JFFS2_BYTE_ORDER_i686 = -l
MKFS_JFFS2_BYTE_ORDER_ppc = -b
MKFS_JFFS2_BYTE_ORDER_mips = -b
MKFS_JFFS2_BYTE_ORDER_native = $(MKFS_JFFS2_BYTE_ORDER_$(NATIVE_ARCH))

MKFS_JFFS2_SECTOR_SIZE_IN_KBYTES = \
  $(call ifdef_fn,$(PLATFORM)_jffs2_sector_size_in_kbytes,256)

mkfs_fn_jffs2 = mkfs.jffs2				\
  --eraseblock=$(MKFS_JFFS2_SECTOR_SIZE_IN_KBYTES)KiB	\
  --root=$(1) --output=$(2)				\
  $(MKFS_JFFS2_BYTE_ORDER_$(BASIC_ARCH))

# As things stand the actual initrd size parameter
# is set in .../open-repo/build-data/packages/linuxrc.mk.
EXT2_RW_IMAGE_SIZE=notused

mkfs_fn_ext2 = \
  e2fsimage -d $(1) -f $(2) -s $(EXT2_RW_IMAGE_SIZE)

RW_IMAGE_TYPE=jffs2

make_rw_image_fn = \
  $(call mkfs_fn_$(RW_IMAGE_TYPE),$(1),$(2))

rw_image_embed_ro_image_fn =					\
  mkdir -p proc initrd images ro rw union ;			\
  cp $(PLATFORM_IMAGE_DIR)/$(1) images/$(1) ;			\
  md5sum images/$(1) > images/$(1).md5 ;			\
  echo Built by $(LOGNAME) at `date` > images/$(1).stamp ;	\
  mkdir -p changes/$(1)

# make sure RW_IMAGE_TYPE is a type we know how to build
.PHONY: rw-image-check-type
rw-image-check-type:
	@$(BUILD_ENV) ;								\
	if [ -z "$(make_rw_image_fn)" ] ; then					\
	  $(call build_msg_fn,Unknown read/write fs image type;			\
		              try RW_IMAGE_TYPE=ext2 or RW_IMAGE_TYPE=jffs2) ;	\
	  exit 1;								\
	fi

# read write image
.PHONY: rw-image
rw-image: rw-image-check-type ro-image
	@$(BUILD_ENV) ;						\
	d=$(PLATFORM_IMAGE_DIR) ;				\
	mkdir -p $$d ;						\
	rw_image="$$d/rw.$(RW_IMAGE_TYPE)" ;			\
	ro_image="ro.img" ;					\
	rm -f $$rw_image ;					\
	tmp_dir="`mktemp -d $$d/rw-image-XXXXXX`" ;		\
	chmod 0755 $${tmp_dir} ;				\
	cd $${tmp_dir} ;					\
	trap "rm -rf $${tmp_dir}" err ;				\
	fakeroot /bin/bash -c "{				\
	  set -eu$(BUILD_DEBUG) ;				\
	  $(linuxrc_makedev) ;					\
	  $(call rw_image_embed_ro_image_fn,$${ro_image}) ;	\
	  $(call make_rw_image_fn,$${tmp_dir},$${rw_image}) ;	\
	}" ;							\
	: cleanup tmp directory ;				\
	rm -rf $${tmp_dir}

images: linuxrc-install linux-install $(image_extra_dependencies) rw-image
	@$(BUILD_ENV) ;						\
	d=$(PLATFORM_IMAGE_DIR) ;				\
	cd $(BUILD_DIR)/linux-$(PLATFORM) ;			\
	i="" ;							\
	[[ -z $$i && -f bzImage ]] && i=bzImage ;		\
	[[ -z $$i && -f zImage ]] && i=zImage ;			\
	[[ -z $$i && -f linux ]] && i=linux ;			\
	[[ -z $$i && -f vmlinux ]] && i=vmlinux ;		\
	[[ -z $$i ]]						\
	  && $(call build_msg_fn,no linux image to install	\
		in $(BUILD_DIR)/linux-$(PLATFORM))		\
	  && exit 1 ;						\
	cp $$i $$d

######################################################################
# Tool chain build/install
######################################################################

.PHONY: ccache-install
ccache-install:
	$(MAKE) -C $(MU_BUILD_ROOT_DIR)	ccache-build
	mkdir -p $(TOOL_INSTALL_DIR)/ccache-bin
	ln -sf $(MU_BUILD_ROOT_DIR)/build-tool-native/ccache/ccache \
		$(TOOL_INSTALL_DIR)/ccache-bin/$(TARGET_PREFIX)gcc

TOOL_MAKE = $(MAKE) is_build_tool=yes

tool_make_target_fn = 							\
  $(if $(strip $(NATIVE_TOOLS)),					\
    $(TOOL_MAKE) $(patsubst %,%-$(1),$(NATIVE_TOOLS)) ARCH=native || exit 1 ;) \
  $(TOOL_MAKE) $(patsubst %,%-$(1),$(CROSS_TOOLS))

.PHONY: install-tools
install-tools:
	$(call tool_make_target_fn,install)

.PHONY: bootstrap-tools
bootstrap-tools:
	$(TOOL_MAKE) make-install findutils-install git-install \
	automake-install autoconf-install libtool-install fakeroot-install


######################################################################
# Clean
######################################################################

package_clean_script =							\
  @$(call build_msg_fn, Cleaning $* in $(PACKAGE_INSTALL_DIR)) ;	\
  $(BUILD_ENV) ;							\
  $(if $(is_build_tool),,rm -rf $(PACKAGE_INSTALL_DIR) ;)		\
  rm -rf $(TIMESTAMP_DIR)/$(call timestamp_name_fn,*) ;			\
  $(if $($(PACKAGE)_clean),						\
    $($(PACKAGE)_clean),						\
    $(PACKAGE_MAKE) clean)

.PHONY: %-clean
%-clean:
	$(package_clean_script)

# Wipe e.g. remove build and install directories for packages.
package_wipe_script =											\
  @message=$(if $(is_build_tool),"Wiping build $(PACKAGE)","Wiping build/install $(PACKAGE)") ;		\
  $(call build_msg_fn,$$message) ;									\
  $(BUILD_ENV) ;											\
  rm -rf $(if $(is_build_tool),$(PACKAGE_BUILD_DIR),$(PACKAGE_INSTALL_DIR) $(PACKAGE_BUILD_DIR))

.PHONY: %-wipe
%-wipe:
	$(package_wipe_script)

# Wipe entire build/install area for TAG and PLATFORM
.PHONY: wipe-all
wipe-all:
	@$(call build_msg_fn, Wiping $(BUILD_DIR) $(INSTALL_DIR)) ;	\
	$(BUILD_ENV) ;							\
	rm -rf $(BUILD_DIR) $(INSTALL_DIR)

# Clean everything
distclean:
	rm -rf $(MU_BUILD_ROOT_DIR)/$(BUILD_PREFIX_package)*/
	rm -rf $(MU_BUILD_ROOT_DIR)/$(BUILD_PREFIX_tool)*
	rm -rf $(MU_BUILD_ROOT_DIR)/$(INSTALL_PREFIX)*
	rm -rf $(MU_BUILD_ROOT_DIR)/$(IMAGES_PREFIX)*
	rm -rf $(TOOL_INSTALL_DIR)
	rm -rf $(MU_BUILD_ROOT_DIR)/*.deb
	rm -rf $(MU_BUILD_ROOT_DIR)/*.rpm
	rm -rf $(MU_BUILD_ROOT_DIR)/*.changes
	rm -rf $(MU_BUILD_ROOT_DIR)/*.buildinfo
