Introduction to build-root/Makefile
===================================

The vpp build system consists of a top-level Makefile, a data-driven
build-root/Makefile, and a set of makefile fragments. The various parts
come together as the result of a set of well-thought-out conventions.

This section describes build-root/Makefile in some detail.

Repository Groups and Source Paths
----------------------------------

Current vpp workspaces comprise a single repository group. The file
.../build-root/build-config.mk defines a key variable called
SOURCE\_PATH. The SOURCE\_PATH variable names the set of repository
groups. At the moment, there is only one repository group.

Single pass build system, dependencies and components
-----------------------------------------------------

The vpp build system caters to components built with GNU autoconf /
automake. Adding such components is a simple process. Dealing with
components which use BSD-style raw Makefiles is a more difficult.
Dealing with toolchain components such as gcc, glibc, and binutils can
be considerably more complicated.

The vpp build system is a **single-pass** build system. A partial order
must exist for any set of components: the set of (a before b) tuples
must resolve to an ordered list. If you create a circular dependency of
the form; (a,b) (b,c) (c,a), gmake will try to build the target list,
but there’s a 0.0% chance that the results will be pleasant. Cut-n-paste
mistakes in .../build-data/packages/.mk can produce confusing failures.

In a single-pass build system, it’s best to separate libraries and
applications which instantiate them. For example, if vpp depends on
libfoo.a, and myapp depends on both vpp and libfoo.a, it's best to place
libfoo.a and myapp in separate components. The build system will build
libfoo.a, vpp, and then (as a separate component) myapp. If you try to
build libfoo.a and myapp from the same component, it won’t work.

If you absolutely, positively insist on having myapp and libfoo.a in the
same source tree, you can create a pseudo-component in a separate .mk
file in the .../build-data/packages/ directory. Define the code
phoneycomponent\_source = realcomponent, and provide manual
configure/build/install targets.

Separate components for myapp, libfoo.a, and vpp is the best and easiest
solution. However, the “mumble\_source = realsource” degree of freedom
exists to solve intractable circular dependencies, such as: to build
gcc-bootstrap, followed by glibc, followed by “real” gcc/g++ [which
depends on glibc too].

.../build-root
--------------

The .../build-root directory contains the repository group specification
build-config.mk, the main Makefile, and the system-wide set of
autoconf/automake variable overrides in config.site. We'll describe
these files in some detail. To be clear about expectations: the main
Makefile and config.site file are subtle and complex. It's unlikely that
you'll need or want to modify them. Poorly planned changes in either
place typically cause bugs that are difficult to solve.

.../build-root/build-config.mk
------------------------------

As described above, the build-config.mk file is straightforward: it sets
the make variable SOURCE\_PATH to a list of repository group absolute
paths.

The SOURCE\_PATH variable If you choose to move a workspace, make sure
to modify the paths defined by the SOURCE\_PATH variable. Those paths
need to match changes you make in the workspace paths. For example, if
you place the vpp directory in the workspace of a user named jsmith, you
might change the SOURCE\_PATH to:

SOURCE\_PATH = /home/jsmithuser/workspace/vpp

The "out of the box" setting should work 99.5% of the time:

::

        SOURCE_PATH = $(CURDIR)/..

.../vpp/build-root/Makefile
---------------------------

The main Makefile is complex in a number of dimensions. If you think you
need to modify it, it's a good idea to do some research, or ask for
advice before you change it.

The main Makefile was organized and designed to provide the following
characteristics: excellent performance, accurate dependency processing,
cache enablement, timestamp optimizations, git integration,
extensibility, builds with cross-compilation tool chains, and builds
with embedded Linux distributions.

If you really need to do so, you can build double-cross tools with it,
with a minimum amount of fuss. For example, you could: compile gdb on
x86\_64, to run on PowerPC, to debug the Xtensa instruction set.

The PLATFORM variable
---------------------

The PLATFORM make/environment variable controls a number of important
characteristics, primarily:

-  CPU architecture
-  The list of images to build.

With respect to .../build-root/Makefile, the list of images to build is
specified by the target. For example:

::

       make PLATFORM=vpp TAG=vpp_debug install-deb

builds vpp debug Debian packages.

The main Makefile interprets $PLATFORM by attempting to "-include" the
file /build-data/platforms.mk:

::

        $(foreach d,$(FULL_SOURCE_PATH), \
          $(eval -include $(d)/platforms.mk))

By convention, we don't define **platforms** in the
...//build-data/platforms.mk file.

In the vpp case, we search for platform definition makefile fragments in
.../vpp/build-data/platforms.mk, as follows:

::

        $(foreach d,$(SOURCE_PATH_BUILD_DATA_DIRS), \
             $(eval -include $(d)/platforms/*.mk))

With vpp, which uses the "vpp" platform as discussed above, we end up
"-include"-ing .../vpp/build-data/platforms/vpp.mk.

The platform-specific .mk fragment
----------------------------------

Here are the contents of .../build-data/platforms/vpp.mk:

::

        MACHINE=$(shell uname -m)
     
        vpp_arch = native
        ifeq ($(TARGET_PLATFORM),thunderx)
        vpp_dpdk_target = arm64-thunderx-linuxapp-gcc
        endif
        vpp_native_tools = vppapigen
     
        vpp_uses_dpdk = yes
     
        # Uncomment to enable building unit tests
        # vpp_enable_tests = yes
     
        vpp_root_packages = vpp
     
        # DPDK configuration parameters
        # vpp_uses_dpdk_mlx4_pmd = yes
        # vpp_uses_dpdk_mlx5_pmd = yes
        # vpp_uses_external_dpdk = yes
        # vpp_dpdk_inc_dir = /usr/include/dpdk
        # vpp_dpdk_lib_dir = /usr/lib
        # vpp_dpdk_shared_lib = yes
     
        # Use '--without-libnuma' for non-numa aware architecture
        # Use '--enable-dlmalloc' to use dlmalloc instead of mheap
        vpp_configure_args_vpp = --enable-dlmalloc
        sample-plugin_configure_args_vpp = --enable-dlmalloc
     
        # load balancer plugin is not portable on 32 bit platform
        ifeq ($(MACHINE),i686)
        vpp_configure_args_vpp += --disable-lb-plugin
        endif
     
        vpp_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG \
            -fstack-protector-all -fPIC -Werror
        vpp_debug_TAG_CXXFLAGS = -g -O0 -DCLIB_DEBUG \
            -fstack-protector-all -fPIC -Werror
        vpp_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG \
            -fstack-protector-all -fPIC -Werror

        vpp_TAG_CFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
        vpp_TAG_CXXFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
        vpp_TAG_LDFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror -pie -Wl,-z,now

        vpp_clang_TAG_CFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
        vpp_clang_TAG_LDFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror

        vpp_gcov_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -fPIC -Werror -fprofile-arcs -ftest-coverage
        vpp_gcov_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -fPIC -Werror -coverage

        vpp_coverity_TAG_CFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__
        vpp_coverity_TAG_LDFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__

Note the following variable settings:

-  The variable \_arch sets the CPU architecture used to build the
   per-platform cross-compilation toolchain. With the exception of the
   "native" architecture - used in our example - the vpp build system
   produces cross-compiled binaries.

-  The variable \_native\_tools lists the required set of self-compiled
   build tools.

-  The variable \_root\_packages lists the set of images to build when
   specifying the target: make PLATFORM= TAG= [install-deb \|
   install-rpm].

The TAG variable
----------------

The TAG variable indirectly sets CFLAGS and LDFLAGS, as well as the
build and install directory names in the .../vpp/build-root directory.
See definitions above.

Important targets build-root/Makefile
-------------------------------------

The main Makefile and the various makefile fragments implement the
following user-visible targets:

+------------------+----------------------+--------------------------------------------------------------------------------------+
| Target           | ENV Variable Settings| Notes                                                                                |
|                  |                      |                                                                                      |
+==================+======================+======================================================================================+
| foo              |      bar             | mumble                                                                               |
+------------------+----------------------+--------------------------------------------------------------------------------------+
| bootstrap-tools  | none                 |  Builds the set of native tools needed by the vpp build system to                    |
|                  |                      |  build images. Example: vppapigen. In a full cross compilation case might include    |
|                  |                      |  include "make", "git", "find", and "tar                                             |  
+------------------+----------------------+--------------------------------------------------------------------------------------+  
| install-tools    | PLATFORM             | Builds the tool chain for the indicated <platform>. Not used in vpp builds           |
+------------------+----------------------+--------------------------------------------------------------------------------------+  
| distclean        | none                 | Roto-rooters everything in sight: toolchains, images, and so forth.                  |
+------------------+----------------------+--------------------------------------------------------------------------------------+  
| install-deb      | PLATFORM and TAG     | Build Debian packages comprising components listed in <platform>_root_packages,      |
|                  |                      | using compile / link options defined by TAG.                                         |
+------------------+----------------------+--------------------------------------------------------------------------------------+  
| install-rpm      | PLATFORM and TAG     | Build RPMs comprising components listed in <platform>_root_packages,                 |
|                  |                      | using compile / link options defined by TAG.                                         |
+------------------+----------------------+--------------------------------------------------------------------------------------+  

Additional build-root/Makefile environment variable settings
------------------------------------------------------------

These variable settings may be of use:

+----------------------+------------------------------------------------------------------------------------------------------------+
| ENV Variable         | Notes                                                                                                      |
+======================+======================+=====================================================================================+
| BUILD_DEBUG=vx       | Directs Makefile et al. to make a good-faith effort to show what's going on in excruciating detail.        |
|                      | Use it as follows: "make ... BUILD_DEBUG=vx". Fairly effective in Makefile debug situations.               |
+----------------------+------------------------------------------------------------------------------------------------------------+  
| V=1                  | print detailed cc / ld command lines. Useful for discovering if -DFOO=11 is in the command line or not     |
+----------------------+------------------------------------------------------------------------------------------------------------+  
| CC=mygcc             | Override the configured C-compiler                                                                         |
+----------------------+------------------------------------------------------------------------------------------------------------+  

.../build-root/config.site
--------------------------

The contents of .../build-root/config.site override individual autoconf /
automake default variable settings. Here are a few sample settings related to
building a full toolchain:

::

    # glibc needs these setting for cross compiling 
    libc_cv_forced_unwind=yes
    libc_cv_c_cleanup=yes
    libc_cv_ssp=no

Determining the set of variables which need to be overridden, and the
override values is a matter of trial and error. It should be
unnecessary to modify this file for use with fd.io vpp.

.../build-data/platforms.mk
---------------------------

Each repo group includes the platforms.mk file, which is included by
the main Makefile. The vpp/build-data/platforms.mk file is not terribly
complex. As of this writing, .../build-data/platforms.mk file accomplishes two
tasks.

First, it includes vpp/build-data/platforms/\*.mk:

::

    # Pick up per-platform makefile fragments
    $(foreach d,$(SOURCE_PATH_BUILD_DATA_DIRS),	\
      $(eval -include $(d)/platforms/*.mk))

This collects the set of platform definition makefile fragments, as discussed above.

Second, platforms.mk implements the user-visible "install-deb" target.

.../build-data/packages/\*.mk
-----------------------------

Each component needs a makefile fragment in order for the build system
to recognize it. The per-component makefile fragments vary
considerably in complexity. For a component built with GNU autoconf /
automake which does not depend on other components, the make fragment
can be empty. See .../build-data/packages/vpp.mk for an uncomplicated
but fully realistic example.

Here are some of the important variable settings in per-component makefile fragments:

+----------------------+------------------------------------------------------------------------------------------------------------+
| Variable             | Notes                                                                                                      |
+======================+======================+=====================================================================================+
| xxx_configure_depend |  Lists the set of component build dependencies for the xxx component. In plain English: don't try to       |
|                      |  configure this component until you've successfully built the indicated targets. Almost always,            |
|                      |  xxx_configure_depend will list a set of "yyy-install" targets. Note the pattern:                          |
|                      |  "variable names contain underscores, make target names contain hyphens"                                   |
+----------------------+------------------------------------------------------------------------------------------------------------+  
| xxx_configure_args   | (optional) Lists any additional arguments to pass to the xxx component "configure" script.                 |
|                      | The main Makefile %-configure rule adds the required settings for --libdir, --prefix, and                  |
|                      | --host (when cross-compiling)                                                                              |
+----------------------+------------------------------------------------------------------------------------------------------------+  
| xxx_CPPFLAGS         | Adds -I stanzas to CPPFLAGS for components upon which xxx depends.                                         |
|                      | Almost invariably "xxx_CPPFLAGS = $(call installed_includes_fn, dep1 dep2 dep3)", where dep1, dep2, and    |
|                      | dep3 are listed in xxx_configure_depend. It is bad practice to set "-g -O3" here. Those settings           |
|                      | belong in a TAG.                                                                                           |
+----------------------+------------------------------------------------------------------------------------------------------------+  
| xxx_LDFLAGS          | Adds -Wl,-rpath -Wl,depN stanzas to LDFLAGS for components upon which xxx depends.                         |
|                      | Almost invariably "xxx_LDFLAGS = $(call installed_lib_fn, dep1 dep2 dep3)", where dep1, dep2, and          |
|                      | dep3 are listed in xxx_configure_depend. It is bad manners to set "-liberty-or-death" here.                |
|                      | Those settings belong in Makefile.am.                                                                      |
+----------------------+------------------------------------------------------------------------------------------------------------+  

When dealing with "irritating" components built with raw Makefiles
which only work when building in the source tree, we use a specific
strategy in the xxx.mk file. 

The strategy is simple for those components: We copy the source tree
into .../vpp/build-root/build-xxx. This works, but completely defeats
dependency processing. This strategy is acceptable only for 3rd party
software which won't need extensive (or preferably any) modifications.

Take a look at .../vpp/build-data/packages/dpdk.mk. When invoked, the
dpdk_configure variable copies source code into $(PACKAGE_BUILD_DIR),
and performs the BSD equivalent of "autoreconf -i -f" to configure the
build area. The rest of the file is similar: a bunch of hand-rolled
glue code which manages to make the dpdk act like a good vpp build
citizen even though it is not. 
