Introduction to cmake and ninja
===============================

Cmake plus ninja is approximately equal to GNU autotools plus GNU
make, respectively. Both cmake and GNU autotools support self and
cross-compilation, checking for required components and versions.

- For a decent-sized project - such as vpp - build performance is drastically better with (cmake, ninja).

- The cmake input language looks like an actual language, rather than a shell scripting scheme on steroids.

- Ninja doesn't pretend to support manually-generated input files. Think of it as a fast, dumb robot which eats mildly legible byte-code.

See the `cmake website <http://cmake.org>`_, and the `ninja website
<https://ninja-build.org>`_ for additional information.

vpp cmake configuration files
-----------------------------

The top of the vpp project cmake hierarchy lives in .../src/CMakeLists.txt.
This file defines the vpp project, and (recursively) includes two kinds
of files: rule/function definitions, and target lists.

- Rule/function definitions live in .../src/cmake/{\*.cmake}. Although the contents of these files is simple enough to read, it shouldn't be necessary to modify them very often

- Build target lists come from CMakeLists.txt files found in subdirectories, which are named in the SUBDIRS list in .../src/CMakeLists.txt

::

    ##############################################################################
    # subdirs - order matters
    ##############################################################################
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
      find_package(OpenSSL REQUIRED)
      set(SUBDIRS
        vppinfra svm vlib vlibmemory vlibapi vnet vpp vat vcl plugins
        vpp-api tools/vppapigen tools/g2 tools/perftool)
    elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
      set(SUBDIRS vppinfra)
    else()
      message(FATAL_ERROR "Unsupported system: ${CMAKE_SYSTEM_NAME}")
    endif()

    foreach(DIR ${SUBDIRS})
      add_subdirectory(${DIR})
    endforeach()

- The vpp cmake configuration hierarchy discovers the list of plugins to be built by searching for subdirectories in .../src/plugins which contain CMakeLists.txt files


::

    ##############################################################################
    # find and add all plugin subdirs
    ##############################################################################
    FILE(GLOB files RELATIVE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
    )
    foreach (f ${files})
      get_filename_component(dir ${f} DIRECTORY)
      add_subdirectory(${dir})
    endforeach()

.. _build_time_options:

Build-time options
------------------

The top-level ``make`` targets configure VPP through CMake. Most VPP
build-time parameters are CMake cache entries, so pass them from the top
level with ``VPP_EXTRA_CMAKE_ARGS``:

::

   $ make build VPP_EXTRA_CMAKE_ARGS='-DVPP_PLUGINS=dpdk,acl -DVPP_DRIVERS=iavf'

For an existing build directory, use ``make rebuild`` or
``make rebuild-release`` after changing these options. The build-root
configure step is timestamp based, and CMake cache values from a previous
configure can otherwise remain in effect.

The CMake configure summary prints the selected ``Plugins``, ``Drivers``,
``Crypto engines``, ``Tools``, and ``Tests`` lists. Unknown requested names,
or names that cannot be registered because their build prerequisites are
missing, fail the configure step.

Selecting plugins, drivers, crypto engines, tools, and tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The allow-list variables below take comma-separated lists. An empty value
means "build the default discovered set". The special value ``none`` disables
that whole class. ``VPP_EXCLUDED_PLUGINS`` is a skip list for the default
plugin set, not an allow-list.

``VPP_PLUGINS``
    Plugins to include in the build. Names are the first argument to
    ``add_vpp_plugin()``, normally the subdirectory name under
    ``src/plugins``. For example:

    ::

       $ make rebuild VPP_EXTRA_CMAKE_ARGS='-DVPP_PLUGINS=dpdk,acl,memif'

``VPP_EXCLUDED_PLUGINS``
    Plugins to skip when building the default plugin set. This one is also
    forwarded directly by ``build-data/packages/vpp.mk``, so it can be passed
    without ``VPP_EXTRA_CMAKE_ARGS``:

    ::

       $ make rebuild VPP_EXCLUDED_PLUGINS=dpdk,rdma

    It can also be passed explicitly as a CMake argument:
    ``VPP_EXTRA_CMAKE_ARGS='-DVPP_EXCLUDED_PLUGINS=dpdk,rdma'``.

``VPP_DRIVERS``
    Device drivers to include in the build. Names are the first argument to
    ``add_vpp_driver()``, normally the subdirectory name under
    ``src/drivers``:

    ::

       $ make rebuild VPP_EXTRA_CMAKE_ARGS='-DVPP_DRIVERS=iavf,ige'

``VPP_CRYPTO_ENGINES``
    Crypto engines to include in the build. Names are the first argument to
    ``add_vpp_crypto_engine()``, normally the subdirectory name under
    ``src/crypto_engines``:

    ::

       $ make rebuild VPP_EXTRA_CMAKE_ARGS='-DVPP_CRYPTO_ENGINES=native,openssl'

``VPP_TOOLS``
    Tools registered with ``add_vpp_tool()`` to include in the build. Some
    tools are also guarded by their own options. For example, ``g2`` requires
    ``VPP_BUILD_G2=ON``:

    ::

       $ make rebuild VPP_EXTRA_CMAKE_ARGS='-DVPP_BUILD_G2=ON -DVPP_TOOLS=g2,vppctl'

``VPP_TESTS``
    Test executables registered with ``add_vpp_test()`` to include in the
    build:

    ::

       $ make rebuild VPP_EXTRA_CMAKE_ARGS='-DVPP_TESTS=test_vat2,vpp_json_test'

``DISABLED_PLUGINS`` is different: it only adds plugin disable entries to
the generated startup configuration used by ``make run`` and ``make debug``.
It does not change which plugins are compiled.

Other common VPP CMake options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These options are also set with ``VPP_EXTRA_CMAKE_ARGS`` unless noted
otherwise:

``VPP_PLATFORM``
    Selects a CMake CPU platform file from ``src/cmake/platform`` or a
    compiler ``-march`` value supported by the target compiler. The top-level
    ``PLATFORM`` make variable is a build-root platform selector and is not
    the same knob.

``VPP_BUILD_NATIVE_ONLY`` and ``VPP_BUILD_NATIVE_ARCH``
    Build only one native CPU variant, using ``-march=native`` by default.

``VPP_USE_LTO``
    Enables link-time optimization for release builds when supported by the
    compiler.

``VPP_ENABLE_SANITIZE_ADDR`` and ``VPP_SANITIZE_ADDR_OPTIONS``
    Build with AddressSanitizer and configure its runtime options.

``VPP_ENABLE_TRAJECTORY_TRACE``
    Builds VPP with buffer trajectory tracing enabled.

``VPP_HOST_TOOLS_ONLY``
    Builds only host tools needed by external projects.

``VPP_BUILD_VCL`` and ``VPP_BUILD_VCL_BAPI``
    Enable or disable VCL and VCL binary API components.

``VPP_BUILD_PYTHON_API``
    Enables or disables the Python API package.

``VPP_BUILD_VCL_TESTS``, ``VPP_BUILD_HS_SAPI_APPS``, ``VPP_BUILD_VPPINFRA_TESTS``, and ``VPP_BUILD_TESTS_WITH_COVERAGE``
    Control optional test and host-stack application builds.

``VPP_BUILD_G2``, ``VPP_BUILD_PERFTOOL``, ``VPP_BUILD_APPIMAGE``, and ``VPP_BUILD_MACTIME_TOP``
    Control optional tools that are off by default or plugin-specific.

``VPP_USE_SYSTEM_DPDK``
    Uses the system DPDK installation for the DPDK plugin.

``VPP_USE_CCACHE``
    Enables or disables ccache use. This is on by default when ccache is
    available.

``VPP_SET_RPATH``
    Controls whether installed binaries and libraries receive an rpath.

Use ``ccmake`` or inspect ``CMakeCache.txt`` in the VPP build directory for
the complete set of CMake cache variables available in a particular build
tree.

How to write a plugin CMakeLists.txt file
-----------------------------------------

It's really quite simple. Follow the pattern:

::

    add_vpp_plugin(mactime
      SOURCES
      mactime.c
      node.c

      API_FILES
      mactime.api

      INSTALL_HEADERS
      mactime_all_api_h.h
      mactime_msg_enum.h

      API_TEST_SOURCES
      mactime_test.c
    )

Adding a target elsewhere in the source tree
--------------------------------------------

Within reason, adding a subdirectory to the SUBDIRS list in
.../src/CMakeLists.txt is perfectly OK. The indicated directory will
need a CMakeLists.txt file.

.. _building-g2:

Here's how we build the g2 event data visualization tool:

::

    option(VPP_BUILD_G2 "Build g2 tool." OFF)
    if(VPP_BUILD_G2)
      find_package(GTK2 COMPONENTS gtk)
      if(GTK2_FOUND)
        include_directories(${GTK2_INCLUDE_DIRS})
        add_vpp_executable(g2
          SOURCES
          clib.c
          cpel.c
          events.c
          main.c
          menu1.c
          pointsel.c
          props.c
          g2version.c
          view1.c

          LINK_LIBRARIES vppinfra Threads::Threads m ${GTK2_LIBRARIES}
          NO_INSTALL
        )
      endif()
    endif()

The g2 component is optional, and is not built by default. There are
a couple of ways to tell cmake to include it in build.ninja [or in Makefile.]

When invoking cmake manually [rarely done and not very easy], specify
-DVPP_BUILD_G2=ON:

::

   $ cmake ... -DVPP_BUILD_G2=ON

Take a good look at .../build-data/packages/vpp.mk to see where and
how the top-level Makefile and .../build-root/Makefile set all of the
cmake arguments. One strategy to enable an optional component is fairly
obvious. Add -DVPP_BUILD_G2=ON to vpp_cmake_args.

That would work, of course, but it's not a particularly elegant solution.

Tinkering with build options: ccmake
------------------------------------

The easy way to set VPP_BUILD_G2 - or frankly **any** cmake
parameter - is to install the "cmake-curses-gui" package and use
it.

- Do a straightforward vpp build using the top level Makefile, "make build" or "make build-release"
- Ajourn to .../build-root/build-vpp-native/vpp or .../build-root/build-vpp_debug-native/vpp
- Invoke "ccmake ." to reconfigure the project as desired

Here's approximately what you'll see:

::

     CCACHE_FOUND                     /usr/bin/ccache
     CMAKE_BUILD_TYPE
     CMAKE_INSTALL_PREFIX             /scratch/vpp-gate/build-root/install-vpp-nati
     DPDK_INCLUDE_DIR                 /scratch/vpp-gate/build-root/install-vpp-nati
     DPDK_LIB                         /scratch/vpp-gate/build-root/install-vpp-nati
     MBEDTLS_INCLUDE_DIR              /usr/include
     MBEDTLS_LIB1                     /usr/lib/x86_64-linux-gnu/libmbedtls.so
     MBEDTLS_LIB2                     /usr/lib/x86_64-linux-gnu/libmbedx509.so
     MBEDTLS_LIB3                     /usr/lib/x86_64-linux-gnu/libmbedcrypto.so
     MUSDK_INCLUDE_DIR                MUSDK_INCLUDE_DIR-NOTFOUND
     MUSDK_LIB                        MUSDK_LIB-NOTFOUND
     PRE_DATA_SIZE                    128
     VPP_API_TEST_BUILTIN             ON
     VPP_BUILD_G2                     OFF
     VPP_BUILD_PERFTOOL               OFF
     VPP_BUILD_VCL_TESTS              ON
     VPP_BUILD_VPPINFRA_TESTS         OFF

    CCACHE_FOUND: Path to a program.
    Press [enter] to edit option Press [d] to delete an entry   CMake Version 3.10.2
    Press [c] to configure
    Press [h] for help           Press [q] to quit without generating
    Press [t] to toggle advanced mode (Currently Off)

Use the cursor to point at the VPP_BUILD_G2 line. Press the return key
to change OFF to ON. Press "c" to regenerate build.ninja, etc.

At that point "make build" or "make build-release" will build g2. And so on.

Note that toggling advanced mode ["t"] gives access to substantially
all of the cmake option, discovered directories and paths.
