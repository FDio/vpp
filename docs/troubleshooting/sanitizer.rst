.. _sanitizer:

*****************
Google Sanitizers
*****************

VPP is instrumented to support `Google Sanitizers <https://github.com/google/sanitizers>`_.
As of today, only `AddressSanitizer <https://github.com/google/sanitizers/wiki/AddressSanitizer>`_
is supported and only for the heap.

AddressSanitizer
================

`AddressSanitizer <https://github.com/google/sanitizers/wiki/AddressSanitizer>`_  (aka ASan) is a memory
error detector for C/C++. Think Valgrind but much faster.

In order to use it, VPP must be recompiled with ASan support. It is implemented as a cmake
build option, so all VPP targets should be supported. For example:

.. code-block:: console

    # build a debug image with ASan support:
    $ make rebuild VPP_EXTRA_CMAKE_ARGS=-DENABLE_SANITIZE_ADDR=ON
    ....

    # build a release image with ASan support:
    $ make rebuild-release VPP_EXTRA_CMAKE_ARGS=-DENABLE_SANITIZE_ADDR=ON
    ....

    # build packages in debug mode with ASan support:
    $ make pkg-deb-debug VPP_EXTRA_CMAKE_ARGS=-DENABLE_SANITIZE_ADDR=ON
    ....

    # run GBP plugin tests in debug mode with ASan
    $ make test-debug TEST=test_gbp VPP_EXTRA_CMAKE_ARGS=-DENABLE_SANITIZE_ADDR=ON
    ....

Once VPP has been built with ASan support, you can use it as usual. When
running under a debugger it can be useful to disable LeakSanitizer which is
not compatible with a debugger and displays spurious warnings at exit:

.. code-block:: console

    $ ASAN_OPTIONS=detect_leaks=0 gdb --args $PWD/build-root/install-vpp_debug-native/vpp/bin/vpp "unix { interactive }"
    ....

