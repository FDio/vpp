.. _cross_compile_osx :

Cross compilation on OSX
========================

This is a first attempt to support Cross compilation of VPP on OSX for development (linting, completion, compile_commands.json)


**Prerequisites**

You'll need to install the following packages

.. code-block:: bash

  pip install ply
  brew install diffutils gnu-sed pkg-config ninja

You'll also need to install ``gnu-ident 2.2.11`` to be able to ``make checkstyle``. You can get it from `GNU <https://www.gnu.org/prep/ftp.html>`_

**Setup**

* Create a `cross compile toolchain <https://crosstool-ng.github.io/>`_
* Create a case sensitive volume and mount the toolchain in it e.g. in ``/Volumes/xchain``
* Create a xchain.toolchain file with the following content

.. code-block:: cmake

  SET(CMAKE_SYSTEM_NAME Linux)
  SET(CMAKE_SYSTEM_VERSION 1)

  # specify the cross compiler
  SET(CMAKE_C_COMPILER   /Volumes/xchain/x86_64-ubuntu16.04-linux-gnu/bin/x86_64-ubuntu16.04-linux-gnu-gcc)
  SET(CMAKE_CXX_COMPILER /Volumes/xchain/x86_64-ubuntu16.04-linux-gnu/bin/x86_64-ubuntu16.04-linux-gnu-g++)

  # where is the target environment
  SET(CMAKE_FIND_ROOT_PATH  /Volumes/xchain/x86_64-ubuntu16.04-linux-gnu /Volumes/xchain/x86_64-ubuntu16.04-linux-gnu//x86_64-ubuntu16.04-linux-gnu/sysroot/)

  SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
  SET(CMAKE_SYSTEM_PROCESSOR x86_64)
  # This is needed to build vpp-papi
  SET(PYTHON_EXECUTABLE /usr/local/bin/python)


For now we don't support e-build so you'll need to deactivate it in ``./build/external/Makefile`` by removing all tasks in ``install:`` and ``config:``

To build with the toolchain do:

.. code-block:: bash

  export VPP_TOOLCHAIN_FILE=xchain.toolchain ; make build


To get the compile_commands.json do

.. code-block:: bash

  export VPP_TOOLCHAIN_FILE=xchain.toolchain ; export VPP_EXPORT_COMPILE_COMMANDS=ON ; make build
  # >> ./build-root/build-vpp[_debug]-native/vpp/compile_commands.json

This should build vpp on OSX


Good luck :)


