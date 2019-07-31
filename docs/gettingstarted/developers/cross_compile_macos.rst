.. _cross_compile_macos :

Cross compilation on MacOS
==========================

This is a first attempt to support Cross compilation of VPP on MacOS for development (linting, completion, compile_commands.json)


**Prerequisites**

You'll need to install the following packages

.. code-block:: bash

  pip install ply
  brew install diffutils gnu-sed pkg-config ninja crosstool-ng

You'll also need to install ``gnu-ident 2.2.11`` to be able to ``make checkstyle``. You can get it from `GNU <https://www.gnu.org/prep/ftp.html>`_

**Setup**

* Create a `cross compile toolchain <https://crosstool-ng.github.io/>`_
* Create a case sensitive volume and mount the toolchain in it e.g. in ``/Volumes/xchain``
* Create a xchain.toolchain file with ``$VPP_DIR/extras/scripts/cross_compile_macos.sh conf /Volumes/xchan``

For now we don't support e-build so dpdk, rdma, quicly won't be compiled as part of ``make build``

To build with the toolchain do:

.. code-block:: bash

  $VPP_DIR/extras/scripts/cross_compile_macos.sh build


To get the compile_commands.json do

.. code-block:: bash

  $VPP_DIR/extras/scripts/cross_compile_macos.sh cc
  # >> ./build-root/build-vpp[_debug]-native/vpp/compile_commands.json



This should build vpp on MacOS


Good luck :)


