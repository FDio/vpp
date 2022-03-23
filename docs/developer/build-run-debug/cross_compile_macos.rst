.. _cross_compile_macos :

Cross compilation on MacOS
==========================

This is a first attempt to support Cross compilation of VPP on MacOS for development (linting, completion, compile_commands.json)


**Prerequisites**

* You'll need to install the following packages

.. code-block:: console

  $ pip3 install ply pyyaml jsonschema
  $ brew install gnu-sed pkg-config ninja crosstool-ng

* You'll also need to install ``clang-format 11.0.0`` to be able to ``make checkstyle``. This can be done with :ref:`this doc<install_clang_format_11_0_0>`
* You should link the binaries to make them available in your path with their original names e.g. :

.. code-block:: console

  $ ln -s $(which gsed) /usr/local/bin/sed

**Setup**

* Create a `cross compile toolchain <https://crosstool-ng.github.io/>`_
* Create a case sensitive volume and mount the toolchain in it e.g. in ``/Volumes/xchain``
* Create a xchain.toolchain file with ``$VPP_DIR/extras/scripts/cross_compile_macos.sh conf /Volumes/xchan``

For now we don't support e-build so dpdk, rdma, quicly won't be compiled as part of ``make build``

To build with the toolchain do:

.. code-block:: console

  $ $VPP_DIR/extras/scripts/cross_compile_macos.sh build


To get the compile_commands.json do

.. code-block:: console

  $ $VPP_DIR/extras/scripts/cross_compile_macos.sh cc
  $ >> ./build-root/build-vpp[_debug]-native/vpp/compile_commands.json



This should build vpp on MacOS


Good luck :)

.. _install_clang_format_11_0_0 :

Installing clang-format 11.0.0
------------------------------

In order to install clang-format on macos :

.. code-block:: bash

    brew install clang-format@11
    wget https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-11.0.0/clang/tools/clang-format/clang-format-diff.py \
        -O /usr/local/Cellar/clang-format@11/11.1.0/bin/clang-format-diff.py
    chmod +x /usr/local/Cellar/clang-format@11/11.1.0/bin/clang-format-diff.py
    ln -s /usr/local/Cellar/clang-format@11/11.1.0/bin/clang-format-diff.py /usr/local/bin/clang-format-diff-11
    ln -s /usr/local/Cellar/clang-format@11/11.1.0/bin/clang-format-11 /usr/local/bin/clang-format


Source `Clang website <https://releases.llvm.org/download.html#git>`_
