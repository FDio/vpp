.. _cross_compile_macos :

Cross compilation on MacOS
==========================

This is a first attempt to support Cross compilation of VPP on MacOS for development (linting, completion, compile_commands.json)


**Prerequisites**

* You'll need to install the following packages

.. code-block:: console

  $ pip3 install ply pyyaml jsonschema
  $ brew install diffutils gnu-sed pkg-config ninja crosstool-ng

* You'll also need to install ``gnu-ident 2.2.11`` to be able to ``make checkstyle``. This can be done with :ref:`this doc<install_indent_2_2_11>`
* You should link the binaries to make them available in your path with their original names e.g. :

.. code-block:: console

  $ ln -s $(which gsed) /usr/local/bin/sed
  $ ln -s $(which gindent) /usr/local/bin/indent
  $ ln -s /usr/local/Cellar/diffutils/3.7/bin/diff /usr/local/bin/diff


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

.. _install_indent_2_2_11 :

Installing indent 2.2.11
------------------------

In order to install indent on macos :

.. code-block:: bash

    $ wget http://mirror.sergal.org/gnu/indent/indent-2.2.11.tar.gz
    $ tar -xzvf indent-2.2.11.tar.gz
    $ cd indent-2.2.11
    $ ./configure --disable-dependency-tracking --disable-debug --program-prefix=g --prefix=/usr/local/Cellar/gnu-indent/2.2.11

Install will exit with an error code, but indent 2.2.11 will still be installed in ``/usr/local/bin/gindent``
Other mirrors can be found on the `GNU website <https://www.gnu.org/prep/ftp.html>`_
