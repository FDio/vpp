.. _running_vpp:

.. toctree::

Running VPP
===========

After building the VPP binaries, you now have several images built.
These images are useful when you need to run VPP without installing the packages.
For instance if you want to run VPP with GDB.

Running Without GDB
_________________________

To run the VPP images that you've built without GDB, run the following commands:

Running the release image:

.. code-block:: console

   # make run-release
   #

Running the debug image:

.. code-block:: console

   # make run
   #

Running With GDB
_________________________

With the following commands you can run VPP and then be dropped into the GDB prompt.

Before running either command, please make sure that the 'gdb' package is installed.
If it's not installed, run the following command first:

.. code-block:: console

   $ sudo apt install gdb

Running the release image:

.. code-block:: console

   # make debug-release
   (gdb)

Running the debug image:

.. code-block:: console

   # make debug
   (gdb)

