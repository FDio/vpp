.. _running_vpp:

.. toctree::

Running VPP
===========

After build the VPP binaries, there a several to run the images you've built. These is useful when
if you need to run VPP without  installing the packages. For instance if you want to run VPP with GDB.

Without GDB
_________________________

To run the VPP images, that you've build without GDB.

Running the release image:

.. code-block:: console

   # make run-release
   #

Running the debug image:

.. code-block:: console

   # make run
   #

With GDB
_________________________

With the following commands you can run VPP and then be dropped into the GDB prompt.

Running the release image:

.. code-block:: console

   # make debug-release
   (gdb)

Running the debug image:

.. code-block:: console

   # make debug
   (gdb)
