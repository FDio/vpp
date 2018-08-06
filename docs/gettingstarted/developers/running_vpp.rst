.. _running_vpp:

.. toctree::

Running VPP
===========

'Make' targets to run VPP
_________________________

Here's a snippet from the main Makefile showing all Make targets for running VPP, found in the base directory where you cloned the VPP repo.

Put 'make' before a listed target below.

.. code-block:: console

	run                 - run debug binary
	run-release         - run release binary
	debug               - run debug binary with debugger
	debug-release       - run release binary with debugger

For example, if you've built the VPP debug binary (contains debug symbols useful when modifying VPP), run the VPP debug binary with:

.. code-block:: console
	
	$ make run


Another example is if you encounter issues when running VPP, such as VPP terminating due to a segfault or abort signal, you can run the VPP debug binary in GDB with:

.. code-block:: console
	
	$ make debug

This will run VPP and give you a GDB prompt. You can show the backtrace with 'bt':

.. code-block:: console
	
	(gdb) bt
