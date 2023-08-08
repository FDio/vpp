.. _buildingrst:

Writing VPP Documentation
=========================

These instructions show how the VPP documentation sources are built.

The VPP Documents are written using `reStructuredText <http://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html>`_ (rst),
or markdown (md). These files are then built using the Sphinx build system `Sphinx <http://www.sphinx-doc.org/en/master/>`_.

Building the docs
-----------------

Start with a clone of the vpp repository.

.. code-block:: console

   $ git clone https://gerrit.fd.io/r/vpp
   $ cd vpp

Build the html **index.html** file:

.. code-block:: console

   $ make docs

Delete all the generated files with the following:

.. code-block:: console

   $ make docs-clean

View the results
----------------

If there are no errors during the build process, you should now have an ``index.html`` file in your ``vpp/build-root/docs/html`` directory, which you can then view in your browser.

Whenever you make changes to your ``.rst`` files that you want to see, repeat this build process.

Writing Docs and merging
------------------------

Documentation should be added as ``.rst`` file in the ``./src/`` tree next to the code it refers to. A symlink should be added at the relevant place in the ``./docs`` folder and a link in the appropriate place in the tree.

To ensure documentation is correctly inserted, you can run

.. code-block:: console

   $ ./extras/scripts/check_documentation.sh

VPP documents are reviewed and merged like and other source code. Refer to :ref:`gitreview`
to get your changes reviewed and merged.
