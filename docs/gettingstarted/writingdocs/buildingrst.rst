.. _buildingrst:

**************************
Creating VPP Documents
**************************

These instructions show how the VPP documentation sources are built.

The VPP Documents are written using `reStructuredText <http://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html>`_ (rst),
or markdown (md). These files are then built using the Sphinx build system `Sphinx <http://www.sphinx-doc.org/en/master/>`_.

Get the VPP sources
=====================

Start with a clone of the vpp repository.

.. code-block:: console

   $ git clone https://gerrit.fd.io/r/vpp
   $ cd vpp


Install the Necessary Packages
===============================

Before building the docs there are some packages that are needed. To install
these packages on ubuntu execute the following.

.. code-block:: console

   $ sudo apt-get install python3-all python3-setuptools python3-pip

 
Create a Virtual Environment using virtualenv
===============================================
 
For more information on how to use the Python virtual environment check out
`Installing packages using pip and virtualenv`_.

.. _`Installing packages using pip and virtualenv`: https://packaging.python.org/guides/installing-using-pip-and-virtualenv/

In the vpp root directory on your system, run: 

.. code-block:: console

   $ make docs-venv

Which installs all the required applications into it's own, isolated, virtual environment, so as to not
interfere with other builds that may use different versions of software.

Build the html files
======================

Build the html **index.html** file: 

.. code-block:: console

   $ make docs

Clean the environment
======================

Delete all the generated files with the following:

.. code-block:: console

   $ make docs-clean

View the results
=================

| If there are no errors during the build process, you should now have an **index.html** file in your
| **vpp/docs/_build/html** directory, which you can then view in your browser.

.. figure:: /_images/htmlBuild.png
   :alt: Figure: My directory containing the index.html file
   :scale: 35%
   :align: center

Whenever you make changes to your **.rst** files that you want to see, repeat this build process.

.. note::

   To exit from the virtual environment execute:

.. code-block:: console

   $ deactivate

Getting your documents reviewed and merged
==========================================

VPP documents are reviewed and merged like and other source code. Refer to :ref:`gitreview`
to get your changes reviewed and merged.
