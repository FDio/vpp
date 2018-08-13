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


Create a Virtual Environment using virtualenv
===============================================
 
For more information on how to use the Python virtual environment check out
`Installing packages using pip and virtualenv`_.

.. _`Installing packages using pip and virtualenv`: https://packaging.python.org/guides/installing-using-pip-and-virtualenv/

In the vpp root directory on your system, run: 

.. code-block:: console

   $ python -m pip install --user virtualenv 
   $ python -m virtualenv env
   $ source env/bin/activate
   $ pip install -r docs/etc/requirements.txt
   $ cd docs

Which installs all the required applications into it's own, isolated, virtual environment, so as to not
interfere with other builds that may use different versions of software.

Build the html files
======================

Be sure you are in your vpp-docs/docs directory, since that is where Sphinx will look for your **conf.py**
file, and build the **.rst** files into an **index.html** file: 

.. code-block:: console

   $ make html

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
