
Overview
========

This repository was created as a private staring point for the vpp documentation
project. It is expected that it will be used as a sandbox that can be used to
evaluate and comment on the new fd.io document structure.

Build and Load Instructions
===========================
I build and load the documents using a mac, but these instuctions should be portable
to any platform. I used the Python virtual environment.

For more information on how to use the Python virtual enviroment check out
`Installing packages using pip and virtualenv`_.

.. _`Installing packages using pip and virtualenv`: https://packaging.python.org/guides/installing-using-pip-and-virtualenv/
 
1. Get the repository

.. code-block:: console

   git clone https://github.com/fdioDocs/vpp-docs
   cd vpp-docs

2. Install the virtual environment

.. code-block:: console

   python -m pip install --user virtualenv 
   python -m virtualenv env
   source env/bin/activate
   pip install -r etc/requirements.txt

.. note::

   To exit from the virtual environment execute:

.. code-block:: console

   deactivate

3. Build the html files

.. code-block:: console

   cd docs
   make html

4. View the results.

To view the results start a browser and open the file:

.. code-block:: console

   <THE CLONED DIRECTORY>/docs/_build/html/index.html
