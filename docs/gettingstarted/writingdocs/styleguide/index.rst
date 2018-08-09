.. _styleguide:

#############################
reStructured Text Style Guide
#############################

Most of the these documents are written ins reStructured Text (rst). This chapter describes some of
the Sphinx Markup Constructs used in these documents. The Sphinx style guide can be found at:
`Sphinx Style Guide <http://documentation-style-guide-sphinx.readthedocs.io/en/latest/style-guide.html>`_
For a more detailed list of Sphinx Markup Constructs please refer to:
`Sphinx Markup Constructs <http://www.sphinx-doc.org/en/stable/markup/index.html>`_

This document is also an example of a directory structure for a document that spans mutliple pages.
Notice we have the file **index.rst** and the then documents that are referenced in index.rst. The
referenced documents are shown at the bottom of this page.

A label is shown at the top of this page. Then the first construct describes a the document title
**FD.io Style Guide**. Text usually follows under each title or heading.

A **Table of Contents** structure is shown below. Using **toctree** in this way will show the headings
in a nicely in the generated documents.

.. toctree::
   :maxdepth: 2

   styleguide.rst
   styleguide02.rst
   styleguide02table.rst
   styleguide03.rst
   styleguide04.rst
   styleguide05.rst
