.. _styleguide02table:

******
Tables
******

There are two types of tables with different syntax, `Grid Tables <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#grid-tables>`_, and `Simple Tables <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#simple-tables>`_.

Grid Tables
___________

`Grid Tables <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#grid-tables>`_ are described with a visual grid made up of the characters "-", "=", "|", and "+". The hyphen ("-") is used for horizontal lines (row separators). The equals sign ("=") may be used to separate optional header rows from the table body. The vertical bar ("|") is used for vertical lines (column separators). The plus sign ("+") is used for intersections of horizontal and vertical lines.

Here is example code for a grid table in a *.rst* file:

.. code-block:: console

	+------------------------+------------+----------+----------+
	| Header row, column 1   | Header 2   | Header 3 | Header 4 |
	| (header rows optional) |            |          |          |
	+========================+============+==========+==========+
	| body row 1, column 1   | column 2   | column 3 | column 4 |
	+------------------------+------------+----------+----------+
	| body row 2             | Cells may span columns.          |
	+------------------------+------------+---------------------+
	| body row 3             | Cells may  | - Table cells       |
	+------------------------+ span rows. | - contain           |
	| body row 4             |            | - body elements.    |
	+------------------------+------------+---------------------+
	
This example code generates a grid table that looks like this:

+------------------------+------------+----------+----------+
| Header row, column 1   | Header 2   | Header 3 | Header 4 |
| (header rows optional) |            |          |          |
+========================+============+==========+==========+
| body row 1, column 1   | column 2   | column 3 | column 4 |
+------------------------+------------+----------+----------+
| body row 2             | Cells may span columns.          |
+------------------------+------------+---------------------+
| body row 3             | Cells may  | - Table cells       |
+------------------------+ span rows. | - contain           |
| body row 4             |            | - body elements.    |
+------------------------+------------+---------------------+


Simple Tables
_____________

`Simple tables <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#simple-tables>`_ are described with horizontal borders made up of "=" and "-" characters. The equals sign ("=") is used for top and bottom table borders, and to separate optional header rows from the table body. The hyphen ("-") is used to indicate column spans in a single row by underlining the joined columns, and may optionally be used to explicitly and/or visually separate rows. 

Simple tables are "simpler" to create than grid tables, but are more limited.

Here is example code for a simple table in a *.rst* file.

.. code-block:: console
	
	=====  =====  =======
	  A      B    A and B
	=====  =====  =======
	False  False  False
	True   False  False
	False  True   False
	True   True   True
	=====  =====  =======

This example code generates a simple table that looks like this:

=====  =====  =======
  A      B    A and B
=====  =====  =======
False  False  False
True   False  False
False  True   False
True   True   True
=====  =====  =======