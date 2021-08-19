.. _controlplane:

The Control Plane
-----------------

The control plane follows a layered data representation. This document describes the
model starting from the lowest layer. The description uses IPv4 addresses and
protocols, but all concepts apply equally to the IPv6 equivalents. The diagrams
all portray the CLI command to install the information in VPP and an
[approximation of] a UML diagram [#f1]_ of the data structures used to represent that
information.

.. toctree::

   neighbors
   routes
   attachedexport
   graphwalks
   marknsweep

.. rubric:: Footnotes:

.. [#f1] The arrow indicates a ‘has-a’ relationship. The object attached to the arrow head ‘has-a’ instance of the other. The numbers next to the arrows indicate the multiplicity, i.e. object A has n to m instances of object B. The difference between a UML association and aggregation is not conveyed in any diagrams. To UML aficionados, I apologize. Word is not the best drawing tool.
