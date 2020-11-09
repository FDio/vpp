.. _attachedexport:

Attached Export
^^^^^^^^^^^^^^^^

Extranets make prefixes in table A also reachable from table B. Table A is the export table,
B the import. Consider this route in the export table;

.. code-block:: console

   # ip route add table 2 1.1.1.0/24 via 10.10.10.0 GigabitEthernet0/8/0

there are two ways one might consider representing this route in the import VRF:

#. ip route add table 3 1.1.1.0/24 via 10.10.10.0 GigabitEthernet0/8/0
#. ip route add table 3 1.1.1.0/24 via lookup-in-table 2

where option 2) is an example of a de-aggregate route where a second lookup is
performed in table 2, the export VRF. Option 2) is clearly less efficient, since
the cost of the second lookup is high. Option 1) is therefore preferred. However,
connected and attached prefixes, and specifically the adj-fibs that they cover,
require special attention. The control plane is aware of the connected and
attached prefixes that are required to be exported, but it is unaware of the
adj-fibs. It is therefore the responsibility of FIB to ensure that whenever an
attached prefix is exported, so are the adj-fibs and local prefixes that it
covers, and only the adj-fibs and locals, not any covered more specific
(sourced e.g. by API). The imported FIB entries are sourced as *attached-export*
this is a low priority source, so if those prefixes already exist in the import
table, sourced by the API, then they will continue to forward with that information.

.. figure:: /_images/fib20fig6.png

Figure 6: Attached Export Class diagram.

Figure 6 shows the data structures used to perform attached export.

- *fib_import_t*. A representation of the need to import covered prefixes. An instance is associated with the FIB entry in the import VRF. The need to import prefixes is recognised when an attached route is added to a table that is different to the table of the interface to which it t is attached. The creation of a *fib_import_t* will trigger the creation of a *fib_export_t*.
- *fib_export_t*. A representation of the need to export prefixes. An instance is associated with the attached entry in the export VRF. A *fib_export_t* can have many associated *fib_import_t* objects representing multiple VRFs into which the prefix is exported.

.. figure:: /_images/fib20fig6.png

Figure 7: Attached Export object diagram

Figure 7 shows an object instance diagram for the export of a connected from table
1 to two other tables. The /32 adj-fib and local prefix in the export VRF are
exported into the import VRFs, where they are sourced as *attached-export* and
inherit the forwarding information from the exported entry. The attached prefix
in the import VRF also performs cover tracking with the connected prefix in the
export VRF so that it can react to updates to that prefix that will require the
removal the imported covered prefixes.
