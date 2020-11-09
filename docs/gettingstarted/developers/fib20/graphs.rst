.. _graphs:

Graphs
^^^^^^

The FIB is essentially a collection of related graphs. Terminology from graph theory
is often used in the sections that follow. From Wikipedia:

*... a graph is a representation of a set of objects where some pairs of objects are
connected by links. The interconnected objects are represented by mathematical
abstractions called vertices (also called nodes or points), and the links that
connect some pairs of vertices are called edges (also called arcs or lines) ...
edges may be directed or undirected.*

In a directed graph the edges can only be traversed in one direction - from child to
parent. The names are chosen to represent the many to one relationship. A child has
one parent, but a parent many children.  In undirected graphs the edge traversal
can be in either direction, but in FIB the parent child nomenclature remains to
represent the many to one relationship. Children of the same parent are termed
siblings. When the traversal is from child to parent it is considered to be a
forward traversal, or walk, and from parent to the many children a back walk.
Forward walks are cheap since they start from the many and move toward the few.
Back walks are expensive as the start from the few and visit the many.

The many to one relationship between child and parent means that the lifetime of a
parent object must extend to the lifetime of its children. If the control plane
removes a parent object before its children, then the parent must remain, in an
**incomplete** state, until the children are themselves removed. Likewise if a child
is created before its parent, the parent is created in an *incomplete* state. These
incomplete objects are needed to maintain the graph dependencies. Without them when
the parent is added finding the affected children would require a search through many
databases for those children. To extend the lifetime of parents all children thereof
hold a **lock** on the parent. This is a simple reference count. Children then follow
the add-or-lock/unlock semantics for finding a parent, as opposed to a malloc/free.
