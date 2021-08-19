.. _graphwalks:

Graph Walks
^^^^^^^^^^^^

All FIB object types are allocated from a VPP memory pool [#f13]_. The objects are thus
susceptible to memory re-allocation, therefore the use of a bare "C" pointer to refer
to a child or parent is not possible. Instead there is the concept of a *fib_node_ptr_t*
which is a tuple of type,index. The type indicates what type of object it is
(and hence which pool to use) and the index is the index in that pool. This allows
for the safe retrieval of any object type.

When a child resolves via a parent it does so knowing the type of that parent. The
child to parent relationship is thus fully known to the child, and hence a forward
walk of the graph (from child to parent) is trivial. However, a parent does not choose
its children, it does not even choose the type. All object types that form part of the
FIB control plane graph all inherit from a single base class; *fib_node_t*. A *fib_node_t*
identifies the object's index and its associated virtual function table provides the
parent a mechanism to visit that object during the walk. The reason for a back-walk
is to inform all children that the state of the parent has changed in some way, and
that the child may itself need to update.

To support the many to one, child to parent, relationship a parent must maintain a
list of its children. The requirements of this list are;

- O(1) insertion and delete time. Several child-parent relationships are made/broken during route addition/deletion.
- Ordering. High priority children are at the front, low priority at the back (see section Fast Convergence)
- Insertion at arbitrary locations.

To realise these requirements the child-list is a doubly linked-list, where each element
contains a *fib_node_ptr_t*. The VPP pool memory model applies to the list elements, so
they are also identified by an index. When a child is added to a list it is returned the
index of the element. Using this index the element can be removed in constant time.
The list supports 'push-front' and 'push-back' semantics for ordering. To walk the children
of a parent is then to iterate this list.

A back-walk of the graph is a depth first search where all children in all levels of the
hierarchy are visited. Such walks can therefore encounter all object instances in the
FIB control plane graph, numbering in the millions. A FIB control-plane graph is cyclic
in the presence of a recursion loop, so the walk implementation has mechanisms to detect
this and exit early.

A back-walk can be either synchronous or asynchronous. A synchronous walk will visit the
entire section of the graph before control is returned to the caller, an asynchronous
walk will queue the walk to a background process, to run at a later time, and immediately
return to the caller. To implement asynchronous walks a *fib_walk_t* object it added to
the front of the parent's child list. As children are visited the *fib_walk_t* object
advances through the list. Since it is inserted in the list, when the walk suspends
and resumes, it can continue at the correct location. It is also safe with respect to
the deletion of children from the list. New children are added to the head of the list,
and so will not encounter the walk, but since they are new, they already have the up to
date state of the parent.

A VLIB process 'fib-walk' runs to perform the asynchronous walks. VLIB has no priority
scheduling between respective processes, so the fib-walk process does work in small
increments so it does not block the main route download process. Since the main download
process effectively has priority numerous asynchronous back-walks can be started on the
same parent instance before the fib-walk process can run. FIB is a 'final state' application.
If a parent changes n times, it is not necessary for the children to also update n
times, instead it is only necessary that this child updates to the latest, or final,
state. Consequently when multiple walks on a parent (and hence potential updates to a
child) are queued, these walks can be merged into a single walk. This
is the main reason the walks are designed this way, to eliminate (as
much as possible) redundant work and thus converge the system as fast
as possible.

Choosing between a synchronous and an asynchronous walk is therefore a trade-off between
time it takes to propagate a change in the parent to all of its children, versus the
time it takes to act on a single route update. For example, if a route update were to
affect millions of child recursive routes, then the rate at which such updates could be
processed would be dependent on the number of child recursive route which would not be
good. At the time of writing FIB2.0 uses synchronous walk in all locations except when
walking the children of a path-list, and it has more than 32 [#f15]_ children. This avoids the
case mentioned above.

.. rubric:: Footnotes:

.. [#f13] Fast memory allocation is crucial to fast route update times.
.. [#f14] VPP may be written in C and not C++ but inheritance is still possible.
.. [#f15] The value is arbitrary and yet to be tuned.
