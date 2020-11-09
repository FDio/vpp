.. _hacking:

Get Hacking
-----------

The code's directory structure is trivial, FIB, mFIB, adj have their
own directories.

for the most part, for all the FIB object types mentioned in this
documentation there is a corresponding .h and .c file. As with any VPP
component/sub-system a 'public' header file is any file that can be
included by another sub-system and/or plugin. These must be specified
in the build-system, so go look there. Public header files are always
a good entry point to start reading.

FIB
^^^

There is no direct [VPP's binary] API access to FIB, but FIB does
expose types that can be used on the API by FIB and by other
subsystems (e.g. :ref:`barnacles`). These types are specified in
fib.api and the encoding and decoding thereof in fib_api.[ch].

Most operations on a FIB entry happen as a result of an operation on a
FIB table; an entry does not exist in isolation. The APIs in
fib_table.h are well doxygen documented you should be able to figure
out what they do. Use this as a starting point to explore how entries
are created and deleted and how the source priority scheme works.

FIB sources are defined in fib_source.h. Each source behaviour has its
own file fib_entry_src_*.c These define the virtual functions that
determine how the source behaves when actions on the FIB occur. For
example, what the entry must do when its covering prefix's forwarding
is updated.

When creating new paths/path-lists the main action required is to
resolve them; see fib_path*_resolve, and once resolved to have them
contribute a DPO for forwarding or for the uRPF list; see
fib_*_contribute_forwarding and fib_*_contribute_urpf respectively.

The data-structures that used for entry lookup are protocol
specific, they are implemented in separate files; ip4_fib.[ch],
ip6_fib.[ch] and mpls_fib.[ch].

FIB extranet support is implemented in fib_attached_export.[ch].
FIB tracking is implemented in fib_entry_track.[ch].
FIB [back]walk is implemented in fib_walk.[ch].

Adjacency
^^^^^^^^^

Not much to say here, each adjacency type has it own file; use the
force, read the source.


Testing
^^^^^^^

the majority of FIB coverage comes from the C Unit tests in
fib_test.c. I strongly encourage you to add code here. It's a much
easier development cycle to fire up GDB, run VPP and iterate with
'test fib', than it is work in the python UT. You still need to write
python UT, don't get me wrong, it's just easier to do the FIB dev
using C UT.



Enjoy!
