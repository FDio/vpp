Multi-Architecture Arbitrary Function Cookbook
==============================================

Optimizing arbitrary functions for multiple architectures is simple
enough, and very similar to process used to produce multi-architecture
graph node dispatch functions.

As with multi-architecture graph nodes, we compile source files
multiple times, generating multiple implementations of the original
function, and a public selector function.

Details
-------

Decorate function definitions with CLIB_MARCH_FN macros. For example:

Change the original function prototype...

::

   u32 vlib_frame_alloc_to_node (vlib_main_t * vm, u32 to_node_index,
                                 u32 frame_flags)

...by recasting the function name and return type as the first two
arguments to the CLIB_MARCH_FN macro:

::

    CLIB_MARCH_FN (vlib_frame_alloc_to_node, u32, vlib_main_t * vm,
                   u32 to_node_index, u32 frame_flags)

In the actual vpp image, several versions of vlib_frame_alloc_to_node
will appear: vlib_frame_alloc_to_node_avx2,
vlib_frame_alloc_to_node_avx512, and so forth.


For each multi-architecture function, use the CLIB_MARCH_FN_SELECT
macro to help generate the one-and-only multi-architecture selector
function:

::

    #ifndef CLIB_MARCH_VARIANT
    u32
    vlib_frame_alloc_to_node (vlib_main_t * vm, u32 to_node_index,
    			  u32 frame_flags)
    {
      return CLIB_MARCH_FN_SELECT (vlib_frame_alloc_to_node)
        (vm, to_node_index, frame_flags);
    }
    #endif /* CLIB_MARCH_VARIANT */

Once bound, the multi-architecture selector function is about as
expensive as an indirect function call; which is to say: not very
expensive.

Modify CMakeLists.txt
---------------------

If the component in question already lists "MULTIARCH_SOURCES", simply
add the indicated .c file to the list.  Otherwise, add as shown
below. Note that the added file "new_multiarch_node.c" should appear in
*both* SOURCES and MULTIARCH_SOURCES:

::

    add_vpp_plugin(myplugin
      SOURCES
      multiarch_code.c
      ...

      MULTIARCH_SOURCES
      multiarch_code.c
      ...
     )

A Word to the Wise
------------------

A file which liberally mixes functions worth compiling for multiple
architectures and functions which are not will end up full of
#ifndef CLIB_MARCH_VARIANT conditionals. This won't do a thing to make
the code look any better.

Depending on requirements, it may make sense to move functions to
(new) files to reduce complexity and/or improve legibility of the
resulting code.
