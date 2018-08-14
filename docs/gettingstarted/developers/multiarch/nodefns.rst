Multi-Architecture Graph Node Cookbook
======================================

In the context of graph node dispatch functions, it's easy enough to
use the vpp multi-architecture support setup. The point of the scheme
is simple: for performance-critical nodes, generate multiple CPU
hardware-dependent versions of the node dispatch functions, and pick
the best one at runtime.

The vpp scheme is simple enough to use, but details matter.

100,000 foot view
-----------------

We compile entire graph node dispatch function implementation files
multiple times. These compilations give rise to multiple versions of
the graph node dispatch functions. Per-node constructor-functions
interrogate CPU hardware, select the node dispatch function variant to
use, and set the vlib_node_registration_t ".function" member to the
address of the selected variant.

Details
-------

Declare the node dispatch function as shown, using the VLIB\_NODE\_FN macro. The
name of the node function **MUST** match the name of the graph node. 

:: 

    VLIB_NODE_FN (ip4_sdp_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
    {
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
        return ip46_sdp_inline (vm, node, frame, 1 /* is_ip4 */ ,
    			    1 /* is_trace */ );
      else
        return ip46_sdp_inline (vm, node, frame, 1 /* is_ip4 */ ,
    			    0 /* is_trace */ );
    }   

We need to generate *precisely one copy* of the
vlib_node_registration_t, error strings, and packet trace decode function.

Simply bracket these items with "#ifndef CLIB_MARCH_VARIANT...#endif":

::

    #ifndef CLIB_MARCH_VARIANT
    static u8 *
    format_sdp_trace (u8 * s, va_list * args)
    {
       <snip>
    }
    #endif

    ...

    #ifndef CLIB_MARCH_VARIANT
    static char *sdp_error_strings[] = {
    #define _(sym,string) string,
      foreach_sdp_error
    #undef _
    };
    #endif

    ...

    #ifndef CLIB_MARCH_VARIANT
    VLIB_REGISTER_NODE (ip4_sdp_node) =
    {
      // DO NOT set the .function structure member.
      // The multiarch selection __attribute__((constructor)) function
      // takes care of it at runtime
      .name = "ip4-sdp",
      .vector_size = sizeof (u32),
      .format_trace = format_sdp_trace,
      .type = VLIB_NODE_TYPE_INTERNAL,

      .n_errors = ARRAY_LEN(sdp_error_strings),
      .error_strings = sdp_error_strings,

      .n_next_nodes = SDP_N_NEXT,

      /* edit / add dispositions here */
      .next_nodes =
      {
        [SDP_NEXT_DROP] = "ip4-drop",
      },
    };
    #endif

To belabor the point: *do not* set the ".function" member! That's the job of the multi-arch
selection \_\_attribute\_\_((constructor)) function

Always inline node dispatch functions
-------------------------------------

It's typical for a graph dispatch function to contain one or more
calls to an inline function. See above. If your node dispatch function
is structured that way, make *ABSOLUTELY CERTAIN* to use the
"always_inline" macro:

::

    always_inline uword
    ip46_sdp_inline (vlib_main_t * vm, vlib_node_runtime_t * node, 
                 vlib_frame_t * frame,
    		 int is_ip4, int is_trace)
    { ... }

Otherwise, the compiler is highly likely NOT to build multiple
versions of the guts of your dispatch function. 

It's fairly easy to spot this mistake in "perf top." If you see, for
example, a bunch of functions with names of the form
"xxx_node_fn_avx2" in the profile, *BUT* your brand-new node function
shows up with a name of the form "xxx_inline.isra.1", it's quite likely
that the inline was declared "static inline" instead of "always_inline".

Add the required Makefile.am content
------------------------------------

If the component in question already sets a "multiversioning_sources"
variable, simply add the indicated .c file to the list. If not, add
the required boilerplate:

::

    if CPU_X86_64
    sdp_multiversioning_sources =			\
    	sdp/node.c				\
    	sdp/sdp_slookup.c

    if CC_SUPPORTS_AVX2
    ###############################################################
    # AVX2
    ###############################################################
    libsdp_plugin_avx2_la_SOURCES = $(sdp_multiversioning_sources)
    libsdp_plugin_avx2_la_CFLAGS =					\
    	$(AM_CFLAGS)  @CPU_AVX2_FLAGS@				\
    	-DCLIB_MARCH_VARIANT=avx2
    noinst_LTLIBRARIES += libsdp_plugin_avx2.la
    sdp_plugin_la_LIBADD += libsdp_plugin_avx2.la
    endif

    if CC_SUPPORTS_AVX512
    ###############################################################
    # AVX512
    ###############################################################
    libsdp_plugin_avx512_la_SOURCES = $(sdp_multiversioning_sources)
    libsdp_plugin_avx512_la_CFLAGS =				\
    	$(AM_CFLAGS) @CPU_AVX512_FLAGS@				\
    	-DCLIB_MARCH_VARIANT=avx512
    noinst_LTLIBRARIES += libsdp_plugin_avx512.la
    sdp_plugin_la_LIBADD += libsdp_plugin_avx512.la
    endif
    endif

A certain amount of cut-paste-modify is currently required. Hopefully
we'll manage to improve the scheme in the future.
