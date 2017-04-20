;;; pipe-skel.el - pipelined graph node skeleton

(require 'skeleton)

(define-skeleton skel-pipeline-node
"Insert a skeleton pipelined graph node"
nil
'(setq node-name (skeleton-read "Node Name: "))
'(setq uc-node-name (upcase node-name))
'(setq nstages (skeleton-read "Number of pipeline stages: "))
"
#include <vlib/vlib.h>
#include <vppinfra/error.h>

/*
 * Dump these counters via the \"show error\" CLI command 
 * FIXME: Add packet counter / error strings as desired
 */

#define foreach_" node-name "_error \\
_(ERROR1, \"sample counter/ error string\")

static char * " node-name "_error_strings[] = {
#define _(sym,string) string,
  foreach_" node-name "_error
#undef _
};

/*
 * packet error / counter enumeration
 *
 * To count and drop a vlib_buffer_t *b:
 *
 *     Set b->error = node->errors[" uc-node-name "_ERROR_xxx];
 *     last_stage returns a disposition index bound to \"error-drop\"
 * 
 * To manually increment the specific counter " uc-node-name "_ERROR1
 *
 *  vlib_node_t *n = vlib_get_node (vm, " node-name ".index);
 *  u32 node_counter_base_index = n->error_heap_index;
 *  vlib_error_main_t * em = &vm->error_main;
 *  em->counters[node_counter_base_index + " uc-node-name "_ERROR1] += 1;
 * 
 */

typedef enum {
#define _(sym,str) " uc-node-name "_ERROR_##sym,
    foreach_" node-name "_error
#undef _
    " uc-node-name "_N_ERROR,
} " node-name "_error_t;

/*
 * enumeration of per-packet dispositions
 * FIXME: add dispositions as desired
 */

typedef enum { \n"
"    " uc-node-name "_NEXT_NORMAL,\n"
"    " uc-node-name "_N_NEXT,
} " node-name "_next_t;

#define NSTAGES " nstages "

/* 
 * Use the generic buffer metadata + first line of packet data prefetch
 * stage function from <api/pipeline.h>. This is usually a Good Idea.
 */
#define stage0 generic_stage0

/* 
 * FIXME: add stage functions. Here is the function prototype:
 * 
 * static inline void stageN (vlib_main_t * vm,
 *                            vlib_node_runtime_t * node,
 *                            u32 buffer_index)
 */

/*
 * FIXME: the last pipeline stage returns the desired pkt next node index,
 * from the " node-name "_next_t enum above
 */
static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);

    b->error = node->errors[EXAMPLE_ERROR_ERROR1];

    return " uc-node-name "_NEXT_NORMAL;
}

#include <api/pipeline.h>

static uword " node-name "_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}

static VLIB_REGISTER_NODE (example_node) = {
  .function = " node-name "_node_fn,
  .name = \"" node-name "-node\",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(" node-name "_error_strings),
  .error_strings = " node-name "_error_strings,

  .n_next_nodes = " uc-node-name "_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [" uc-node-name "_NEXT_NORMAL] = \"error-drop\",
  },
};

/* 
 * packet generator definition to push superframes of data into the
 * new graph node. Cut and paste into <file>, then
 * \"exec <file>\", \"pa enable test\" at the QVNET prompt...
 * 
packet-generator new {
  name test
  limit 100
  node " node-name "-node
  size 374-374
  data { hex 0x02b46b96000100096978676265000500bf436973636f20494f5320536f6674776172652c2043333735304520536f66747761726520284333373530452d554e4956455253414c2d4d292c2056657273696f6e2031322e32283335295345352c2052454c4541534520534f4654574152452028666331290a436f707972696768742028632920313938362d3230303720627920436973636f2053797374656d732c20496e632e0a436f6d70696c6564205468752031392d4a756c2d30372031363a3137206279206e616368656e00060018636973636f2057532d4333373530452d3234544400020011000000010101cc0004000000000003001b54656e4769676162697445746865726e6574312f302f3100040008000000280008002400000c011200000000ffffffff010221ff000000000000001e7a50f000ff000000090004000a00060001000b0005010012000500001300050000160011000000010101cc000400000000001a00100000000100000000ffffffff }
}
 */
")
