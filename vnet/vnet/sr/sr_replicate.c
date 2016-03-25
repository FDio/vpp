
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;
} sr_replicate_main_t;

sr_replicate_main_t sr_replicate_main;

vlib_node_registration_t sr_replicate_node;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} sr_replicate_trace_t;

/* packet trace format function */
static u8 * format_sr_replicate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_replicate_trace_t * t = va_arg (*args, sr_replicate_trace_t *);
  
  s = format (s, "SR_REPLICATE: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t sr_replicate_node;

#define foreach_sr_replicate_error \
_(REPLICATED, "sr packets replicated")

typedef enum {
#define _(sym,str) SR_REPLICATE_ERROR_##sym,
  foreach_sr_replicate_error
#undef _
  SR_REPLICATE_N_ERROR,
} sr_replicate_error_t;

static char * sr_replicate_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_replicate_error
#undef _
};

typedef enum {
  SR_REPLICATE_NEXT_INTERFACE_OUTPUT,
  SR_REPLICATE_N_NEXT,
} sr_replicate_next_t;

static uword
sr_replicate_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  sr_replicate_next_t next_index;
  u32 pkts_swapped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      /* Dual loop disabled */
      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = SR_REPLICATE_NEXT_INTERFACE_OUTPUT;
          u32 next1 = SR_REPLICATE_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
          u8 tmp0[6], tmp1[6];
          ethernet_header_t *en0, *en1;
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          /* $$$$$ Dual loop: process 2 x packets here $$$$$ */
          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

	  /* Replicate for each policy */

          /*sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	  */

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          /* $$$$$ End of processing 2 x packets $$$$$ */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    sr_replicate_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    sr_replicate_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                  }
              }
            
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = SR_REPLICATE_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0;
          u8 tmp0[6];
          ethernet_header_t *en0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* $$$$$ Single loop: process 1  packet here $$$$$ */

          /* 
           * Direct from the driver, we should be at offset 0
           * aka at &b0->data[0]
           */
          ASSERT (b0->current_data == 0);

          en0 = vlib_buffer_get_current (b0);

	  /* Replicate for each policy */

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              sr_replicate_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }
            
          pkts_swapped += 1;

          /* $$$$$ Done processing 1 packet here $$$$$ */

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sr_replicate_node.index, 
                               SR_REPLICATE_ERROR_SWAPPED, pkts_swapped);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_replicate_node) = {
  .function = sr_replicate_node_fn,
  .name = "sr-replicate",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_replicate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(sr_replicate_error_strings),
  .error_strings = sr_replicate_error_strings,

  .n_next_nodes = SR_REPLICATE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [SR_REPLICATE_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};

clib_error_t *sr_replicate_init (vlib_main_t *vm)
{
  sr_replicate_main_t *msm = &sr_replicate_main;
    
  /* $$$$$ Initialize sr_replicate_main_t structure here. $$$$$ */
  msm->vlib_main = vm;
  msm->vnet_main = vnet_get_main();
  msm->ethernet_main = ethernet_get_main(vm);

  return 0;
}

VLIB_INIT_FUNCTION(sr_replicate_init);
