/*
 * l2_fwd.c : layer 2 forwarding using l2fib
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/cli.h>

#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_fwd.h>
#include <vnet/l2/l2_fib.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/sparse_vec.h>


typedef struct {

  // Hash table
  BVT(clib_bihash) *mac_table;

  // next node index for the L3 input node of each ethertype
  next_by_ethertype_t l3_next;

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} l2fwd_main_t;

typedef struct {
  /* per-pkt trace data */ 
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u16 bd_index;
} l2fwd_trace_t;

/* packet trace format function */
static u8 * format_l2fwd_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2fwd_trace_t * t = va_arg (*args, l2fwd_trace_t *);
  
  s = format (s, "l2-fwd:   sw_if_index %d dst %U src %U bd_index %d",
	      t->sw_if_index,
              format_ethernet_address, t->dst,
              format_ethernet_address, t->src,
              t->bd_index);
  return s;
}

l2fwd_main_t l2fwd_main;

static vlib_node_registration_t l2fwd_node;

#define foreach_l2fwd_error				\
_(L2FWD,         "L2 forward packets")			\
_(FLOOD,         "L2 forward misses")			\
_(HIT,           "L2 forward hits")			\
_(BVI_BAD_MAC,   "BVI L3 MAC mismatch")  		\
_(BVI_ETHERTYPE, "BVI packet with unhandled ethertype")	\
_(FILTER_DROP,   "Filter Mac Drop")			\
_(REFLECT_DROP,  "Reflection Drop")

typedef enum {
#define _(sym,str) L2FWD_ERROR_##sym,
  foreach_l2fwd_error
#undef _
  L2FWD_N_ERROR,
} l2fwd_error_t;

static char * l2fwd_error_strings[] = {
#define _(sym,string) string,
  foreach_l2fwd_error
#undef _
};

typedef enum {		
  L2FWD_NEXT_L2_OUTPUT,
  L2FWD_NEXT_FLOOD,
  L2FWD_NEXT_DROP,
  L2FWD_N_NEXT,
} l2fwd_next_t;

// Forward one packet based on the mac table lookup result

static_always_inline void
l2fwd_process (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               l2fwd_main_t * msm,
               vlib_error_main_t * em,
               vlib_buffer_t * b0,
               u32 sw_if_index0,
               l2fib_entry_result_t * result0,
               u32 * next0)
{
  if (PREDICT_FALSE (result0->raw == ~0)) {  
    // lookup miss, so flood
    // TODO:replicate packet to each intf in bridge-domain
    // For now just drop
    if (vnet_buffer(b0)->l2.feature_bitmap & L2INPUT_FEAT_UU_FLOOD) {
      *next0 = L2FWD_NEXT_FLOOD;
    } else {
      // Flooding is disabled
      b0->error = node->errors[L2FWD_ERROR_FLOOD];
      *next0 = L2FWD_NEXT_DROP;
    }

  } else {

    // lookup hit, forward packet 
#ifdef COUNTERS
    em->counters[node_counter_base_index + L2FWD_ERROR_HIT] += 1;
#endif 

    vnet_buffer(b0)->sw_if_index[VLIB_TX] = result0->fields.sw_if_index;
    *next0 = L2FWD_NEXT_L2_OUTPUT;

    // perform reflection check
    if (PREDICT_FALSE (sw_if_index0 == result0->fields.sw_if_index)) {
      b0->error = node->errors[L2FWD_ERROR_REFLECT_DROP];
      *next0 = L2FWD_NEXT_DROP;

    // perform filter check
    } else if (PREDICT_FALSE (result0->fields.filter)) {
      b0->error = node->errors[L2FWD_ERROR_FILTER_DROP];
      *next0 = L2FWD_NEXT_DROP;

    // perform BVI check
    } else if (PREDICT_FALSE (result0->fields.bvi)) {
      u32 rc;
      rc = l2_to_bvi (vm,
                      msm->vnet_main,
                      b0, 
	              vnet_buffer(b0)->sw_if_index[VLIB_TX],
	              &msm->l3_next,
                      next0);

      if (PREDICT_FALSE(rc)) {
        if (rc == TO_BVI_ERR_BAD_MAC) {
          b0->error = node->errors[L2FWD_ERROR_BVI_BAD_MAC];
          *next0 = L2FWD_NEXT_DROP;
        } else if (rc == TO_BVI_ERR_ETHERTYPE) {
          b0->error = node->errors[L2FWD_ERROR_BVI_ETHERTYPE];
          *next0 = L2FWD_NEXT_DROP;
        }
      }
    }
  }
}


static uword
l2fwd_node_fn (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  l2fwd_next_t next_index;
  l2fwd_main_t * msm = &l2fwd_main;
  vlib_node_t *n = vlib_get_node (vm, l2fwd_node.index);
  CLIB_UNUSED(u32 node_counter_base_index) = n->error_heap_index;
  vlib_error_main_t * em = &vm->error_main;
  l2fib_entry_key_t cached_key;
  l2fib_entry_result_t cached_result;

  // Clear the one-entry cache in case mac table was updated
  cached_key.raw = ~0; 
  cached_result.raw = ~0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors; /* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          ethernet_header_t * h0, * h1;
          l2fib_entry_key_t key0, key1;
          l2fib_entry_result_t result0, result1;
          u32 bucket0, bucket1;
          
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
          /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
 
          /* RX interface handles */
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
  
          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    l2fwd_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->bd_index = vnet_buffer(b0)->l2.bd_index;
                    clib_memcpy(t->src, h0->src_address, 6);
                    clib_memcpy(t->dst, h0->dst_address, 6);
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    l2fwd_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->bd_index = vnet_buffer(b1)->l2.bd_index;
                    clib_memcpy(t->src, h1->src_address, 6);
                    clib_memcpy(t->dst, h1->dst_address, 6);
                  }
              }

            /* process 2 pkts */
#ifdef COUNTERS
            em->counters[node_counter_base_index + L2FWD_ERROR_L2FWD] += 2;
#endif
            l2fib_lookup_2 (msm->mac_table, &cached_key, &cached_result, 
                            h0->dst_address, 
                            h1->dst_address, 
                            vnet_buffer(b0)->l2.bd_index, 
                            vnet_buffer(b1)->l2.bd_index,
                            &key0,    // not used
                            &key1,    // not used
                            &bucket0, // not used
                            &bucket1, // not used
                            &result0, 
                            &result1);
            l2fwd_process (vm, node, msm, em, b0, sw_if_index0, &result0, &next0);
            l2fwd_process (vm, node, msm, em, b1, sw_if_index1, &result1, &next1);

            /* verify speculative enqueues, maybe switch current next frame */
            /* if next0==next1==next_index then nothing special needs to be done */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }
      
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ethernet_header_t * h0;
          l2fib_entry_key_t key0;
          l2fib_entry_result_t result0;
          u32 bucket0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
 
          h0 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            l2fwd_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->bd_index = vnet_buffer(b0)->l2.bd_index;
            clib_memcpy(t->src, h0->src_address, 6);
            clib_memcpy(t->dst, h0->dst_address, 6);
          }

          /* process 1 pkt */
#ifdef COUNTERS
          em->counters[node_counter_base_index + L2FWD_ERROR_L2FWD] += 1;
#endif
          l2fib_lookup_1 (msm->mac_table, &cached_key, &cached_result, 
                          h0->dst_address, vnet_buffer(b0)->l2.bd_index, 
                          &key0,    // not used
                          &bucket0, // not used
                          &result0);
          l2fwd_process (vm, node, msm, em, b0, sw_if_index0, &result0, &next0);

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (l2fwd_node,static) = {
  .function = l2fwd_node_fn,
  .name = "l2-fwd",
  .vector_size = sizeof (u32),
  .format_trace = format_l2fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(l2fwd_error_strings),
  .error_strings = l2fwd_error_strings,

  .n_next_nodes = L2FWD_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2FWD_NEXT_L2_OUTPUT] = "l2-output",
    [L2FWD_NEXT_FLOOD] = "l2-flood",
    [L2FWD_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (l2fwd_node, l2fwd_node_fn)

clib_error_t *l2fwd_init (vlib_main_t *vm)
{
  l2fwd_main_t * mp = &l2fwd_main;
    
  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  /* init the hash table ptr */
  mp->mac_table = get_mac_table();

  // Initialize the next nodes for each ethertype
  next_by_ethertype_init (&mp->l3_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2fwd_init);


// Add the L3 input node for this ethertype to the next nodes structure
void
l2fwd_register_input_type (vlib_main_t * vm,
                           ethernet_type_t type,
                           u32 node_index)
{
  l2fwd_main_t * mp = &l2fwd_main;
  u32 next_index;

  next_index = vlib_node_add_next (vm, 
                                   l2fwd_node.index,
                                   node_index);

  next_by_ethertype_register (&mp->l3_next, type, next_index);
}


// set subinterface forward enable/disable
// The CLI format is:
//    set interface l2 forward <interface> [disable]
static clib_error_t *
int_fwd (vlib_main_t * vm,
         unformat_input_t * input,
         vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;
  u32 enable;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  enable = 1;
  if (unformat (input, "disable")) {
    enable = 0;
  }

  // set the interface flag
  if (l2input_intf_config(sw_if_index)->xconnect) {
    l2input_intf_bitmap_enable(sw_if_index, L2INPUT_FEAT_XCONNECT, enable);
  } else {
    l2input_intf_bitmap_enable(sw_if_index, L2INPUT_FEAT_FWD, enable);
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (int_fwd_cli, static) = {
  .path = "set interface l2 forward",
  .short_help = "set interface l2 forward <interface> [disable]",
  .function = int_fwd,
};
