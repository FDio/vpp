/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include "ssvm_eth.h"

vlib_node_registration_t ssvm_eth_input_node;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} ssvm_eth_input_trace_t;

/* packet trace format function */
static u8 *
format_ssvm_eth_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ssvm_eth_input_trace_t *t = va_arg (*args, ssvm_eth_input_trace_t *);

  s = format (s, "SSVM_ETH_INPUT: sw_if_index %d, next index %d",
	      t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t ssvm_eth_input_node;

#define foreach_ssvm_eth_input_error \
_(NO_BUFFERS, "Rx packet drops (no buffers)")

typedef enum
{
#define _(sym,str) SSVM_ETH_INPUT_ERROR_##sym,
  foreach_ssvm_eth_input_error
#undef _
    SSVM_ETH_INPUT_N_ERROR,
} ssvm_eth_input_error_t;

static char *ssvm_eth_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ssvm_eth_input_error
#undef _
};

typedef enum
{
  SSVM_ETH_INPUT_NEXT_DROP,
  SSVM_ETH_INPUT_NEXT_ETHERNET_INPUT,
  SSVM_ETH_INPUT_NEXT_IP4_INPUT,
  SSVM_ETH_INPUT_NEXT_IP6_INPUT,
  SSVM_ETH_INPUT_NEXT_MPLS_INPUT,
  SSVM_ETH_INPUT_N_NEXT,
} ssvm_eth_input_next_t;

static inline uword
ssvm_eth_device_input (ssvm_eth_main_t * em,
		       ssvm_private_t * intfc, vlib_node_runtime_t * node)
{
  ssvm_shared_header_t *sh = intfc->sh;
  vlib_main_t *vm = em->vlib_main;
  unix_shared_memory_queue_t *q;
  ssvm_eth_queue_elt_t *elt, *elts;
  u32 elt_index;
  u32 my_pid = intfc->my_pid;
  int rx_queue_index;
  u32 n_to_alloc = VLIB_FRAME_SIZE * 2;
  u32 n_allocated, n_present_in_cache;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_free_list_t *fl;
  u32 n_left_to_next, *to_next;
  u32 next0;
  u32 n_buffers;
  u32 n_available;
  u32 bi0, saved_bi0;
  vlib_buffer_t *b0, *prev;
  u32 saved_cache_size = 0;
  ethernet_header_t *eh0;
  u16 type0;
  u32 n_rx_bytes = 0, l3_offset0;
  u32 thread_index = vlib_get_thread_index ();
  u32 trace_cnt __attribute__ ((unused)) = vlib_get_trace_count (vm, node);
  volatile u32 *lock;
  u32 *elt_indices;
  uword n_trace = vlib_get_trace_count (vm, node);

  /* Either side down? buh-bye... */
  if (pointer_to_uword (sh->opaque[MASTER_ADMIN_STATE_INDEX]) == 0 ||
      pointer_to_uword (sh->opaque[SLAVE_ADMIN_STATE_INDEX]) == 0)
    return 0;

  if (intfc->i_am_master)
    q = (unix_shared_memory_queue_t *) (sh->opaque[TO_MASTER_Q_INDEX]);
  else
    q = (unix_shared_memory_queue_t *) (sh->opaque[TO_SLAVE_Q_INDEX]);

  /* Nothing to do? */
  if (q->cursize == 0)
    return 0;

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  vec_reset_length (intfc->rx_queue);

  lock = (u32 *) q;
  while (__sync_lock_test_and_set (lock, 1))
    ;
  while (q->cursize > 0)
    {
      unix_shared_memory_queue_sub_raw (q, (u8 *) & elt_index);
      ASSERT (elt_index < 2048);
      vec_add1 (intfc->rx_queue, elt_index);
    }
  CLIB_MEMORY_BARRIER ();
  *lock = 0;

  n_present_in_cache = vec_len (em->buffer_cache);

  if (vec_len (em->buffer_cache) < vec_len (intfc->rx_queue) * 2)
    {
      vec_validate (em->buffer_cache,
		    n_to_alloc + vec_len (em->buffer_cache) - 1);
      n_allocated =
	vlib_buffer_alloc (vm, &em->buffer_cache[n_present_in_cache],
			   n_to_alloc);

      n_present_in_cache += n_allocated;
      _vec_len (em->buffer_cache) = n_present_in_cache;
    }

  elts = (ssvm_eth_queue_elt_t *) (sh->opaque[CHUNK_POOL_INDEX]);

  n_buffers = vec_len (intfc->rx_queue);
  rx_queue_index = 0;

  while (n_buffers > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_buffers > 0 && n_left_to_next > 0)
	{
	  elt = elts + intfc->rx_queue[rx_queue_index];

	  saved_cache_size = n_present_in_cache;
	  if (PREDICT_FALSE (saved_cache_size == 0))
	    {
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      goto out;
	    }
	  saved_bi0 = bi0 = em->buffer_cache[--n_present_in_cache];
	  b0 = vlib_get_buffer (vm, bi0);
	  prev = 0;

	  while (1)
	    {
	      vlib_buffer_init_for_free_list (b0, fl);

	      b0->current_data = elt->current_data_hint;
	      b0->current_length = elt->length_this_buffer;
	      b0->total_length_not_including_first_buffer =
		elt->total_length_not_including_first_buffer;

	      clib_memcpy (b0->data + b0->current_data, elt->data,
			   b0->current_length);

	      if (PREDICT_FALSE (prev != 0))
		prev->next_buffer = bi0;

	      if (PREDICT_FALSE (elt->flags & SSVM_BUFFER_NEXT_PRESENT))
		{
		  prev = b0;
		  if (PREDICT_FALSE (n_present_in_cache == 0))
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      goto out;
		    }
		  bi0 = em->buffer_cache[--n_present_in_cache];
		  b0 = vlib_get_buffer (vm, bi0);
		}
	      else
		break;
	    }

	  saved_cache_size = n_present_in_cache;

	  to_next[0] = saved_bi0;
	  to_next++;
	  n_left_to_next--;

	  b0 = vlib_get_buffer (vm, saved_bi0);
	  eh0 = vlib_buffer_get_current (b0);

	  type0 = clib_net_to_host_u16 (eh0->type);

	  next0 = SSVM_ETH_INPUT_NEXT_ETHERNET_INPUT;

	  if (type0 == ETHERNET_TYPE_IP4)
	    next0 = SSVM_ETH_INPUT_NEXT_IP4_INPUT;
	  else if (type0 == ETHERNET_TYPE_IP6)
	    next0 = SSVM_ETH_INPUT_NEXT_IP6_INPUT;
	  else if (type0 == ETHERNET_TYPE_MPLS)
	    next0 = SSVM_ETH_INPUT_NEXT_MPLS_INPUT;

	  l3_offset0 = ((next0 == SSVM_ETH_INPUT_NEXT_IP4_INPUT ||
			 next0 == SSVM_ETH_INPUT_NEXT_IP6_INPUT ||
			 next0 == SSVM_ETH_INPUT_NEXT_MPLS_INPUT) ?
			sizeof (ethernet_header_t) : 0);

	  n_rx_bytes += b0->current_length
	    + b0->total_length_not_including_first_buffer;

	  b0->current_data += l3_offset0;
	  b0->current_length -= l3_offset0;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = intfc->vlib_hw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /*
	   * Turn this on if you run into
	   * "bad monkey" contexts, and you want to know exactly
	   * which nodes they've visited... See main.c...
	   */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      ssvm_eth_input_trace_t *tr;

	      vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 1);
	      vlib_set_trace_count (vm, node, --n_trace);

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->next_index = next0;
	      tr->sw_if_index = intfc->vlib_hw_if_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	  n_buffers--;
	  rx_queue_index++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

out:
  if (em->buffer_cache)
    _vec_len (em->buffer_cache) = saved_cache_size;
  else
    ASSERT (saved_cache_size == 0);

  ssvm_lock (sh, my_pid, 2);

  ASSERT (vec_len (intfc->rx_queue) > 0);

  n_available = (u32) pointer_to_uword (sh->opaque[CHUNK_POOL_NFREE]);
  elt_indices = (u32 *) (sh->opaque[CHUNK_POOL_FREELIST_INDEX]);

  clib_memcpy (&elt_indices[n_available], intfc->rx_queue,
	       vec_len (intfc->rx_queue) * sizeof (u32));

  n_available += vec_len (intfc->rx_queue);
  sh->opaque[CHUNK_POOL_NFREE] = uword_to_pointer (n_available, void *);

  ssvm_unlock (sh);

  vlib_error_count (vm, node->node_index, SSVM_ETH_INPUT_ERROR_NO_BUFFERS,
		    n_buffers);

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, thread_index,
     intfc->vlib_hw_if_index, rx_queue_index, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, rx_queue_index);

  return rx_queue_index;
}

static uword
ssvm_eth_input_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ssvm_eth_main_t *em = &ssvm_eth_main;
  ssvm_private_t *intfc;
  uword n_rx_packets = 0;

  vec_foreach (intfc, em->intfcs)
  {
    n_rx_packets += ssvm_eth_device_input (em, intfc, node);
  }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ssvm_eth_input_node) = {
  .function = ssvm_eth_input_node_fn,
  .name = "ssvm_eth_input",
  .vector_size = sizeof (u32),
  .format_trace = format_ssvm_eth_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .n_errors = ARRAY_LEN(ssvm_eth_input_error_strings),
  .error_strings = ssvm_eth_input_error_strings,

  .n_next_nodes = SSVM_ETH_INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [SSVM_ETH_INPUT_NEXT_DROP] = "error-drop",
        [SSVM_ETH_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
        [SSVM_ETH_INPUT_NEXT_IP4_INPUT] = "ip4-input",
        [SSVM_ETH_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [SSVM_ETH_INPUT_NEXT_MPLS_INPUT] = "mpls-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ssvm_eth_input_node, ssvm_eth_input_node_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
