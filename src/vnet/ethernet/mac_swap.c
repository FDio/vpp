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
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vnet/devices/pci/ige.h>
#include <vnet/devices/pci/ixge.h>
#include <vnet/devices/pci/ixgev.h>

typedef struct
{
  u32 cached_next_index;
  u32 cached_sw_if_index;

  /* Hash table to map sw_if_index to next node index */
  uword *next_node_index_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} mac_swap_main_t;

typedef struct
{
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u32 next_index;
} swap_trace_t;

/* packet trace format function */
static u8 *
format_swap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  swap_trace_t *t = va_arg (*args, swap_trace_t *);

  s = format (s, "SWAP: dst now %U src now %U sw_if_index %d next_index %d",
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src, t->sw_if_index, t->next_index);
  return s;
}

#define foreach_hw_driver_next                  \
  _(IP4)                                        \
  _(IP6)                                        \
  _(ETHERNET)

mac_swap_main_t mac_swap_main;

static vlib_node_registration_t mac_swap_node;

#define foreach_mac_swap_error \
_(SWAPS, "mac addresses swapped")

typedef enum
{
#define _(sym,str) MAC_SWAP_ERROR_##sym,
  foreach_mac_swap_error
#undef _
    MAC_SWAP_N_ERROR,
} mac_swap_error_t;

static char *mac_swap_error_strings[] = {
#define _(sym,string) string,
  foreach_mac_swap_error
#undef _
};

/*
 * To drop a pkt and increment one of the previous counters:
 *
 * set b0->error = error_node->errors[RANDOM_ERROR_SAMPLE];
 * set next0 to a disposition index bound to "error-drop".
 *
 * To manually increment the specific counter MAC_SWAP_ERROR_SAMPLE:
 *
 *  vlib_node_t *n = vlib_get_node (vm, mac_swap.index);
 *  u32 node_counter_base_index = n->error_heap_index;
 *  vlib_error_main_t * em = &vm->error_main;
 *  em->counters[node_counter_base_index + MAC_SWAP_ERROR_SAMPLE] += 1;
 *
 */

typedef enum
{
  MAC_SWAP_NEXT_DROP,
  MAC_SWAP_N_NEXT,
} mac_swap_next_t;

static uword
mac_swap_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  mac_swap_next_t next_index;
  mac_swap_main_t *msm = &mac_swap_main;
  vlib_node_t *n = vlib_get_node (vm, mac_swap_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  uword *p0, *p1;
	  u64 tmp0a, tmp0b;
	  u64 tmp1a, tmp1b;
	  ethernet_header_t *h0, *h1;


	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  next0 = msm->cached_next_index;
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  next1 = msm->cached_next_index;

	  if (PREDICT_FALSE (msm->cached_sw_if_index != sw_if_index0))
	    {
	      p0 =
		hash_get (msm->next_node_index_by_sw_if_index, sw_if_index0);
	      if (p0 == 0)
		{
		  vnet_hw_interface_t *hw0;

		  hw0 = vnet_get_sup_hw_interface (msm->vnet_main,
						   sw_if_index0);

		  next0 = vlib_node_add_next (msm->vlib_main,
					      mac_swap_node.index,
					      hw0->output_node_index);
		  hash_set (msm->next_node_index_by_sw_if_index,
			    sw_if_index0, next0);
		}
	      else
		next0 = p0[0];
	      msm->cached_sw_if_index = sw_if_index0;
	      msm->cached_next_index = next0;
	      next1 = next0;
	    }
	  if (PREDICT_FALSE (msm->cached_sw_if_index != sw_if_index1))
	    {
	      p1 =
		hash_get (msm->next_node_index_by_sw_if_index, sw_if_index1);
	      if (p1 == 0)
		{
		  vnet_hw_interface_t *hw1;

		  hw1 = vnet_get_sup_hw_interface (msm->vnet_main,
						   sw_if_index1);

		  next1 = vlib_node_add_next (msm->vlib_main,
					      mac_swap_node.index,
					      hw1->output_node_index);
		  hash_set (msm->next_node_index_by_sw_if_index,
			    sw_if_index1, next1);
		}
	      else
		next1 = p1[0];
	      msm->cached_sw_if_index = sw_if_index1;
	      msm->cached_next_index = next1;
	    }

	  em->counters[node_counter_base_index + MAC_SWAP_ERROR_SWAPS] += 2;

	  /* reset buffer so we always point at the MAC hdr */
	  vlib_buffer_reset (b0);
	  vlib_buffer_reset (b1);
	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  /* Swap 2 x src and dst mac addresses using 8-byte load/stores */
	  tmp0a = clib_net_to_host_u64 (((u64 *) (h0->dst_address))[0]);
	  tmp1a = clib_net_to_host_u64 (((u64 *) (h1->dst_address))[0]);
	  tmp0b = clib_net_to_host_u64 (((u64 *) (h0->src_address))[0]);
	  tmp1b = clib_net_to_host_u64 (((u64 *) (h1->src_address))[0]);
	  ((u64 *) (h0->dst_address))[0] = clib_host_to_net_u64 (tmp0b);
	  ((u64 *) (h1->dst_address))[0] = clib_host_to_net_u64 (tmp1b);
	  /* Move the ethertype from "b" to "a" */
	  tmp0a &= ~(0xFFFF);
	  tmp1a &= ~(0xFFFF);
	  tmp0a |= tmp0b & 0xFFFF;
	  ((u64 *) (h0->src_address))[0] = clib_host_to_net_u64 (tmp0a);
	  tmp1a |= tmp1b & 0xFFFF;
	  ((u64 *) (h1->src_address))[0] = clib_host_to_net_u64 (tmp1a);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  swap_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  swap_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  uword *p0;
	  u64 tmp0a, tmp0b;
	  ethernet_header_t *h0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  next0 = msm->cached_next_index;

	  if (PREDICT_FALSE (msm->cached_sw_if_index != sw_if_index0))
	    {
	      p0 =
		hash_get (msm->next_node_index_by_sw_if_index, sw_if_index0);
	      if (p0 == 0)
		{
		  vnet_hw_interface_t *hw0;

		  hw0 = vnet_get_sup_hw_interface (msm->vnet_main,
						   sw_if_index0);

		  next0 = vlib_node_add_next (msm->vlib_main,
					      mac_swap_node.index,
					      hw0->output_node_index);
		  hash_set (msm->next_node_index_by_sw_if_index,
			    sw_if_index0, next0);
		}
	      else
		next0 = p0[0];
	      msm->cached_sw_if_index = sw_if_index0;
	      msm->cached_next_index = next0;
	    }

	  em->counters[node_counter_base_index + MAC_SWAP_ERROR_SWAPS] += 1;

	  /* reset buffer so we always point at the MAC hdr */
	  vlib_buffer_reset (b0);
	  h0 = vlib_buffer_get_current (b0);

	  /* Exchange src and dst, preserve the ethertype */
	  tmp0a = clib_net_to_host_u64 (((u64 *) (h0->dst_address))[0]);
	  tmp0b = clib_net_to_host_u64 (((u64 *) (h0->src_address))[0]);
	  ((u64 *) (h0->dst_address))[0] = clib_host_to_net_u64 (tmp0b);
	  tmp0a &= ~(0xFFFF);
	  tmp0a |= tmp0b & 0xFFFF;
	  ((u64 *) (h0->src_address))[0] = clib_host_to_net_u64 (tmp0a);

	  /* ship it */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      swap_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mac_swap_node,static) = {
  .function = mac_swap_node_fn,
  .name = "mac-swap",
  .vector_size = sizeof (u32),
  .format_trace = format_swap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mac_swap_error_strings),
  .error_strings = mac_swap_error_strings,

  .n_next_nodes = MAC_SWAP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [MAC_SWAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

clib_error_t *
mac_swap_init (vlib_main_t * vm)
{
  mac_swap_main_t *msm = &mac_swap_main;

  msm->next_node_index_by_sw_if_index = hash_create (0, sizeof (uword));
  msm->cached_next_index = (u32) ~ 0;
  msm->cached_sw_if_index = (u32) ~ 0;
  msm->vlib_main = vm;
  msm->vnet_main = vnet_get_main ();

  /* Driver RX nodes send pkts here... */
#define _(a) ixge_set_next_node (IXGE_RX_NEXT_##a##_INPUT, "mac-swap");
  foreach_hw_driver_next
#undef _
#define _(a) ixgev_set_next_node (IXGEV_RX_NEXT_##a##_INPUT, "mac-swap");
    foreach_hw_driver_next
#undef _
#define _(a) ige_set_next_node (IGE_RX_NEXT_##a##_INPUT, "mac-swap");
    foreach_hw_driver_next
#undef _
    return 0;
}

VLIB_INIT_FUNCTION (mac_swap_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
