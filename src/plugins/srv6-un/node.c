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
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <srv6-un/un.h>


/******************************* Packet tracing *******************************/
typedef struct
{
  u32 localsid_index;
} srv6_un_localsid_trace_t;


static u8 *
format_srv6_un_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_un_localsid_trace_t *t = va_arg (*args, srv6_un_localsid_trace_t *);

  return format (s, "SRv6-uN-localsid: localsid_index %d", t->localsid_index);
}

/********************************* Next nodes *********************************/
typedef enum
{
  SRV6_UN_LOCALSID_NEXT_ERROR,
  SRV6_UN_LOCALSID_NEXT_IP6LOOKUP,
  SRV6_UN_LOCALSID_N_NEXT,
} srv6_un_localsid_next_t;

/******************************* Local SID node *******************************/

/**
 * @brief Graph node for applying SRv6 uN.
 */
static uword
srv6_un_localsid_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  u32 next0 = SRV6_UN_LOCALSID_NEXT_IP6LOOKUP;
	  ip6_sr_localsid_t *ls0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 =
	    pool_elt_at_index (sm->localsids,
			       vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

	  /* Set Destination Address to Last Segment (index 0) */
	  ip0->dst_address.as_u16[2] = ip0->dst_address.as_u16[3];
	  ip0->dst_address.as_u16[3] = ip0->dst_address.as_u16[4];
	  ip0->dst_address.as_u16[4] = ip0->dst_address.as_u16[5];
	  ip0->dst_address.as_u16[5] = ip0->dst_address.as_u16[6];
	  ip0->dst_address.as_u16[6] = ip0->dst_address.as_u16[7];
	  ip0->dst_address.as_u16[7] = 0x0000;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_un_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->localsid_index = ls0 - sm->localsids;
	    }

	  /* This increments the SRv6 per LocalSID counters. */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_UN_LOCALSID_NEXT_ERROR) ?
					    &(sm->sr_ls_invalid_counters) :
					    &(sm->sr_ls_valid_counters)),
					   thread_index, ls0 - sm->localsids,
					   1, vlib_buffer_length_in_chain (vm,
									   b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_un_localsid_node) = {
  .function = srv6_un_localsid_fn,
  .name = "srv6-un-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_un_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SRV6_UN_LOCALSID_N_NEXT,
  .next_nodes = {
    [SRV6_UN_LOCALSID_NEXT_IP6LOOKUP] = "ip6-lookup",
    [SRV6_UN_LOCALSID_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
