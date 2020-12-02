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
/*
 * interface_output.c: interface output node
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/feature/feature.h>
#include <vnet/classify/trace_classify.h>
#include <vnet/interface_output.h>

typedef struct
{
  u32 sw_if_index;
  u32 flags;
  u8 data[128 - 2 * sizeof (u32)];
}
interface_output_trace_t;

#ifndef CLIB_MARCH_VARIANT
u8 *
format_vnet_interface_output_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  vlib_node_t *node = va_arg (*va, vlib_node_t *);
  interface_output_trace_t *t = va_arg (*va, interface_output_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  u32 indent;

  if (t->sw_if_index != (u32) ~ 0)
    {
      indent = format_get_indent (s);

      if (pool_is_free_index
	  (vnm->interface_main.sw_interfaces, t->sw_if_index))
	{
	  /* the interface may have been deleted by the time the trace is printed */
	  s = format (s, "sw_if_index: %d ", t->sw_if_index);
	}
      else
	{
	  si = vnet_get_sw_interface (vnm, t->sw_if_index);
	  s =
	    format (s, "%U ", format_vnet_sw_interface_name, vnm, si,
		    t->flags);
	}
      s =
	format (s, "\n%U%U", format_white_space, indent,
		node->format_buffer ? node->format_buffer : format_hex_bytes,
		t->data, sizeof (t->data));
    }
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

static void
vnet_interface_output_trace (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame, uword n_buffers)
{
  u32 n_left, *from;

  n_left = n_buffers;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      interface_output_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  t0->flags = b0->flags;
	  clib_memcpy_fast (t0->data, vlib_buffer_get_current (b0),
			    sizeof (t0->data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  t1->flags = b1->flags;
	  clib_memcpy_fast (t1->data, vlib_buffer_get_current (b1),
			    sizeof (t1->data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      interface_output_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  t0->flags = b0->flags;
	  clib_memcpy_fast (t0->data, vlib_buffer_get_current (b0),
			    sizeof (t0->data));
	}
      from += 1;
      n_left -= 1;
    }
}

static_always_inline uword
vnet_interface_output_node_inline (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame,
				   vnet_main_t * vnm,
				   vnet_hw_interface_t * hi,
				   int do_tx_offloads)
{
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
  vnet_sw_interface_t *si;
  u32 n_left_to_tx, *from, *from_end, *to_tx;
  u32 n_bytes, n_buffers, n_packets;
  u32 n_bytes_b0, n_bytes_b1, n_bytes_b2, n_bytes_b3;
  u32 thread_index = vm->thread_index;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 next_index = VNET_INTERFACE_OUTPUT_NEXT_TX;
  u32 current_config_index = ~0;
  u8 arc = im->output_feature_arc_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  n_buffers = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vnet_interface_output_trace (vm, node, frame, n_buffers);

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, b, n_buffers);

  if (rt->is_deleted)
    return vlib_error_drop_buffers (vm, node, from,
				    /* buffer stride */ 1,
				    n_buffers,
				    VNET_INTERFACE_OUTPUT_NEXT_DROP,
				    node->node_index,
				    VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DELETED);

  si = vnet_get_sw_interface (vnm, rt->sw_if_index);
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);
  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ||
      !(hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    {
      vlib_simple_counter_main_t *cm;

      cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			     VNET_INTERFACE_COUNTER_TX_ERROR);
      vlib_increment_simple_counter (cm, thread_index,
				     rt->sw_if_index, n_buffers);

      return vlib_error_drop_buffers (vm, node, from,
				      /* buffer stride */ 1,
				      n_buffers,
				      VNET_INTERFACE_OUTPUT_NEXT_DROP,
				      node->node_index,
				      VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DOWN);
    }

  from_end = from + n_buffers;

  /* Total byte count of all buffers. */
  n_bytes = 0;
  n_packets = 0;

  /* interface-output feature arc handling */
  if (PREDICT_FALSE (vnet_have_features (arc, rt->sw_if_index)))
    {
      vnet_feature_config_main_t *fcm;
      fcm = vnet_feature_get_config_main (arc);
      current_config_index = vnet_get_feature_config_index (arc,
							    rt->sw_if_index);
      vnet_get_config_data (&fcm->config_main, &current_config_index,
			    &next_index, 0);
    }

  while (from < from_end)
    {
      /* Get new next frame since previous incomplete frame may have less
         than VNET_FRAME_SIZE vectors in it. */
      vlib_get_new_next_frame (vm, node, next_index, to_tx, n_left_to_tx);

      while (from + 8 <= from_end && n_left_to_tx >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  u32 tx_swif0, tx_swif1, tx_swif2, tx_swif3;
	  u32 or_flags;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  bi2 = from[2];
	  bi3 = from[3];
	  to_tx[0] = bi0;
	  to_tx[1] = bi1;
	  to_tx[2] = bi2;
	  to_tx[3] = bi3;

	  or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

	  from += 4;
	  to_tx += 4;
	  n_left_to_tx -= 4;

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b[0]->current_length > 0);
	  ASSERT (b[1]->current_length > 0);
	  ASSERT (b[2]->current_length > 0);
	  ASSERT (b[3]->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b[0]);
	  n_bytes_b1 = vlib_buffer_length_in_chain (vm, b[1]);
	  n_bytes_b2 = vlib_buffer_length_in_chain (vm, b[2]);
	  n_bytes_b3 = vlib_buffer_length_in_chain (vm, b[3]);
	  tx_swif0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  tx_swif1 = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	  tx_swif2 = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
	  tx_swif3 = vnet_buffer (b[3])->sw_if_index[VLIB_TX];

	  n_bytes += n_bytes_b0 + n_bytes_b1;
	  n_bytes += n_bytes_b2 + n_bytes_b3;
	  n_packets += 4;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      vnet_buffer (b[0])->feature_arc_index = arc;
	      vnet_buffer (b[1])->feature_arc_index = arc;
	      vnet_buffer (b[2])->feature_arc_index = arc;
	      vnet_buffer (b[3])->feature_arc_index = arc;
	      b[0]->current_config_index = current_config_index;
	      b[1]->current_config_index = current_config_index;
	      b[2]->current_config_index = current_config_index;
	      b[3]->current_config_index = current_config_index;
	    }

	  /* update vlan subif tx counts, if required */
	  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
	    {
	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif0, 1,
					       n_bytes_b0);
	    }

	  if (PREDICT_FALSE (tx_swif1 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif1, 1,
					       n_bytes_b1);
	    }

	  if (PREDICT_FALSE (tx_swif2 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif2, 1,
					       n_bytes_b2);
	    }
	  if (PREDICT_FALSE (tx_swif3 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif3, 1,
					       n_bytes_b3);
	    }

	  if (do_tx_offloads)
	    {
	      u32 vnet_buffer_offload_flags =
		(VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
		 VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
		 VNET_BUFFER_F_OFFLOAD_IP_CKSUM);
	      if (or_flags & vnet_buffer_offload_flags)
		{
		  if (b[0]->flags & vnet_buffer_offload_flags)
		    vnet_calc_checksums_inline
		      (vm, b[0],
		       b[0]->flags & VNET_BUFFER_F_IS_IP4,
		       b[0]->flags & VNET_BUFFER_F_IS_IP6);
		  if (b[1]->flags & vnet_buffer_offload_flags)
		    vnet_calc_checksums_inline
		      (vm, b[1],
		       b[1]->flags & VNET_BUFFER_F_IS_IP4,
		       b[1]->flags & VNET_BUFFER_F_IS_IP6);
		  if (b[2]->flags & vnet_buffer_offload_flags)
		    vnet_calc_checksums_inline
		      (vm, b[2],
		       b[2]->flags & VNET_BUFFER_F_IS_IP4,
		       b[2]->flags & VNET_BUFFER_F_IS_IP6);
		  if (b[3]->flags & vnet_buffer_offload_flags)
		    vnet_calc_checksums_inline
		      (vm, b[3],
		       b[3]->flags & VNET_BUFFER_F_IS_IP4,
		       b[3]->flags & VNET_BUFFER_F_IS_IP6);
		}
	    }
	  b += 4;

	}

      while (from + 1 <= from_end && n_left_to_tx >= 1)
	{
	  u32 bi0;
	  u32 tx_swif0;

	  bi0 = from[0];
	  to_tx[0] = bi0;
	  from += 1;
	  to_tx += 1;
	  n_left_to_tx -= 1;

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b[0]->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b[0]);
	  tx_swif0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  n_bytes += n_bytes_b0;
	  n_packets += 1;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      vnet_buffer (b[0])->feature_arc_index = arc;
	      b[0]->current_config_index = current_config_index;
	    }

	  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif0, 1,
					       n_bytes_b0);
	    }

	  if (do_tx_offloads)
	    {
	      if (b[0]->flags &
		  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
		   VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
		   VNET_BUFFER_F_OFFLOAD_IP_CKSUM))
		vnet_calc_checksums_inline
		  (vm, b[0],
		   b[0]->flags & VNET_BUFFER_F_IS_IP4,
		   b[0]->flags & VNET_BUFFER_F_IS_IP6);
	    }
	  b += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_tx);
    }

  /* Update main interface stats. */
  vlib_increment_combined_counter (im->combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_TX,
				   thread_index,
				   rt->sw_if_index, n_packets, n_bytes);
  return n_buffers;
}

static_always_inline void vnet_interface_pcap_tx_trace
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame,
   int sw_if_index_from_buffer)
{
  u32 n_left_from, *from;
  u32 sw_if_index;
  vnet_pcap_t *pp = &vlib_global_main.pcap;

  if (PREDICT_TRUE (pp->pcap_tx_enable == 0))
    return;

  if (sw_if_index_from_buffer == 0)
    {
      vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
      sw_if_index = rt->sw_if_index;
    }
  else
    sw_if_index = ~0;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      int classify_filter_result;
      u32 bi0 = from[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      from++;
      n_left_from--;

      if (pp->filter_classify_table_index != ~0)
	{
	  classify_filter_result =
	    vnet_is_packet_traced_inline
	    (b0, pp->filter_classify_table_index, 0 /* full classify */ );
	  if (classify_filter_result)
	    pcap_add_buffer (&pp->pcap_main, vm, bi0, pp->max_bytes_per_pkt);
	  continue;
	}

      if (sw_if_index_from_buffer)
	sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      if (pp->pcap_sw_if_index == 0 || pp->pcap_sw_if_index == sw_if_index)
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  vnet_hw_interface_t *hi =
	    vnet_get_sup_hw_interface (vnm, sw_if_index);
	  /* Capture pkt if not filtered, or if filter hits */
	  if (hi->trace_classify_table_index == ~0 ||
	      vnet_is_packet_traced_inline
	      (b0, hi->trace_classify_table_index, 0 /* full classify */ ))
	    pcap_add_buffer (&pp->pcap_main, vm, bi0, pp->max_bytes_per_pkt);
	}
    }
}

static vlib_node_function_t CLIB_MULTIARCH_FN (vnet_interface_output_node);

static uword
CLIB_MULTIARCH_FN (vnet_interface_output_node) (vlib_main_t * vm,
						vlib_node_runtime_t * node,
						vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);

  vnet_interface_pcap_tx_trace (vm, node, frame,
				0 /* sw_if_index_from_buffer */ );

  if (hi->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD)
    return vnet_interface_output_node_inline (vm, node, frame, vnm, hi,
					      /* do_tx_offloads */ 0);
  else
    return vnet_interface_output_node_inline (vm, node, frame, vnm, hi,
					      /* do_tx_offloads */ 1);
}

CLIB_MARCH_FN_REGISTRATION (vnet_interface_output_node);

#ifndef CLIB_MARCH_VARIANT
vlib_node_function_t *
vnet_interface_output_node_get (vlib_main_t * vm)
{
  vlib_node_function_t *fn = 0;
  vlib_node_fn_registration_t *fnr;
  char *name = 0;
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "interface-output");
  ASSERT (node);

  /* search for the same name */
  fnr = node->node_fn_registrations;
  while (fnr)
    {
      if (fnr->function == node->function)
	{
	  name = fnr->name;
	  break;
	}
      fnr = fnr->next_registration;
    }

  if (name)
    {
      fn = CLIB_MARCH_FN_POINTER_BY_NAME (vnet_interface_output_node, name);
    }
  if (!fn)			/* revert to march type selection if search failed */
    {
      fn = CLIB_MARCH_FN_POINTER (vnet_interface_output_node);
    }
  return fn;
}
#endif /* CLIB_MARCH_VARIANT */

/* Use buffer's sw_if_index[VNET_TX] to choose output interface. */
VLIB_NODE_FN (vnet_per_buffer_interface_output_node) (vlib_main_t * vm,
						      vlib_node_runtime_t *
						      node,
						      vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_to_next, *from, *to_next;
  u32 n_left_from, next_index;

  vnet_interface_pcap_tx_trace (vm, node, frame,
				1 /* sw_if_index_from_buffer */ );

  n_left_from = frame->n_vectors;

  from = vlib_frame_vector_args (frame);
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1, next0, next1;
	  vlib_buffer_t *b0, *b1;
	  vnet_hw_interface_t *hi0, *hi1;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  hi0 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b0)->sw_if_index
				       [VLIB_TX]);
	  hi1 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b1)->sw_if_index
				       [VLIB_TX]);

	  next0 = hi0->output_node_next_index;
	  next1 = hi1->output_node_next_index;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  vnet_hw_interface_t *hi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  hi0 =
	    vnet_get_sup_hw_interface (vnm,
				       vnet_buffer (b0)->sw_if_index
				       [VLIB_TX]);

	  next0 = hi0->output_node_next_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

typedef struct vnet_error_trace_t_
{
  u32 sw_if_index;
  i8 details_valid;
  u8 is_ip6;
  u8 pad[2];
  u16 mactype;
  ip46_address_t src, dst;
} vnet_error_trace_t;

static u8 *
format_vnet_error_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vnet_error_trace_t *t = va_arg (*va, vnet_error_trace_t *);

  /* Normal, non-catchup trace */
  if (t->details_valid == 0)
    {
      s = format (s, "rx:%U", format_vnet_sw_if_index_name,
		  vnet_get_main (), t->sw_if_index);
    }
  else if (t->details_valid == 1)
    {
      /* The trace capture code didn't understant the mactype */
      s = format (s, "mactype 0x%4x (not decoded)", t->mactype);
    }
  else if (t->details_valid == 2)
    {
      /* Dump the src/dst addresses */
      if (t->is_ip6 == 0)
	s = format (s, "IP4: %U -> %U",
		    format_ip4_address, &t->src.ip4,
		    format_ip4_address, &t->dst.ip4);
      else
	s = format (s, "IP6: %U -> %U",
		    format_ip6_address, &t->src.ip6,
		    format_ip6_address, &t->dst.ip6);
    }
  return s;
}

static void
interface_trace_buffers (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left, *buffers;

  buffers = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      vnet_error_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, buffers[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[3], LOAD);

      bi0 = buffers[0];
      bi1 = buffers[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0,
			       STRUCT_OFFSET_OF (vnet_error_trace_t, pad));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t0->details_valid = 0;
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1,
			       STRUCT_OFFSET_OF (vnet_error_trace_t, pad));
	  t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  t1->details_valid = 0;
	}
      buffers += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      vnet_error_trace_t *t0;

      bi0 = buffers[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0,
			       STRUCT_OFFSET_OF (vnet_error_trace_t, pad));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t0->details_valid = 0;
	}
      buffers += 1;
      n_left -= 1;
    }
}

typedef enum
{
  VNET_ERROR_DISPOSITION_DROP,
  VNET_ERROR_DISPOSITION_PUNT,
  VNET_ERROR_N_DISPOSITION,
} vnet_error_disposition_t;

static void
drop_catchup_trace (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_buffer_t * b)
{
  /* Can we safely rewind the buffer? If not, fagedaboudit */
  if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    {
      vnet_error_trace_t *t;
      ip4_header_t *ip4;
      ip6_header_t *ip6;
      ethernet_header_t *eh;
      i16 delta;

      t = vlib_add_trace (vm, node, b, sizeof (*t));
      delta = vnet_buffer (b)->l2_hdr_offset - b->current_data;
      vlib_buffer_advance (b, delta);

      eh = vlib_buffer_get_current (b);
      /* Save mactype */
      t->mactype = clib_net_to_host_u16 (eh->type);
      t->details_valid = 1;
      switch (t->mactype)
	{
	case ETHERNET_TYPE_IP4:
	  ip4 = (void *) (eh + 1);
	  t->details_valid = 2;
	  t->is_ip6 = 0;
	  t->src.ip4.as_u32 = ip4->src_address.as_u32;
	  t->dst.ip4.as_u32 = ip4->dst_address.as_u32;
	  break;

	case ETHERNET_TYPE_IP6:
	  ip6 = (void *) (eh + 1);
	  t->details_valid = 2;
	  t->is_ip6 = 1;
	  clib_memcpy_fast (t->src.as_u8, ip6->src_address.as_u8,
			    sizeof (ip6_address_t));
	  clib_memcpy_fast (t->dst.as_u8, ip6->dst_address.as_u8,
			    sizeof (ip6_address_t));
	  break;

	default:
	  /* Dunno, do nothing, leave details_valid alone */
	  break;
	}
      /* Restore current data (probably unnecessary) */
      vlib_buffer_advance (b, -delta);
    }
}

static_always_inline uword
interface_drop_punt (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame,
		     vnet_error_disposition_t disposition)
{
  u32 *from, n_left, thread_index, *sw_if_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 sw_if_indices[VLIB_FRAME_SIZE];
  vlib_simple_counter_main_t *cm;
  u16 nexts[VLIB_FRAME_SIZE];
  u32 n_trace;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  sw_if_index = sw_if_indices;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* "trace add error-drop NNN?" */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      /* If pkts aren't otherwise traced... */
      if ((node->flags & VLIB_NODE_FLAG_TRACE) == 0)
	{
	  /* Trace them from here */
	  node->flags |= VLIB_NODE_FLAG_TRACE;
	  while (n_trace && n_left)
	    {
	      if (PREDICT_TRUE
		  (vlib_trace_buffer (vm, node, 0 /* next_index */ , b[0],
				      0 /* follow chain */ )))
		{
		  /*
		   * Here we have a wireshark dissector problem.
		   * Packets may be well-formed, or not. We
		   * must not blow chunks in any case.
		   *
		   * Try to produce trace records which will help
		   * folks understand what's going on.
		   */
		  drop_catchup_trace (vm, node, b[0]);
		  n_trace--;
		}
	      n_left--;
	      b++;
	    }
	}

      vlib_set_trace_count (vm, node, n_trace);
      b = bufs;
      n_left = frame->n_vectors;
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    interface_trace_buffers (vm, node, frame);

  /* All going to drop regardless, this is just a counting exercise */
  clib_memset (nexts, 0, sizeof (nexts));

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			 (disposition == VNET_ERROR_DISPOSITION_PUNT
			  ? VNET_INTERFACE_COUNTER_PUNT
			  : VNET_INTERFACE_COUNTER_DROP));

  /* collect the array of interfaces first ... */
  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  /* Prefetch 8 ahead - there's not much going on in each iteration */
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	}
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      sw_if_index += 4;
      n_left -= 4;
      b += 4;
    }
  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      sw_if_index += 1;
      n_left -= 1;
      b += 1;
    }

  /* ... then count against them in blocks */
  n_left = frame->n_vectors;

  while (n_left)
    {
      vnet_sw_interface_t *sw_if0;
      u16 off, count;

      off = frame->n_vectors - n_left;

      sw_if_index = sw_if_indices + off;

      count = clib_count_equal_u32 (sw_if_index, n_left);
      n_left -= count;

      vlib_increment_simple_counter (cm, thread_index, sw_if_index[0], count);

      /* Increment super-interface drop/punt counters for
         sub-interfaces. */
      sw_if0 = vnet_get_sw_interface (vnm, sw_if_index[0]);
      if (sw_if0->sup_sw_if_index != sw_if_index[0])
	vlib_increment_simple_counter
	  (cm, thread_index, sw_if0->sup_sw_if_index, count);
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

static inline void
pcap_drop_trace (vlib_main_t * vm,
		 vnet_interface_main_t * im,
		 vnet_pcap_t * pp, vlib_frame_t * f)
{
  u32 *from;
  u32 n_left = f->n_vectors;
  vlib_buffer_t *b0, *p1;
  u32 bi0;
  i16 save_current_data;
  u16 save_current_length;
  vlib_error_main_t *em = &vm->error_main;
  int do_trace = 0;


  from = vlib_frame_vector_args (f);

  while (n_left > 0)
    {
      if (PREDICT_TRUE (n_left > 1))
	{
	  p1 = vlib_get_buffer (vm, from[1]);
	  vlib_prefetch_buffer_header (p1, LOAD);
	}

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      from++;
      n_left--;

      /* See if we're pointedly ignoring this specific error */
      if (im->pcap_drop_filter_hash
	  && hash_get (im->pcap_drop_filter_hash, b0->error))
	continue;

      do_trace = (pp->pcap_sw_if_index == 0) ||
	pp->pcap_sw_if_index == vnet_buffer (b0)->sw_if_index[VLIB_RX];

      if (PREDICT_FALSE
	  (do_trace == 0 && pp->filter_classify_table_index != ~0))
	{
	  do_trace = vnet_is_packet_traced_inline
	    (b0, pp->filter_classify_table_index, 0 /* full classify */ );
	}

      /* Trace all drops, or drops received on a specific interface */
      if (do_trace)
	{
	  save_current_data = b0->current_data;
	  save_current_length = b0->current_length;

	  /*
	   * Typically, we'll need to rewind the buffer
	   * if l2_hdr_offset is valid, make sure to rewind to the start of
	   * the L2 header. This may not be the buffer start in case we pop-ed
	   * vlan tags.
	   * Otherwise, rewind to buffer start and hope for the best.
	   */
	  if (b0->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
	    {
	      if (b0->current_data > vnet_buffer (b0)->l2_hdr_offset)
		vlib_buffer_advance (b0,
				     vnet_buffer (b0)->l2_hdr_offset -
				     b0->current_data);
	    }
	  else if (b0->current_data > 0)
	    vlib_buffer_advance (b0, (word) - b0->current_data);

	  {
	    vlib_buffer_t *last = b0;
	    u32 error_node_index;
	    int drop_string_len;
	    vlib_node_t *n;
	    /* Length of the error string */
	    int error_string_len =
	      clib_strnlen (em->counters_heap[b0->error].name, 128);

	    /* Dig up the drop node */
	    error_node_index = vm->node_main.node_by_error[b0->error];
	    n = vlib_get_node (vm, error_node_index);

	    /* Length of full drop string, w/ "nodename: " prepended */
	    drop_string_len = error_string_len + vec_len (n->name) + 2;

	    /* Find the last buffer in the chain */
	    while (last->flags & VLIB_BUFFER_NEXT_PRESENT)
	      last = vlib_get_buffer (vm, last->next_buffer);

	    /*
	     * Append <nodename>: <error-string> to the capture,
	     * only if we can do that without allocating a new buffer.
	     */
	    if (PREDICT_TRUE ((last->current_data + last->current_length)
			      < (VLIB_BUFFER_DEFAULT_DATA_SIZE
				 - drop_string_len)))
	      {
		clib_memcpy_fast (last->data + last->current_data +
				  last->current_length, n->name,
				  vec_len (n->name));
		clib_memcpy_fast (last->data + last->current_data +
				  last->current_length + vec_len (n->name),
				  ": ", 2);
		clib_memcpy_fast (last->data + last->current_data +
				  last->current_length + vec_len (n->name) +
				  2, em->counters_heap[b0->error].name,
				  error_string_len);
		last->current_length += drop_string_len;
		b0->flags &= ~(VLIB_BUFFER_TOTAL_LENGTH_VALID);
		pcap_add_buffer (&pp->pcap_main, vm, bi0,
				 pp->max_bytes_per_pkt);
		last->current_length -= drop_string_len;
		b0->current_data = save_current_data;
		b0->current_length = save_current_length;
		continue;
	      }
	  }

	  /*
	   * Didn't have space in the last buffer, here's the dropped
	   * packet as-is
	   */
	  pcap_add_buffer (&pp->pcap_main, vm, bi0, pp->max_bytes_per_pkt);

	  b0->current_data = save_current_data;
	  b0->current_length = save_current_length;
	}
    }
}

#ifndef CLIB_MARCH_VARIANT
void
vnet_pcap_drop_trace_filter_add_del (u32 error_index, int is_add)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;

  if (im->pcap_drop_filter_hash == 0)
    im->pcap_drop_filter_hash = hash_create (0, sizeof (uword));

  if (is_add)
    hash_set (im->pcap_drop_filter_hash, error_index, 1);
  else
    hash_unset (im->pcap_drop_filter_hash, error_index);
}
#endif /* CLIB_MARCH_VARIANT */

VLIB_NODE_FN (interface_drop) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  vnet_pcap_t *pp = &vlib_global_main.pcap;

  if (PREDICT_FALSE (pp->pcap_drop_enable))
    pcap_drop_trace (vm, im, pp, frame);

  return interface_drop_punt (vm, node, frame, VNET_ERROR_DISPOSITION_DROP);
}

VLIB_NODE_FN (interface_punt) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return interface_drop_punt (vm, node, frame, VNET_ERROR_DISPOSITION_PUNT);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (interface_drop) = {
  .name = "error-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_vnet_error_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (interface_punt) = {
  .name = "error-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_vnet_error_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "punt",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vnet_per_buffer_interface_output_node) = {
  .name = "interface-output",
  .vector_size = sizeof (u32),
};
/* *INDENT-ON* */

static uword
interface_tx_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 last_sw_if_index = ~0;
  vlib_frame_t *to_frame = 0;
  vnet_hw_interface_t *hw = 0;
  u32 *from, *to_next = 0;
  u32 n_left_from;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;

      bi0 = from[0];
      from++;
      n_left_from--;
      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      if (PREDICT_FALSE ((last_sw_if_index != sw_if_index0) || to_frame == 0))
	{
	  if (to_frame)
	    {
	      hw = vnet_get_sup_hw_interface (vnm, last_sw_if_index);
	      vlib_put_frame_to_node (vm, hw->tx_node_index, to_frame);
	    }
	  last_sw_if_index = sw_if_index0;
	  hw = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  to_frame = vlib_get_frame_to_node (vm, hw->tx_node_index);
	  to_next = vlib_frame_vector_args (to_frame);
	}

      to_next[0] = bi0;
      to_next++;
      to_frame->n_vectors++;
    }
  vlib_put_frame_to_node (vm, hw->tx_node_index, to_frame);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (interface_tx) = {
  .function = interface_tx_node_fn,
  .name = "interface-tx",
  .vector_size = sizeof (u32),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_ARC_INIT (interface_output, static) =
{
  .arc_name  = "interface-output",
  .start_nodes = VNET_FEATURES (0),
  .last_in_arc = "interface-tx",
  .arc_index_ptr = &vnet_main.interface_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (span_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "span-output",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

VNET_FEATURE_INIT (ipsec_if_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "ipsec-if-output",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

VNET_FEATURE_INIT (interface_tx, static) = {
  .arc_name = "interface-output",
  .node_name = "interface-tx",
  .runs_before = 0,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
vnet_per_buffer_interface_output_hw_interface_add_del (vnet_main_t * vnm,
						       u32 hw_if_index,
						       u32 is_create)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 next_index;

  if (hi->output_node_index == 0)
    return 0;

  next_index = vlib_node_add_next
    (vnm->vlib_main, vnet_per_buffer_interface_output_node.index,
     hi->output_node_index);
  hi->output_node_next_index = next_index;

  return 0;
}

VNET_HW_INTERFACE_ADD_DEL_FUNCTION
  (vnet_per_buffer_interface_output_hw_interface_add_del);

void
vnet_set_interface_output_node (vnet_main_t * vnm,
				u32 hw_if_index, u32 node_index)
{
  ASSERT (node_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 next_index = vlib_node_add_next
    (vnm->vlib_main, vnet_per_buffer_interface_output_node.index, node_index);
  hi->output_node_next_index = next_index;
  hi->output_node_index = node_index;
}
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
