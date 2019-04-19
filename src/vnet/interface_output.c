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
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/feature/feature.h>

typedef struct
{
  u32 sw_if_index;
  u32 flags;
  u16 gso_size;
  u8 gso_l4_hdr_sz;
  u8 data[128 - 3 * sizeof (u32)];
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
#define _(bit, name, v, x) \
          if (v && (t->flags & VNET_BUFFER_F_##name)) \
            s = format (s, "%s ", v);
      foreach_vnet_buffer_flag
#undef _
	if (t->flags & VNET_BUFFER_F_GSO)
	{
	  s = format (s, "\n%Ugso_sz %d gso_l4_hdr_sz %d",
		      format_white_space, indent + 2, t->gso_size,
		      t->gso_l4_hdr_sz);
	}
      s =
	format (s, "\n%U%U", format_white_space, indent,
		node->format_buffer ? node->format_buffer : format_hex_bytes,
		t->data, sizeof (t->data));
    }
  return s;
}

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
	  t0->gso_size = vnet_buffer2 (b0)->gso_size;
	  t0->gso_l4_hdr_sz = vnet_buffer2 (b0)->gso_l4_hdr_sz;
	  clib_memcpy_fast (t0->data, vlib_buffer_get_current (b0),
			    sizeof (t0->data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  t1->flags = b1->flags;
	  t1->gso_size = vnet_buffer2 (b1)->gso_size;
	  t1->gso_l4_hdr_sz = vnet_buffer2 (b1)->gso_l4_hdr_sz;
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
	  t0->gso_size = vnet_buffer2 (b0)->gso_size;
	  t0->gso_l4_hdr_sz = vnet_buffer2 (b0)->gso_l4_hdr_sz;
	  clib_memcpy_fast (t0->data, vlib_buffer_get_current (b0),
			    sizeof (t0->data));
	}
      from += 1;
      n_left -= 1;
    }
}

static_always_inline void
calc_checksums (vlib_main_t * vm, vlib_buffer_t * b)
{
  tcp_header_t *th;
  udp_header_t *uh;

  int is_ip4 = (b->flags & VNET_BUFFER_F_IS_IP4) != 0;
  int is_ip6 = (b->flags & VNET_BUFFER_F_IS_IP6) != 0;

  ASSERT (!(is_ip4 && is_ip6));

  th = (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
  uh = (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);

  if (is_ip4)
    {
      ip4_header_t *ip4;

      ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      if (b->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  th->checksum = 0;
	  th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}
      else if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
	uh->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
    }
  else if (is_ip6)
    {
      int bogus;
      ip6_header_t *ip6;

      ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  th->checksum = 0;
	  th->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
      else if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
	{
	  uh->checksum = 0;
	  uh->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
    }

  b->flags &= ~VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  b->flags &= ~VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  b->flags &= ~VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
}

static_always_inline u16
tso_alloc_tx_bufs (vlib_main_t * vm,
		   vnet_interface_per_thread_data_t * ptd,
		   vlib_buffer_t * b0, u16 l4_hdr_sz)
{
  u32 n_bytes_b0 = vlib_buffer_length_in_chain (vm, b0);
  u16 gso_size = vnet_buffer2 (b0)->gso_size;
  u16 l234_sz = vnet_buffer (b0)->l4_hdr_offset + l4_hdr_sz;
  /* rounded-up division */
  u16 n_bufs = (n_bytes_b0 - l234_sz + (gso_size - 1)) / gso_size;
  u16 n_alloc;

  ASSERT (n_bufs > 0);
  vec_validate (ptd->split_buffers, n_bufs - 1);

  n_alloc = vlib_buffer_alloc (vm, ptd->split_buffers, n_bufs);
  if (n_alloc < n_bufs)
    {
      vlib_buffer_free (vm, ptd->split_buffers, n_alloc);
      return 0;
    }
  return 1;
}

static_always_inline void
tso_init_buf_from_template_base (vlib_buffer_t * nb0, vlib_buffer_t * b0,
				 u32 flags, u16 length)
{
  nb0->current_data = 0;
  nb0->total_length_not_including_first_buffer = 0;
  nb0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | flags;
  clib_memcpy_fast (&nb0->opaque, &b0->opaque, sizeof (nb0->opaque));
  clib_memcpy_fast (nb0->data, b0->data, length);
  nb0->current_length = length;
}

static_always_inline void
tso_init_buf_from_template (vlib_main_t * vm, vlib_buffer_t * nb0,
			    vlib_buffer_t * b0, u16 template_data_sz,
			    u16 gso_size, u8 ** p_dst_ptr, u16 * p_dst_left,
			    u32 next_tcp_seq, u32 flags)
{
  tso_init_buf_from_template_base (nb0, b0, flags, template_data_sz);

  *p_dst_left =
    clib_min (gso_size,
	      vlib_buffer_get_default_data_size (vm) - template_data_sz);
  *p_dst_ptr = nb0->data + template_data_sz;

  tcp_header_t *tcp =
    (tcp_header_t *) (nb0->data + vnet_buffer (nb0)->l4_hdr_offset);
  tcp->seq_number = clib_host_to_net_u32 (next_tcp_seq);
}

static_always_inline void
tso_fixup_segmented_buf (vlib_buffer_t * b0, u8 tcp_flags, int is_ip6)
{
  u16 l3_hdr_offset = vnet_buffer (b0)->l3_hdr_offset;
  u16 l4_hdr_offset = vnet_buffer (b0)->l4_hdr_offset;
  ip4_header_t *ip4 = (ip4_header_t *) (b0->data + l3_hdr_offset);
  ip6_header_t *ip6 = (ip6_header_t *) (b0->data + l3_hdr_offset);
  tcp_header_t *tcp = (tcp_header_t *) (b0->data + l4_hdr_offset);

  tcp->flags = tcp_flags;

  if (is_ip6)
    ip6->payload_length =
      clib_host_to_net_u16 (b0->current_length -
			    vnet_buffer (b0)->l4_hdr_offset);
  else
    ip4->length =
      clib_host_to_net_u16 (b0->current_length -
			    vnet_buffer (b0)->l3_hdr_offset);
}

/**
 * Allocate the necessary number of ptd->split_buffers,
 * and segment the possibly chained buffer(s) from b0 into
 * there.
 *
 * Return the cumulative number of bytes sent or zero
 * if allocation failed.
 */

static_always_inline u32
tso_segment_buffer (vlib_main_t * vm, vnet_interface_per_thread_data_t * ptd,
		    int do_tx_offloads, u32 sbi0, vlib_buffer_t * sb0,
		    u32 n_bytes_b0)
{
  u32 n_tx_bytes = 0;
  int is_ip4 = sb0->flags & VNET_BUFFER_F_IS_IP4;
  int is_ip6 = sb0->flags & VNET_BUFFER_F_IS_IP6;
  ASSERT (is_ip4 || is_ip6);
  ASSERT (sb0->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID);
  ASSERT (sb0->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
  ASSERT (sb0->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
  u16 gso_size = vnet_buffer2 (sb0)->gso_size;

  int l4_hdr_sz = vnet_buffer2 (sb0)->gso_l4_hdr_sz;
  u8 save_tcp_flags = 0;
  u8 tcp_flags_no_fin_psh = 0;
  u32 next_tcp_seq = 0;

  tcp_header_t *tcp =
    (tcp_header_t *) (sb0->data + vnet_buffer (sb0)->l4_hdr_offset);
  next_tcp_seq = clib_net_to_host_u32 (tcp->seq_number);
  /* store original flags for last packet and reset FIN and PSH */
  save_tcp_flags = tcp->flags;
  tcp_flags_no_fin_psh = tcp->flags & ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
  tcp->checksum = 0;

  u32 default_bflags =
    sb0->flags & ~(VNET_BUFFER_F_GSO | VLIB_BUFFER_NEXT_PRESENT);
  u16 l234_sz = vnet_buffer (sb0)->l4_hdr_offset + l4_hdr_sz;
  int first_data_size = clib_min (gso_size, sb0->current_length - l234_sz);
  next_tcp_seq += first_data_size;

  if (PREDICT_FALSE (!tso_alloc_tx_bufs (vm, ptd, sb0, l4_hdr_sz)))
    return 0;

  vlib_buffer_t *b0 = vlib_get_buffer (vm, ptd->split_buffers[0]);
  tso_init_buf_from_template_base (b0, sb0, default_bflags,
				   l4_hdr_sz + first_data_size);

  u32 total_src_left = n_bytes_b0 - l234_sz - first_data_size;
  if (total_src_left)
    {
      /* Need to copy more segments */
      u8 *src_ptr, *dst_ptr;
      u16 src_left, dst_left;
      /* current source buffer */
      vlib_buffer_t *csb0 = sb0;
      u32 csbi0 = sbi0;
      /* current dest buffer */
      vlib_buffer_t *cdb0;
      u16 dbi = 1;		/* the buffer [0] is b0 */

      src_ptr = sb0->data + l234_sz + first_data_size;
      src_left = sb0->current_length - l234_sz - first_data_size;
      b0->current_length = l234_sz + first_data_size;

      tso_fixup_segmented_buf (b0, tcp_flags_no_fin_psh, is_ip6);
      if (do_tx_offloads)
	calc_checksums (vm, b0);

      /* grab a second buffer and prepare the loop */
      ASSERT (dbi < vec_len (ptd->split_buffers));
      cdb0 = vlib_get_buffer (vm, ptd->split_buffers[dbi++]);
      tso_init_buf_from_template (vm, cdb0, b0, l234_sz, gso_size, &dst_ptr,
				  &dst_left, next_tcp_seq, default_bflags);

      /* an arbitrary large number to catch the runaway loops */
      int nloops = 2000;
      while (total_src_left)
	{
	  if (nloops-- <= 0)
	    clib_panic ("infinite loop detected");
	  u16 bytes_to_copy = clib_min (src_left, dst_left);

	  clib_memcpy_fast (dst_ptr, src_ptr, bytes_to_copy);

	  src_left -= bytes_to_copy;
	  src_ptr += bytes_to_copy;
	  total_src_left -= bytes_to_copy;
	  dst_left -= bytes_to_copy;
	  dst_ptr += bytes_to_copy;
	  next_tcp_seq += bytes_to_copy;
	  cdb0->current_length += bytes_to_copy;

	  if (0 == src_left)
	    {
	      int has_next = (csb0->flags & VLIB_BUFFER_NEXT_PRESENT);
	      u32 next_bi = csb0->next_buffer;

	      /* init src to the next buffer in chain */
	      if (has_next)
		{
		  csbi0 = next_bi;
		  csb0 = vlib_get_buffer (vm, csbi0);
		  src_left = csb0->current_length;
		  src_ptr = csb0->data;
		}
	      else
		{
		  ASSERT (total_src_left == 0);
		  break;
		}
	    }
	  if (0 == dst_left && total_src_left)
	    {
	      if (do_tx_offloads)
		calc_checksums (vm, cdb0);
	      n_tx_bytes += cdb0->current_length;
	      ASSERT (dbi < vec_len (ptd->split_buffers));
	      cdb0 = vlib_get_buffer (vm, ptd->split_buffers[dbi++]);
	      tso_init_buf_from_template (vm, cdb0, b0, l234_sz,
					  gso_size, &dst_ptr, &dst_left,
					  next_tcp_seq, default_bflags);
	    }
	}

      tso_fixup_segmented_buf (cdb0, save_tcp_flags, is_ip6);
      if (do_tx_offloads)
	calc_checksums (vm, cdb0);

      n_tx_bytes += cdb0->current_length;
    }
  n_tx_bytes += b0->current_length;
  return n_tx_bytes;
}

static_always_inline void
drop_one_buffer_and_count (vlib_main_t * vm, vnet_main_t * vnm,
			   vlib_node_runtime_t * node, u32 * pbi0,
			   u32 drop_error_code)
{
  u32 thread_index = vm->thread_index;
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;

  vlib_simple_counter_main_t *cm;
  cm =
    vec_elt_at_index (vnm->interface_main.sw_if_counters,
		      VNET_INTERFACE_COUNTER_TX_ERROR);
  vlib_increment_simple_counter (cm, thread_index, rt->sw_if_index, 1);

  vlib_error_drop_buffers (vm, node, pbi0,
			   /* buffer stride */ 1,
			   /* n_buffers */ 1,
			   VNET_INTERFACE_OUTPUT_NEXT_DROP,
			   node->node_index, drop_error_code);
}

static_always_inline uword
vnet_interface_output_node_inline_gso (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame,
				       vnet_main_t * vnm,
				       vnet_hw_interface_t * hi,
				       int do_tx_offloads,
				       int do_segmentation)
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
  vnet_interface_per_thread_data_t *ptd =
    vec_elt_at_index (im->per_thread_data, thread_index);

  n_buffers = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vnet_interface_output_trace (vm, node, frame, n_buffers);

  from = vlib_frame_vector_args (frame);

  if (rt->is_deleted)
    return vlib_error_drop_buffers (vm, node, from,
				    /* buffer stride */ 1,
				    n_buffers,
				    VNET_INTERFACE_OUTPUT_NEXT_DROP,
				    node->node_index,
				    VNET_INTERFACE_OUTPUT_ERROR_INTERFACE_DELETED);

  si = vnet_get_sw_interface (vnm, rt->sw_if_index);
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);
  if (!(si->flags & (VNET_SW_INTERFACE_FLAG_ADMIN_UP |
		     VNET_SW_INTERFACE_FLAG_BOND_SLAVE)) ||
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
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 tx_swif0, tx_swif1, tx_swif2, tx_swif3;
	  u32 or_flags;

	  /* Prefetch next iteration. */
	  vlib_prefetch_buffer_with_index (vm, from[4], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[5], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[6], LOAD);
	  vlib_prefetch_buffer_with_index (vm, from[7], LOAD);

	  bi0 = from[0];
	  bi1 = from[1];
	  bi2 = from[2];
	  bi3 = from[3];
	  to_tx[0] = bi0;
	  to_tx[1] = bi1;
	  to_tx[2] = bi2;
	  to_tx[3] = bi3;
	  if (!do_segmentation)
	    {
	      from += 4;
	      to_tx += 4;
	      n_left_to_tx -= 4;
	    }

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  if (do_segmentation)
	    {
	      or_flags = b0->flags | b1->flags | b2->flags | b3->flags;

	      /* go to single loop if we need TSO segmentation */
	      if (PREDICT_FALSE (or_flags & VNET_BUFFER_F_GSO))
		break;
	      from += 4;
	      to_tx += 4;
	      n_left_to_tx -= 4;
	    }

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);
	  ASSERT (b1->current_length > 0);
	  ASSERT (b2->current_length > 0);
	  ASSERT (b3->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b0);
	  n_bytes_b1 = vlib_buffer_length_in_chain (vm, b1);
	  n_bytes_b2 = vlib_buffer_length_in_chain (vm, b2);
	  n_bytes_b3 = vlib_buffer_length_in_chain (vm, b3);
	  tx_swif0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  tx_swif1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  tx_swif2 = vnet_buffer (b2)->sw_if_index[VLIB_TX];
	  tx_swif3 = vnet_buffer (b3)->sw_if_index[VLIB_TX];

	  n_bytes += n_bytes_b0 + n_bytes_b1;
	  n_bytes += n_bytes_b2 + n_bytes_b3;
	  n_packets += 4;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      vnet_buffer (b0)->feature_arc_index = arc;
	      vnet_buffer (b1)->feature_arc_index = arc;
	      vnet_buffer (b2)->feature_arc_index = arc;
	      vnet_buffer (b3)->feature_arc_index = arc;
	      b0->current_config_index = current_config_index;
	      b1->current_config_index = current_config_index;
	      b2->current_config_index = current_config_index;
	      b3->current_config_index = current_config_index;
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

	  if (!do_segmentation)
	    or_flags = b0->flags | b1->flags | b2->flags | b3->flags;

	  if (do_tx_offloads)
	    {
	      if (or_flags &
		  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
		   VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
		   VNET_BUFFER_F_OFFLOAD_IP_CKSUM))
		{
		  calc_checksums (vm, b0);
		  calc_checksums (vm, b1);
		  calc_checksums (vm, b2);
		  calc_checksums (vm, b3);
		}
	    }
	}

      while (from + 1 <= from_end && n_left_to_tx >= 1)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 tx_swif0;

	  bi0 = from[0];
	  to_tx[0] = bi0;
	  from += 1;
	  to_tx += 1;
	  n_left_to_tx -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Be grumpy about zero length buffers for benefit of
	     driver tx function. */
	  ASSERT (b0->current_length > 0);

	  n_bytes_b0 = vlib_buffer_length_in_chain (vm, b0);
	  tx_swif0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  n_bytes += n_bytes_b0;
	  n_packets += 1;

	  if (PREDICT_FALSE (current_config_index != ~0))
	    {
	      vnet_buffer (b0)->feature_arc_index = arc;
	      b0->current_config_index = current_config_index;
	    }

	  if (do_segmentation)
	    {
	      if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_GSO))
		{
		  /*
		   * Undo the enqueue of the b0 - it is not going anywhere,
		   * and will be freed either after it's segmented or
		   * when dropped, if there is no buffers to segment into.
		   */
		  to_tx -= 1;
		  n_left_to_tx += 1;
		  /* undo the counting. */
		  n_bytes -= n_bytes_b0;
		  n_packets -= 1;

		  u32 n_tx_bytes = 0;

		  n_tx_bytes =
		    tso_segment_buffer (vm, ptd, do_tx_offloads, bi0, b0,
					n_bytes_b0);

		  if (PREDICT_FALSE (n_tx_bytes == 0))
		    {
		      drop_one_buffer_and_count (vm, vnm, node, from - 1,
						 VNET_INTERFACE_OUTPUT_ERROR_NO_BUFFERS_FOR_GSO);
		      continue;
		    }

		  u16 n_tx_bufs = vec_len (ptd->split_buffers);
		  u32 *from_tx_seg = ptd->split_buffers;

		  while (n_tx_bufs > 0)
		    {
		      if (n_tx_bufs >= n_left_to_tx)
			{
			  while (n_left_to_tx > 0)
			    {
			      to_tx[0] = from_tx_seg[0];
			      to_tx += 1;
			      from_tx_seg += 1;
			      n_left_to_tx -= 1;
			      n_tx_bufs -= 1;
			      n_packets += 1;
			    }
			  vlib_put_next_frame (vm, node, next_index,
					       n_left_to_tx);
			  vlib_get_new_next_frame (vm, node, next_index,
						   to_tx, n_left_to_tx);
			}
		      else
			{
			  while (n_tx_bufs > 0)
			    {
			      to_tx[0] = from_tx_seg[0];
			      to_tx += 1;
			      from_tx_seg += 1;
			      n_left_to_tx -= 1;
			      n_tx_bufs -= 1;
			      n_packets += 1;
			    }
			}
		    }
		  n_bytes += n_tx_bytes;
		  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
		    {

		      vlib_increment_combined_counter
			(im->combined_sw_if_counters +
			 VNET_INTERFACE_COUNTER_TX, thread_index, tx_swif0,
			 _vec_len (ptd->split_buffers), n_tx_bytes);
		    }
		  /* The buffers were enqueued. Reset the length */
		  _vec_len (ptd->split_buffers) = 0;
		  /* Free the now segmented buffer */
		  vlib_buffer_free_one (vm, bi0);
		  continue;
		}
	    }

	  if (PREDICT_FALSE (tx_swif0 != rt->sw_if_index))
	    {

	      vlib_increment_combined_counter (im->combined_sw_if_counters +
					       VNET_INTERFACE_COUNTER_TX,
					       thread_index, tx_swif0, 1,
					       n_bytes_b0);
	    }

	  if (do_tx_offloads)
	    calc_checksums (vm, b0);
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
#endif /* CLIB_MARCH_VARIANT */

static_always_inline void vnet_interface_pcap_tx_trace
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame,
   int sw_if_index_from_buffer)
{
  u32 n_left_from, *from;
  u32 sw_if_index;

  if (PREDICT_TRUE (vm->pcap[VLIB_TX].pcap_enable == 0))
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
      u32 bi0 = from[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

      if (sw_if_index_from_buffer)
	sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      if (vm->pcap[VLIB_TX].pcap_sw_if_index == 0 ||
	  vm->pcap[VLIB_TX].pcap_sw_if_index == sw_if_index)
	pcap_add_buffer (&vm->pcap[VLIB_TX].pcap_main, vm, bi0, 512);
      from++;
      n_left_from--;
    }
}

#ifndef CLIB_MARCH_VARIANT
static_always_inline uword
vnet_interface_output_node_inline (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame, vnet_main_t * vnm,
				   vnet_hw_interface_t * hi,
				   int do_tx_offloads)
{
  /*
   * The 3-headed "if" is here because we want to err on the side
   * of not impacting the non-GSO performance - so for the more
   * common case of no GSO interfaces we want to prevent the
   * segmentation codepath from being there altogether.
   */
  if (PREDICT_TRUE (vnm->interface_main.gso_interface_count == 0))
    return vnet_interface_output_node_inline_gso (vm, node, frame, vnm, hi,
						  do_tx_offloads,
						  /* do_segmentation */ 0);
  else if (hi->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO)
    return vnet_interface_output_node_inline_gso (vm, node, frame, vnm, hi,
						  do_tx_offloads,
						  /* do_segmentation */ 0);
  else
    return vnet_interface_output_node_inline_gso (vm, node, frame, vnm, hi,
						  do_tx_offloads,
						  /* do_segmentation */ 1);
}

uword
vnet_interface_output_node (vlib_main_t * vm, vlib_node_runtime_t * node,
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
} vnet_error_trace_t;


static u8 *
format_vnet_error_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vnet_error_trace_t *t = va_arg (*va, vnet_error_trace_t *);

  s = format (s, "rx:%U", format_vnet_sw_if_index_name,
	      vnet_get_main (), t->sw_if_index);

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
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
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
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
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
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  sw_if_index = sw_if_indices;

  vlib_get_buffers (vm, from, bufs, n_left);

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
		 vnet_interface_main_t * im, vlib_frame_t * f)
{
  u32 *from;
  u32 n_left = f->n_vectors;
  vlib_buffer_t *b0, *p1;
  u32 bi0;
  i16 save_current_data;
  u16 save_current_length;

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

      /* Trace all drops, or drops received on a specific interface */
      if (im->pcap_sw_if_index == 0 ||
	  im->pcap_sw_if_index == vnet_buffer (b0)->sw_if_index[VLIB_RX])
	{
	  save_current_data = b0->current_data;
	  save_current_length = b0->current_length;

	  /*
	   * Typically, we'll need to rewind the buffer
	   */
	  if (b0->current_data > 0)
	    vlib_buffer_advance (b0, (word) - b0->current_data);

	  pcap_add_buffer (&im->pcap_main, vm, bi0, 512);

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

  if (PREDICT_FALSE (im->drop_pcap_enable))
    pcap_drop_trace (vm, im, frame);

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
VLIB_REGISTER_NODE (interface_tx, static) = {
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

static clib_error_t *
pcap_drop_trace_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  u8 *filename;
  u32 max;
  int matched = 0;
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on"))
	{
	  if (im->drop_pcap_enable == 0)
	    {
	      if (im->pcap_filename == 0)
		im->pcap_filename = format (0, "/tmp/drop.pcap%c", 0);

	      clib_memset (&im->pcap_main, 0, sizeof (im->pcap_main));
	      im->pcap_main.file_name = (char *) im->pcap_filename;
	      im->pcap_main.n_packets_to_capture = 100;
	      if (im->pcap_pkts_to_capture)
		im->pcap_main.n_packets_to_capture = im->pcap_pkts_to_capture;

	      im->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	      im->drop_pcap_enable = 1;
	      matched = 1;
	      vlib_cli_output (vm, "pcap drop capture on...");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap drop capture already on...");
	    }
	  matched = 1;
	}
      else if (unformat (input, "off"))
	{
	  matched = 1;

	  if (im->drop_pcap_enable)
	    {
	      vlib_cli_output (vm, "captured %d pkts...",
			       im->pcap_main.n_packets_captured);
	      if (im->pcap_main.n_packets_captured)
		{
		  im->pcap_main.n_packets_to_capture =
		    im->pcap_main.n_packets_captured;
		  error = pcap_write (&im->pcap_main);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...", im->pcap_filename);
		}
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap drop capture already off...");
	    }

	  im->drop_pcap_enable = 0;
	}
      else if (unformat (input, "max %d", &max))
	{
	  im->pcap_pkts_to_capture = max;
	  matched = 1;
	}

      else if (unformat (input, "intfc %U",
			 unformat_vnet_sw_interface, vnm,
			 &im->pcap_sw_if_index))
	matched = 1;
      else if (unformat (input, "intfc any"))
	{
	  im->pcap_sw_if_index = 0;
	  matched = 1;
	}
      else if (unformat (input, "file %s", &filename))
	{
	  u8 *chroot_filename;
	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      continue;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);

	  if (im->pcap_filename)
	    vec_free (im->pcap_filename);
	  im->pcap_filename = chroot_filename;
	  im->pcap_main.file_name = (char *) im->pcap_filename;
	  matched = 1;
	}
      else if (unformat (input, "status"))
	{
	  if (im->drop_pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap drop capture is off...");
	      continue;
	    }

	  vlib_cli_output (vm, "pcap drop capture: %d of %d pkts...",
			   im->pcap_main.n_packets_captured,
			   im->pcap_main.n_packets_to_capture);
	  matched = 1;
	}

      else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pcap_trace_command, static) = {
  .path = "pcap drop trace",
  .short_help =
  "pcap drop trace on off max <nn> intfc <intfc> file <name> status",
  .function = pcap_drop_trace_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
