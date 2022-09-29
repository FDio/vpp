/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef included_gso_h
#define included_gso_h

#include <vnet/vnet.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/ip/ip_psh_cksum.h>

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} gso_main_t;

extern gso_main_t gso_main;

int vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable);
u32 gso_segment_buffer (vlib_main_t *vm, vnet_interface_per_thread_data_t *ptd,
			u32 bi, vlib_buffer_t *b, generic_header_offset_t *gho,
			u32 n_bytes_b, u8 is_l2, u8 is_ip6);

static_always_inline void
gso_init_bufs_from_template_base (vlib_buffer_t **bufs, vlib_buffer_t *b0,
				  u32 flags, u16 n_bufs, u16 hdr_sz)
{
  u32 i = n_bufs;
  while (i >= 6)
    {
      /* prefetches */
      CLIB_PREFETCH (bufs[2], 2 * CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (bufs[3], 2 * CLIB_CACHE_LINE_BYTES, LOAD);
      vlib_prefetch_buffer_data (bufs[4], LOAD);
      vlib_prefetch_buffer_data (bufs[5], LOAD);

      /* copying objects from cacheline 0 */
      bufs[0]->current_data = 0;
      bufs[1]->current_data = 0;

      bufs[0]->current_length = hdr_sz;
      bufs[1]->current_length = hdr_sz;

      bufs[0]->flags = bufs[1]->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | flags;
      bufs[0]->flow_id = bufs[1]->flow_id = b0->flow_id;
      bufs[0]->error = bufs[1]->error = b0->error;
      bufs[0]->current_config_index = bufs[1]->current_config_index =
	b0->current_config_index;

      clib_memcpy_fast (&bufs[0]->opaque, &b0->opaque, sizeof (b0->opaque));
      clib_memcpy_fast (&bufs[1]->opaque, &b0->opaque, sizeof (b0->opaque));

      /* copying objects from cacheline 1 */
      bufs[0]->trace_handle = b0->trace_handle;
      bufs[1]->trace_handle = b0->trace_handle;

      bufs[0]->total_length_not_including_first_buffer = 0;
      bufs[1]->total_length_not_including_first_buffer = 0;

      clib_memcpy_fast (&bufs[0]->opaque2, &b0->opaque2, sizeof (b0->opaque2));
      clib_memcpy_fast (&bufs[1]->opaque2, &b0->opaque2, sizeof (b0->opaque2));

      /* copying data */
      clib_memcpy_fast (bufs[0]->data, vlib_buffer_get_current (b0), hdr_sz);
      clib_memcpy_fast (bufs[1]->data, vlib_buffer_get_current (b0), hdr_sz);

      /* header offset fixup */
      vnet_buffer (bufs[0])->l2_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[0])->l3_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[0])->l4_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[0])->outer_l3_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[0])->outer_l4_hdr_offset -= b0->current_data;

      vnet_buffer (bufs[1])->l2_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[1])->l3_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[1])->l4_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[1])->outer_l3_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[1])->outer_l4_hdr_offset -= b0->current_data;

      bufs += 2;
      i -= 2;
    }

  while (i > 0)
    {
      /* copying objects from cacheline 0 */
      bufs[0]->current_data = 0;
      bufs[0]->current_length = hdr_sz;
      bufs[0]->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | flags;
      bufs[0]->flow_id = b0->flow_id;
      bufs[0]->error = b0->error;
      bufs[0]->current_config_index = b0->current_config_index;
      clib_memcpy_fast (&bufs[0]->opaque, &b0->opaque, sizeof (b0->opaque));

      /* copying objects from cacheline 1 */
      bufs[0]->trace_handle = b0->trace_handle;
      bufs[0]->total_length_not_including_first_buffer = 0;
      clib_memcpy_fast (&bufs[0]->opaque2, &b0->opaque2, sizeof (b0->opaque2));

      /* copying data */
      clib_memcpy_fast (bufs[0]->data, vlib_buffer_get_current (b0), hdr_sz);

      /* header offset fixup */
      vnet_buffer (bufs[0])->l2_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[0])->l3_hdr_offset -= b0->current_data;
      vnet_buffer (bufs[0])->l4_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[0])->outer_l3_hdr_offset -= b0->current_data;
      vnet_buffer2 (bufs[0])->outer_l4_hdr_offset -= b0->current_data;

      bufs++;
      i--;
    }
}

static_always_inline void
gso_fixup_segmented_buf (vlib_main_t *vm, vlib_buffer_t *b0, u32 next_tcp_seq,
			 int is_l2, u8 oflags, u16 hdr_sz, u16 l4_hdr_sz,
			 clib_ip_csum_t *c, u8 tcp_flags, u8 is_prefetch,
			 vlib_buffer_t *b1)
{

  i16 l3_hdr_offset = vnet_buffer (b0)->l3_hdr_offset;
  i16 l4_hdr_offset = vnet_buffer (b0)->l4_hdr_offset;

  ip4_header_t *ip4 = (ip4_header_t *) (b0->data + l3_hdr_offset);
  ip6_header_t *ip6 = (ip6_header_t *) (b0->data + l3_hdr_offset);
  tcp_header_t *tcp = (tcp_header_t *) (b0->data + l4_hdr_offset);

  tcp->flags = tcp_flags;
  tcp->seq_number = clib_host_to_net_u32 (next_tcp_seq);
  c->odd = 0;

  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    {
      ip4->length =
	clib_host_to_net_u16 (b0->current_length - hdr_sz +
			      (l4_hdr_offset - l3_hdr_offset) + l4_hdr_sz);
      ip4->checksum = 0;
      ip4->checksum = ip4_header_checksum (ip4);
      vnet_buffer_offload_flags_clear (b0, (VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					    VNET_BUFFER_OFFLOAD_F_TCP_CKSUM));
      c->sum += clib_mem_unaligned (&ip4->src_address, u32);
      c->sum += clib_mem_unaligned (&ip4->dst_address, u32);
      c->sum += clib_host_to_net_u32 (
	(clib_net_to_host_u16 (ip4->length) - ip4_header_bytes (ip4)) +
	(ip4->protocol << 16));
    }
  else
    {
      ip6->payload_length =
	clib_host_to_net_u16 (b0->current_length - hdr_sz + l4_hdr_sz);
      vnet_buffer_offload_flags_clear (b0, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
      ip6_psh_t psh = { 0 };
      u32 *p = (u32 *) &psh;
      psh.src = ip6->src_address;
      psh.dst = ip6->dst_address;
      psh.l4len = ip6->payload_length;
      psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
      for (int i = 0; i < 10; i++)
	c->sum += p[i];
    }

  if (is_prefetch)
    CLIB_PREFETCH (vlib_buffer_get_current (b1) + hdr_sz,
		   CLIB_CACHE_LINE_BYTES, LOAD);

  clib_ip_csum_chunk (c, (u8 *) tcp, l4_hdr_sz);
  tcp->checksum = clib_ip_csum_fold (c);

  if (!is_l2 && ((oflags & VNET_BUFFER_OFFLOAD_F_TNL_MASK) == 0))
    {
      u32 adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];

      ip_adjacency_t *adj0 = adj_get (adj_index0);

      if (adj0->lookup_next_index == IP_LOOKUP_NEXT_MIDCHAIN &&
	  adj0->sub_type.midchain.fixup_func)
	/* calls e.g. ipip44_fixup */
	adj0->sub_type.midchain.fixup_func (
	  vm, adj0, b0, adj0->sub_type.midchain.fixup_data);
    }
}

static_always_inline u32
gso_segment_buffer_inline (vlib_main_t *vm,
			   vnet_interface_per_thread_data_t *ptd,
			   vlib_buffer_t *b, int is_l2)
{
  vlib_buffer_t **bufs = 0;
  u32 n_tx_bytes = 0;

  u8 oflags = vnet_buffer (b)->oflags;
  i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
  u16 gso_size = vnet_buffer2 (b)->gso_size;
  u16 l4_hdr_sz = vnet_buffer2 (b)->gso_l4_hdr_sz;

  u8 tcp_flags = 0, tcp_flags_no_fin_psh = 0;
  u32 default_bflags =
    b->flags & ~(VNET_BUFFER_F_GSO | VLIB_BUFFER_NEXT_PRESENT);
  u16 hdr_sz = (l4_hdr_offset - b->current_data) + l4_hdr_sz;
  u32 next_tcp_seq = 0, tcp_seq = 0;
  u32 data_size = vlib_buffer_length_in_chain (vm, b) - hdr_sz;
  u16 size =
    clib_min (gso_size, vlib_buffer_get_default_data_size (vm) - hdr_sz);
  u16 n_alloc = 0, n_bufs = ((data_size + size - 1) / size);
  clib_ip_csum_t c = { .sum = 0, .odd = 0 };
  u8 *src_ptr, *dst_ptr;
  u16 src_left, dst_left, bytes_to_copy;
  u32 i = 0;

  vec_validate (ptd->split_buffers, n_bufs - 1);
  n_alloc = vlib_buffer_alloc (vm, ptd->split_buffers, n_bufs);
  if (n_alloc < n_bufs)
    {
      vlib_buffer_free (vm, ptd->split_buffers, n_alloc);
      return 0;
    }

  vec_validate (bufs, n_bufs - 1);
  vlib_get_buffers (vm, ptd->split_buffers, bufs, n_bufs);

  tcp_header_t *tcp = (tcp_header_t *) (b->data + l4_hdr_offset);

  tcp_seq = next_tcp_seq = clib_net_to_host_u32 (tcp->seq_number);
  /* store original flags for last packet and reset FIN and PSH */
  tcp_flags = tcp->flags;
  tcp_flags_no_fin_psh = tcp->flags & ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
  tcp->checksum = 0;

  gso_init_bufs_from_template_base (bufs, b, default_bflags, n_bufs, hdr_sz);

  src_ptr = vlib_buffer_get_current (b) + hdr_sz;
  src_left = b->current_length - hdr_sz;
  dst_ptr = vlib_buffer_get_current (bufs[i]) + hdr_sz;
  dst_left = size;

  while (data_size)
    {
      bytes_to_copy = clib_min (src_left, dst_left);
      clib_ip_csum_and_copy_chunk (&c, src_ptr, dst_ptr, bytes_to_copy);

      src_left -= bytes_to_copy;
      src_ptr += bytes_to_copy;
      data_size -= bytes_to_copy;
      dst_left -= bytes_to_copy;
      dst_ptr += bytes_to_copy;
      next_tcp_seq += bytes_to_copy;
      bufs[i]->current_length += bytes_to_copy;

      if (0 == src_left)
	{
	  /* init src to the next buffer in chain */
	  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b = vlib_get_buffer (vm, b->next_buffer);
	      src_left = b->current_length;
	      src_ptr = vlib_buffer_get_current (b);
	    }
	  else
	    {
	      ASSERT (data_size == 0);
	      break;
	    }
	}
      if (0 == dst_left && data_size)
	{
	  vlib_prefetch_buffer_header (bufs[i + 1], LOAD);

	  n_tx_bytes += bufs[i]->current_length;
	  gso_fixup_segmented_buf (vm, bufs[i], tcp_seq, is_l2, oflags, hdr_sz,
				   l4_hdr_sz, &c, tcp_flags_no_fin_psh, 1,
				   bufs[i + 1]);
	  i++;
	  dst_left = size;
	  dst_ptr = vlib_buffer_get_current (bufs[i]) + hdr_sz;
	  tcp_seq = next_tcp_seq;
	  // reset clib_ip_csum_t
	  c.odd = 0;
	  c.sum = 0;
	}
    }

  ASSERT ((i + 1) == n_alloc);
  n_tx_bytes += bufs[i]->current_length;
  gso_fixup_segmented_buf (vm, bufs[i], tcp_seq, is_l2, oflags, hdr_sz,
			   l4_hdr_sz, &c, tcp_flags, 0, NULL);

  vec_free (bufs);
  return n_tx_bytes;
}

#endif /* included_gso_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
