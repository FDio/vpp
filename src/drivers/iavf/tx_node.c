/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <iavf.h>

static_always_inline u8
iavf_tx_desc_get_dtyp (iavf_tx_desc_t *d)
{
  return d->qword[1] & 0x0f;
}

struct iavf_ip4_psh
{
  u32 src;
  u32 dst;
  u8 zero;
  u8 proto;
  u16 l4len;
};

struct iavf_ip6_psh
{
  ip6_address_t src;
  ip6_address_t dst;
  u32 l4len;
  u32 proto;
};

static_always_inline u64
iavf_tx_prepare_cksum (vlib_buffer_t *b, u8 is_tso)
{
  u64 flags = 0;
  if (!is_tso && !(b->flags & VNET_BUFFER_F_OFFLOAD))
    return 0;

  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
  u32 is_tcp = is_tso || oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
  u32 is_udp = !is_tso && oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

  if (!is_tcp && !is_udp)
    return 0;

  u32 is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  u32 is_ip6 = b->flags & VNET_BUFFER_F_IS_IP6;

  ASSERT (!(is_tcp && is_udp));
  ASSERT (is_ip4 || is_ip6);
  i16 l2_hdr_offset = b->current_data;
  i16 l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
  i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
  u16 l2_len = l3_hdr_offset - l2_hdr_offset;
  u16 l3_len = l4_hdr_offset - l3_hdr_offset;
  ip4_header_t *ip4 = (void *) (b->data + l3_hdr_offset);
  ip6_header_t *ip6 = (void *) (b->data + l3_hdr_offset);
  tcp_header_t *tcp = (void *) (b->data + l4_hdr_offset);
  udp_header_t *udp = (void *) (b->data + l4_hdr_offset);
  u16 l4_len = is_tcp ? tcp_header_bytes (tcp) : sizeof (udp_header_t);
  u16 sum = 0;

  flags |= IAVF_TXD_OFFSET_MACLEN (l2_len) | IAVF_TXD_OFFSET_IPLEN (l3_len) |
	   IAVF_TXD_OFFSET_L4LEN (l4_len);
  flags |= is_ip4 ? IAVF_TXD_CMD_IIPT_IPV4 : IAVF_TXD_CMD_IIPT_IPV6;
  flags |= is_tcp ? IAVF_TXD_CMD_L4T_TCP : IAVF_TXD_CMD_L4T_UDP;

  if (is_ip4)
    ip4->checksum = 0;

  if (is_tso)
    {
      if (is_ip4)
	ip4->length = 0;
      else
	ip6->payload_length = 0;
    }

  if (is_ip4)
    {
      struct iavf_ip4_psh psh = { 0 };
      psh.src = ip4->src_address.as_u32;
      psh.dst = ip4->dst_address.as_u32;
      psh.proto = ip4->protocol;
      psh.l4len = is_tso ?
			  0 :
			  clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
					  (l4_hdr_offset - l3_hdr_offset));
      sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
    }
  else
    {
      struct iavf_ip6_psh psh = { 0 };
      psh.src = ip6->src_address;
      psh.dst = ip6->dst_address;
      psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
      psh.l4len = is_tso ? 0 : ip6->payload_length;
      sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
    }

  if (is_tcp)
    tcp->checksum = sum;
  else
    udp->checksum = sum;
  return flags;
}

static_always_inline void
iavf_tx_fill_ctx_desc (iavf_tx_desc_t *d, vlib_buffer_t *b, u32 tlen)
{
  ASSERT ((b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID) != 0);

  d[0].qword[0] = 0;
  d[0].qword[1] = IAVF_TXD_DTYP_CTX | IAVF_TXD_CTX_CMD_TSO |
		  IAVF_TXD_CTX_SEG_MSS (vnet_buffer2 (b)->gso_size) |
		  IAVF_TXD_CTX_SEG_TLEN (tlen);
}

static_always_inline int
iavf_tx_get_gso_hdr_sz (vlib_buffer_t *b, u32 *l234hdr_sz)
{
  i32 l4_offset = (i32) vnet_buffer (b)->l4_hdr_offset - b->current_data;
  u16 l4_hdr_sz = vnet_buffer2 (b)->gso_l4_hdr_sz;
  i32 hdr_sz = l4_offset + l4_hdr_sz;

  if (l4_offset <= 0)
    return IAVF_TX_NODE_CTR_GSO_BAD_HDR_OFFSET;

  if (l4_hdr_sz == 0)
    return IAVF_TX_NODE_CTR_GSO_BAD_L4_HDR_SZ;

  if (hdr_sz <= 0)
    return IAVF_TX_NODE_CTR_GSO_BAD_HDR;

  l234hdr_sz[0] = hdr_sz;
  return 0;
}

static_always_inline int
iavf_tx_fix_gso_l4_hdr_sz (vlib_buffer_t *b, u32 *l234hdr_sz)
{
  i32 l4_offset = (i32) vnet_buffer (b)->l4_hdr_offset - b->current_data;
  tcp_header_t *tcp;
  u16 l4_hdr_sz;

  if (l4_offset <= 0 || l4_offset + sizeof (tcp_header_t) > b->current_length)
    return 0;

  tcp = (tcp_header_t *) (vlib_buffer_get_current (b) + l4_offset);
  l4_hdr_sz = tcp_header_bytes (tcp);

  if (l4_hdr_sz < sizeof (tcp_header_t) || l4_offset + l4_hdr_sz > b->current_length)
    return 0;

  vnet_buffer2 (b)->gso_l4_hdr_sz = l4_hdr_sz;
  l234hdr_sz[0] = l4_offset + l4_hdr_sz;
  return 1;
}

static_always_inline void
iavf_tx_copy_desc (iavf_tx_desc_t *d, iavf_tx_desc_t *s, u32 n_descs)
{
#if defined CLIB_HAVE_VEC512
  while (n_descs >= 8)
    {
      u64x8u *dv = (u64x8u *) d;
      u64x8u *sv = (u64x8u *) s;

      dv[0] = sv[0];
      dv[1] = sv[1];

      /* next */
      d += 8;
      s += 8;
      n_descs -= 8;
    }
#elif defined CLIB_HAVE_VEC256
  while (n_descs >= 4)
    {
      u64x4u *dv = (u64x4u *) d;
      u64x4u *sv = (u64x4u *) s;

      dv[0] = sv[0];
      dv[1] = sv[1];

      /* next */
      d += 4;
      s += 4;
      n_descs -= 4;
    }
#elif defined CLIB_HAVE_VEC128
  while (n_descs >= 2)
    {
      u64x2u *dv = (u64x2u *) d;
      u64x2u *sv = (u64x2u *) s;

      dv[0] = sv[0];
      dv[1] = sv[1];

      /* next */
      d += 2;
      s += 2;
      n_descs -= 2;
    }
#endif
  while (n_descs)
    {
      d[0].qword[0] = s[0].qword[0];
      d[0].qword[1] = s[0].qword[1];
      d++;
      s++;
      n_descs--;
    }
}

static_always_inline void
iavf_tx_fill_data_desc_addr (iavf_tx_desc_t *d, u64 addr, u16 len, u64 cmd)
{
  d->qword[0] = addr;
  d->qword[1] = IAVF_TXD_DATA_SZ (len) | cmd | IAVF_TXD_CMD_RSV;
}

static_always_inline u64
iavf_tx_buffer_dma_addr (vlib_main_t *vm, vlib_buffer_t *b, int use_va_dma)
{
  if (use_va_dma)
    return vlib_buffer_get_current_va (b);
  else
    return vlib_buffer_get_current_pa (vm, b);
}

static_always_inline void
iavf_tx_fill_data_desc (vlib_main_t *vm, iavf_tx_desc_t *d, vlib_buffer_t *b, u64 cmd,
			int use_va_dma)
{
  iavf_tx_fill_data_desc_addr (d, iavf_tx_buffer_dma_addr (vm, b, use_va_dma), b->current_length,
			       cmd);
}

static_always_inline u16
iavf_tx_buffer_desc_count (vlib_buffer_t *b, u8 tso)
{
  if (tso)
    return (b->current_length + IAVF_MAX_DATA_PER_TXD - 1) / IAVF_MAX_DATA_PER_TXD;
  return 1;
}

static_always_inline u32
iavf_tx_tso_chain_len_and_descs (vlib_main_t *vm, vlib_buffer_t *b, u16 *n_descs)
{
  u32 pkt_len = 0;
  u16 n = 0;

  while (1)
    {
      pkt_len += b->current_length;
      n += iavf_tx_buffer_desc_count (b, 1 /* tso */);

      if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	break;

      b = vlib_get_buffer (vm, b->next_buffer);
    }

  n_descs[0] = n;
  return pkt_len;
}

static_always_inline u16
iavf_tx_fill_buffer_descs (vlib_main_t *vm, iavf_tx_desc_t *d, u32 *tb, u8 *tf, vlib_buffer_t *b,
			   u32 bi, u64 cmd, int use_va_dma, u8 tso)
{
  u64 addr = iavf_tx_buffer_dma_addr (vm, b, use_va_dma);
  u32 len = b->current_length;
  u16 n_descs = 0;

  while (tso && len > IAVF_MAX_DATA_PER_TXD)
    {
      iavf_tx_fill_data_desc_addr (d, addr, IAVF_MAX_DATA_PER_TXD, cmd & ~IAVF_TXD_CMD_EOP);
      tb[0] = bi;
      tf[0] = n_descs == 0;
      d++;
      tb++;
      tf++;
      n_descs++;
      addr += IAVF_MAX_DATA_PER_TXD;
      len -= IAVF_MAX_DATA_PER_TXD;
    }

  iavf_tx_fill_data_desc_addr (d, addr, len, cmd);
  tb[0] = bi;
  tf[0] = n_descs == 0;
  return n_descs + 1;
}

static_always_inline u16
iavf_tx_prepare (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vnet_dev_tx_queue_t *txq, u32 *buffers, u32 n_packets,
		 u16 *n_enq_descs, int use_va_dma)
{
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  const u64 cmd_eop = IAVF_TXD_CMD_EOP;
  u16 n_free_desc, n_desc_left, n_packets_left = n_packets;
  i32 n_desc_avail;
#if defined CLIB_HAVE_VEC512
  vlib_buffer_t *b[8];
#else
  vlib_buffer_t *b[4];
#endif
  iavf_tx_desc_t *d = atq->tmp_descs;
  u32 *tb = atq->tmp_bufs;
  u8 *tf = atq->tmp_buf_free_flags;
  u32 drop_counter;

  n_desc_avail = (i32) txq->size - (i32) atq->n_enqueued - 8;

  if (n_desc_avail <= 0)
    return 0;

  n_free_desc = n_desc_left = (u16) n_desc_avail;

  while (n_packets_left && n_desc_left)
    {
#if defined CLIB_HAVE_VEC512
      u32 flags;
      u64x8 or_flags_vec512;
      u64x8 flags_mask_vec512;
#else
      u32 flags, or_flags;
#endif

#if defined CLIB_HAVE_VEC512
      if (n_packets_left < 8 || n_desc_left < 8)
#else
      if (n_packets_left < 8 || n_desc_left < 4)
#endif
	goto one_by_one;

#if defined CLIB_HAVE_VEC512
      u64x8 base_ptr = u64x8_splat (vm->buffer_main->buffer_mem_start);
      u32x8 buf_indices = u32x8_load_unaligned (buffers);

      *(u64x8 *) &b = base_ptr + u64x8_from_u32x8 (
				   buf_indices << CLIB_LOG2_CACHE_LINE_BYTES);

      or_flags_vec512 = u64x8_i64gather (u64x8_load_unaligned (b), 0, 1);
#else
      vlib_prefetch_buffer_with_index (vm, buffers[4], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[5], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[6], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[7], LOAD);

      b[0] = vlib_get_buffer (vm, buffers[0]);
      b[1] = vlib_get_buffer (vm, buffers[1]);
      b[2] = vlib_get_buffer (vm, buffers[2]);
      b[3] = vlib_get_buffer (vm, buffers[3]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;
#endif

#if defined CLIB_HAVE_VEC512
      flags_mask_vec512 = u64x8_splat (
	VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_GSO);
      if (PREDICT_FALSE (
	    !u64x8_is_all_zero (or_flags_vec512 & flags_mask_vec512)))
#else
      if (PREDICT_FALSE (or_flags &
			 (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD |
			  VNET_BUFFER_F_GSO)))
#endif
	goto one_by_one;

#if defined CLIB_HAVE_VEC512
      vlib_buffer_copy_indices (tb, buffers, 8);
      clib_memset_u8 (tf, 1, 8);
      iavf_tx_fill_data_desc (vm, d + 0, b[0], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 1, b[1], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 2, b[2], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 3, b[3], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 4, b[4], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 5, b[5], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 6, b[6], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 7, b[7], cmd_eop, use_va_dma);

      buffers += 8;
      n_packets_left -= 8;
      n_desc_left -= 8;
      d += 8;
      tb += 8;
      tf += 8;
#else
      vlib_buffer_copy_indices (tb, buffers, 4);
      clib_memset_u8 (tf, 1, 4);

      iavf_tx_fill_data_desc (vm, d + 0, b[0], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 1, b[1], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 2, b[2], cmd_eop, use_va_dma);
      iavf_tx_fill_data_desc (vm, d + 3, b[3], cmd_eop, use_va_dma);

      buffers += 4;
      n_packets_left -= 4;
      n_desc_left -= 4;
      d += 4;
      tb += 4;
      tf += 4;
#endif

      continue;

    one_by_one:
      tb[0] = buffers[0];
      tf[0] = 1;
      b[0] = vlib_get_buffer (vm, buffers[0]);
      flags = b[0]->flags;

      /* No chained buffers or TSO case */
      if (PREDICT_TRUE (
	    (flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO)) == 0))
	{
	  u64 cmd = cmd_eop;

	  if (PREDICT_FALSE (flags & VNET_BUFFER_F_OFFLOAD))
	    cmd |= iavf_tx_prepare_cksum (b[0], 0 /* is_tso */);

	  iavf_tx_fill_data_desc (vm, d, b[0], cmd, use_va_dma);
	}
      else
	{
	  u16 n_desc_needed;
	  u64 cmd = 0;
	  u32 tso_tlen = 0;
	  u16 tso_n_descs = 0;
	  u8 is_tso = 0;

	  if (flags & VNET_BUFFER_F_GSO)
	    {
	      u32 l234hdr_sz, gso_size;
	      u32 pkt_len, payload_len;
	      int gso_error;

	      if (PREDICT_FALSE ((flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID) == 0))
		{
		  drop_counter = IAVF_TX_NODE_CTR_GSO_NO_L4_HDR;
		  goto drop_one;
		}

	      gso_error = iavf_tx_get_gso_hdr_sz (b[0], &l234hdr_sz);
	      if (PREDICT_FALSE (gso_error))
		{
		  drop_counter = gso_error;
		  goto drop_one;
		}

	      gso_size = vnet_buffer2 (b[0])->gso_size;
	      pkt_len = iavf_tx_tso_chain_len_and_descs (vm, b[0], &tso_n_descs);

	      if (PREDICT_FALSE (pkt_len <= l234hdr_sz))
		{
		  if (!iavf_tx_fix_gso_l4_hdr_sz (b[0], &l234hdr_sz) || pkt_len <= l234hdr_sz)
		    {
		      flags &= ~VNET_BUFFER_F_GSO;
		      vlib_error_count (vm, node->node_index, IAVF_TX_NODE_CTR_GSO_NOT_NEEDED, 1);
		      goto gso_done;
		    }
		}

	      if (PREDICT_FALSE (l234hdr_sz > b[0]->current_length))
		{
		  u32 n_lin = vlib_buffer_chain_linearize (vm, b[0]);
		  if (PREDICT_FALSE (n_lin == 0 || l234hdr_sz > b[0]->current_length))
		    {
		      drop_counter = IAVF_TX_NODE_CTR_GSO_HDR_LINEARIZE_FAIL;
		      goto drop_one;
		    }

		  flags = b[0]->flags;
		  pkt_len = iavf_tx_tso_chain_len_and_descs (vm, b[0], &tso_n_descs);
		  vlib_error_count (vm, node->node_index, IAVF_TX_NODE_CTR_GSO_HDR_LINEARIZED, 1);
		}

	      if (PREDICT_FALSE (pkt_len <= l234hdr_sz))
		{
		  drop_counter = IAVF_TX_NODE_CTR_GSO_BAD_PAYLOAD;
		  goto drop_one;
		}

	      if (PREDICT_FALSE (gso_size < IAVF_MIN_TSO_MSS || gso_size > IAVF_MAX_TSO_MSS))
		{
		  drop_counter = IAVF_TX_NODE_CTR_GSO_BAD_MSS;
		  goto drop_one;
		}

	      payload_len = pkt_len - l234hdr_sz;
	      is_tso = payload_len > gso_size;
	      if (!is_tso)
		{
		  flags &= ~VNET_BUFFER_F_GSO;
		  vlib_error_count (vm, node->node_index, IAVF_TX_NODE_CTR_GSO_NOT_NEEDED, 1);
		  goto gso_done;
		}

	      if (PREDICT_FALSE (is_tso && payload_len > IAVF_MAX_TSO_LEN))
		{
		  drop_counter = IAVF_TX_NODE_CTR_GSO_BAD_TLEN;
		  goto drop_one;
		}

	      tso_tlen = payload_len;

	    gso_done:;
	    }

	  if (is_tso)
	    n_desc_needed = tso_n_descs + 1;
	  else
	    {
	      n_desc_needed = 1;

	      if (flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  vlib_buffer_t *next = vlib_get_buffer (vm, b[0]->next_buffer);
		  n_desc_needed++;
		  while (next->flags & VLIB_BUFFER_NEXT_PRESENT)
		    {
		      next = vlib_get_buffer (vm, next->next_buffer);
		      n_desc_needed++;
		    }
		}

	      if (PREDICT_FALSE (n_desc_needed > 8))
		{
		  drop_counter = IAVF_TX_NODE_CTR_CHAIN_TOO_LONG;
		  goto drop_one;
		}
	    }

	  if (PREDICT_FALSE (n_desc_left < n_desc_needed))
	    break;

	  if (is_tso)
	    {
	      /* Enqueue a context descriptor */
	      tb[1] = tb[0];
	      tf[1] = tf[0];
	      tb[0] = ~0;
	      tf[0] = 0;
	      iavf_tx_fill_ctx_desc (d, b[0], tso_tlen);
	      n_desc_left -= 1;
	      d += 1;
	      tb += 1;
	      tf += 1;
	      cmd = iavf_tx_prepare_cksum (b[0], 1 /* is_tso */);
	    }
	  else if (flags & VNET_BUFFER_F_OFFLOAD)
	    {
	      cmd = iavf_tx_prepare_cksum (b[0], 0 /* is_tso */);
	    }

	  /* Deal with chain buffer if present */
	  while (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      u16 n =
		iavf_tx_fill_buffer_descs (vm, d, tb, tf, b[0], tb[0], cmd, use_va_dma, is_tso);

	      n_desc_left -= n;
	      d += n;
	      tb += n;
	      tf += n;

	      tb[0] = b[0]->next_buffer;
	      tf[0] = 1;
	      b[0] = vlib_get_buffer (vm, b[0]->next_buffer);
	    }

	  {
	    u16 n = iavf_tx_fill_buffer_descs (vm, d, tb, tf, b[0], tb[0], cmd_eop | cmd,
					       use_va_dma, is_tso);
	    n_desc_left -= n;
	    d += n;
	    tb += n;
	    tf += n;
	  }

	  buffers += 1;
	  n_packets_left -= 1;
	  continue;

	drop_one:
	  vlib_buffer_free_one (vm, buffers[0]);
	  vlib_error_count (vm, node->node_index, drop_counter, 1);
	  n_packets_left -= 1;
	  buffers += 1;
	  continue;
	}

      buffers += 1;
      n_packets_left -= 1;
      n_desc_left -= 1;
      d += 1;
      tb += 1;
      tf += 1;
    }

  *n_enq_descs = n_free_desc - n_desc_left;
  return n_packets - n_packets_left;
}

VNET_DEV_NODE_FN (iavf_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  iavf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  u16 next;
  u16 mask = txq->size - 1;
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_enq, n_left, n_desc, *slot;
  u16 n_retry = 2;

  n_left = frame->n_vectors;

  vnet_dev_tx_queue_lock_if_needed (txq);

retry:
  next = atq->next;
  /* release consumed bufs */
  if (atq->n_enqueued)
    {
      i32 complete_slot = -1;
      while (1)
	{
	  u16 *slot = clib_ring_get_first (atq->rs_slots);

	  if (slot == 0)
	    break;

	  if (iavf_tx_desc_get_dtyp (atq->descs + slot[0]) != 0x0F)
	    break;

	  complete_slot = slot[0];

	  clib_ring_deq (atq->rs_slots);
	}

      if (complete_slot >= 0)
	{
	  u16 first, mask, n_free;
	  mask = txq->size - 1;
	  first = (atq->next - atq->n_enqueued) & mask;
	  n_free = (complete_slot + 1 - first) & mask;

	  atq->n_enqueued -= n_free;
	  iavf_tx_queue_release_descs (vm, txq, first, n_free);
	}
    }

  n_desc = 0;
  if (dev->va_dma)
    n_enq = iavf_tx_prepare (vm, node, txq, buffers, n_left, &n_desc, 1);
  else
    n_enq = iavf_tx_prepare (vm, node, txq, buffers, n_left, &n_desc, 0);

  if (n_desc)
    {
      if (PREDICT_TRUE (next + n_desc <= txq->size))
	{
	  /* no wrap */
	  iavf_tx_copy_desc (atq->descs + next, atq->tmp_descs, n_desc);
	  vlib_buffer_copy_indices (atq->buffer_indices + next, atq->tmp_bufs,
				    n_desc);
	  clib_memcpy_fast (atq->buf_free_flags + next, atq->tmp_buf_free_flags, n_desc);
	}
      else
	{
	  /* wrap */
	  u32 n_not_wrap = txq->size - next;
	  iavf_tx_copy_desc (atq->descs + next, atq->tmp_descs, n_not_wrap);
	  iavf_tx_copy_desc (atq->descs, atq->tmp_descs + n_not_wrap,
			     n_desc - n_not_wrap);
	  vlib_buffer_copy_indices (atq->buffer_indices + next, atq->tmp_bufs,
				    n_not_wrap);
	  vlib_buffer_copy_indices (atq->buffer_indices,
				    atq->tmp_bufs + n_not_wrap,
				    n_desc - n_not_wrap);
	  clib_memcpy_fast (atq->buf_free_flags + next, atq->tmp_buf_free_flags, n_not_wrap);
	  clib_memcpy_fast (atq->buf_free_flags, atq->tmp_buf_free_flags + n_not_wrap,
			    n_desc - n_not_wrap);
	}

      next += n_desc;
      if ((slot = clib_ring_enq (atq->rs_slots)))
	{
	  u16 rs_slot = slot[0] = (next - 1) & mask;
	  atq->descs[rs_slot].qword[1] |= IAVF_TXD_CMD_RS;
	}

      atq->next = next & mask;
      __atomic_store_n (atq->qtx_tail, atq->next, __ATOMIC_RELEASE);
      atq->n_enqueued += n_desc;
      n_left -= n_enq;
    }

  if (n_left)
    {
      buffers += n_enq;

      if (n_retry--)
	goto retry;

      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index, IAVF_TX_NODE_CTR_NO_FREE_SLOTS,
			n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
