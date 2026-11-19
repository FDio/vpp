/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/vector/ip_csum.h>

static const u32 slowpath_mask =
  VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_GSO;

typedef struct
{
  u32 *drops;
  u32 n_invalid;
  u32 n_full;
} vnp_tx_drops_t;

static_always_inline u32
vnp_tx_prepare (vlib_main_t *vm, vlib_buffer_t *b, u32 flags)
{
  u32 n_seg = 1;

  if (PREDICT_TRUE (!(flags & slowpath_mask)))
    return 1;

  if (flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      vlib_buffer_t *seg = b;

      while (seg->flags & VLIB_BUFFER_NEXT_PRESENT && n_seg <= VNP_MAX_SEGS)
	{
	  seg = vlib_get_buffer (vm, seg->next_buffer);
	  n_seg++;
	}
    }

  if (n_seg > VNP_MAX_SEGS)
    return 0;

  if (flags & (VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_GSO))
    {
      u32 gso = (b->flags & VNET_BUFFER_F_GSO) != 0;
      u32 oflags = vnet_buffer (b)->oflags;
      i32 l3 = vnet_buffer (b)->l3_hdr_offset;
      i32 l4 = vnet_buffer (b)->l4_hdr_offset;
      u8 tcp = (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM) || gso;
      u8 udp = (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM) != 0;
      virtio_net_hdr_t *hdr = virtio_net_hdr (b);
      u16 seed;

      ASSERT (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
      ASSERT (b->flags & (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_IS_IP6));
      ASSERT (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
      ASSERT (tcp || udp);

      if (tcp)
	{
	  tcp_header_t *t = (void *) (b->data + l4);

	  hdr->hdr_len = l4 - b->current_data + tcp_header_bytes (t);
	  hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else
	{
	  hdr->hdr_len = l4 - b->current_data + sizeof (udp_header_t);
	  hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}

      if (b->flags & VNET_BUFFER_F_IS_IP4)
	{
	  ip4_header_t *ip = (void *) (b->data + l3);
	  struct
	  {
	    ip4_address_t src, dst;
	    u8 zero, protocol;
	    u16 length;
	  } pseudo = {
	    .src = ip->src_address,
	    .dst = ip->dst_address,
	    .protocol = ip->protocol,
	  };

	  if (!gso)
	    pseudo.length = clib_host_to_net_u16 (clib_net_to_host_u16 (ip->length) - (l4 - l3));

	  seed = ~clib_ip_csum ((u8 *) &pseudo, sizeof (pseudo));

	  if (gso)
	    hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	}
      else
	{
	  ip6_header_t *ip = (void *) (b->data + l3);
	  struct
	  {
	    ip6_address_t src, dst;
	    u32 length, protocol;
	  } pseudo = {
	    .src = ip->src_address,
	    .dst = ip->dst_address,
	    .protocol = clib_host_to_net_u32 (tcp ? 6 : 17),
	  };

	  if (!gso)
	    pseudo.length = clib_host_to_net_u32 (clib_net_to_host_u16 (ip->payload_length) -
						  (l4 - l3 - sizeof (*ip)));

	  seed = ~clib_ip_csum ((u8 *) &pseudo, sizeof (pseudo));

	  if (gso)
	    hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	}

      *(u16u *) (b->data + l4 + hdr->csum_offset) = seed;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = l4 - b->current_data;

      if (gso)
	{
	  ASSERT (vnet_buffer2 (b)->gso_size);
	  hdr->gso_size = vnet_buffer2 (b)->gso_size;
	}
    }

  return n_seg;
}

static_always_inline u16
vnp_txq_enqueue_direct (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 n_pkts, u32 *from,
			vlib_buffer_t **bufs, uword *dma, u16 *lengths, u8 *n_segs,
			vnp_tx_drops_t *dc)
{
  vnet_dev_t *dev = txq->port->dev;
  vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1, n_free = q->n_free, avail_index = q->avail_index;
  u16 *free_ids = q->free_ids, *ring = q->avail->ring;
  u32 *buffer_indices = q->buffer_indices;
  virtq_desc_t *desc = q->desc;

  for (u32 i = 0; i < n_pkts; i++)
    {
      vlib_buffer_t *seg = bufs[i];
      u32 n_seg = n_segs[i];
      u16 head, id;

      if (PREDICT_FALSE (n_seg == 0))
	{
	  *dc->drops++ = from[i];
	  dc->n_invalid++;
	  continue;
	}

      if (PREDICT_FALSE (n_free < n_seg))
	{
	  *dc->drops++ = from[i];
	  dc->n_full++;
	  continue;
	}

      head = id = free_ids[--n_free];
      buffer_indices[head] = from[i];
      desc[id] = (virtq_desc_t) {
	.addr = dma[i],
	.len = lengths[i],
      };

      for (u32 j = 1; j < n_seg; j++)
	{
	  u16 next = free_ids[--n_free];

	  seg = vlib_get_buffer (vm, seg->next_buffer);
	  desc[id].flags = VRING_DESC_F_NEXT;
	  desc[id].next = next;
	  id = next;
	  desc[id] = (virtq_desc_t) {
	    .addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (seg)),
	    .len = seg->current_length,
	  };
	}

      ring[avail_index++ & mask] = head;
    }

  q->n_free = n_free;
  return avail_index;
}

static_always_inline void
vnp_txq_enqueue_single (vnp_txq_t *q, u32 buffer_index, uword dma, u16 length, u16 *n_free,
			u16 *avail_index, u16 mask)
{
  u16 head = q->free_ids[--*n_free];

  q->buffer_indices[head] = buffer_index;
  q->desc[head] = (virtq_desc_t) {
    .addr = dma,
    .len = length,
  };
  q->avail->ring[(*avail_index)++ & mask] = head;
}

/* one main table descriptor pointing to a table of split format descriptors */
static_always_inline u16
vnp_txq_enqueue_ind_split (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 n_pkts, u32 *from,
			   vlib_buffer_t **bufs, uword *dma, u16 *lengths, u8 *n_segs,
			   vnp_tx_drops_t *dc)
{
  vnet_dev_t *dev = txq->port->dev;
  vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1, n_free = q->n_free, avail_index = q->avail_index;
  u16 *free_ids = q->free_ids, *ring = q->avail->ring;
  u32 *buffer_indices = q->buffer_indices;
  virtq_desc_t *desc = q->desc;

  for (u32 i = 0; i < n_pkts; i++)
    {
      vlib_buffer_t *seg = bufs[i];
      u32 n_seg = n_segs[i];
      virtq_desc_t *descs;
      u16 head;

      if (PREDICT_FALSE (n_seg == 0))
	{
	  *dc->drops++ = from[i];
	  dc->n_invalid++;
	  continue;
	}

      if (PREDICT_FALSE (n_free == 0))
	{
	  *dc->drops++ = from[i];
	  dc->n_full++;
	  continue;
	}

      if (n_seg == 1)
	{
	  vnp_txq_enqueue_single (q, from[i], dma[i], lengths[i], &n_free, &avail_index, mask);
	  continue;
	}

      head = free_ids[--n_free];
      buffer_indices[head] = from[i];
      descs = vnp_txq_indirect (q, head);
      desc[head] = (virtq_desc_t) {
	.addr = vnp_txq_indirect_dma (q, head),
	.len = n_seg * sizeof (*descs),
	.flags = VRING_DESC_F_INDIRECT,
      };
      descs[0] = (virtq_desc_t) {
	.addr = dma[i],
	.len = lengths[i],
      };

      for (u32 j = 1; j < n_seg; j++)
	{
	  seg = vlib_get_buffer (vm, seg->next_buffer);
	  descs[j - 1].flags = VRING_DESC_F_NEXT;
	  descs[j - 1].next = j;
	  descs[j] = (virtq_desc_t) {
	    .addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (seg)),
	    .len = seg->current_length,
	  };
	}

      ring[avail_index++ & mask] = head;
    }

  q->n_free = n_free;
  return avail_index;
}

/* same as above, but the table holds packed format descriptors */
static_always_inline u16
vnp_txq_enqueue_ind_packed (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 n_pkts, u32 *from,
			    vlib_buffer_t **bufs, uword *dma, u16 *lengths, u8 *n_segs,
			    vnp_tx_drops_t *dc)
{
  vnet_dev_t *dev = txq->port->dev;
  vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1, n_free = q->n_free, avail_index = q->avail_index;
  u16 *free_ids = q->free_ids, *ring = q->avail->ring;
  u32 *buffer_indices = q->buffer_indices;
  virtq_desc_t *desc = q->desc;

  for (u32 i = 0; i < n_pkts; i++)
    {
      vlib_buffer_t *seg = bufs[i];
      u32 n_seg = n_segs[i];
      pvirtq_desc_t *descs;
      u16 head;

      if (PREDICT_FALSE (n_seg == 0))
	{
	  *dc->drops++ = from[i];
	  dc->n_invalid++;
	  continue;
	}

      if (PREDICT_FALSE (n_free == 0))
	{
	  *dc->drops++ = from[i];
	  dc->n_full++;
	  continue;
	}

      if (n_seg == 1)
	{
	  vnp_txq_enqueue_single (q, from[i], dma[i], lengths[i], &n_free, &avail_index, mask);
	  continue;
	}

      head = free_ids[--n_free];
      buffer_indices[head] = from[i];
      descs = vnp_txq_indirect (q, head);
      desc[head] = (virtq_desc_t) {
	.addr = vnp_txq_indirect_dma (q, head),
	.len = n_seg * sizeof (*descs),
	.flags = VRING_DESC_F_INDIRECT,
      };
      descs[0] = (pvirtq_desc_t) {
	.addr = dma[i],
	.len = lengths[i],
      };

      for (u32 j = 1; j < n_seg; j++)
	{
	  seg = vlib_get_buffer (vm, seg->next_buffer);
	  descs[j] = (pvirtq_desc_t) {
	    .addr = vnet_dev_get_dma_addr (vm, dev, vlib_buffer_get_current (seg)),
	    .len = seg->current_length,
	  };
	}

      ring[avail_index++ & mask] = head;
    }

  q->n_free = n_free;
  return avail_index;
}

static_always_inline void
vnp_txq_packed_publish (vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, avail = q->packed_avail, published = q->published;
  u16 avail_index = q->avail_index, outstanding = q->packed_outstanding;
  u16 *ring = q->avail->ring, *packed_count = q->packed_count;
  virtq_desc_t *desc = q->desc;
  pvirtq_desc_t *packed = q->packed;

  while (published != avail_index)
    {
      u16 head = ring[published & mask];
      u16 id = head, first = avail, first_flags = 0, n = 0;

      while (1)
	{
	  virtq_desc_t d = desc[id];
	  u16 flags = d.flags;
	  u16 packed_flags = flags | vnp_packed_avail_flags (avail, size);
	  pvirtq_desc_t *p = packed + (avail & mask);

	  p->addr = d.addr;
	  p->len = d.len;
	  p->id = head;

	  if (n == 0)
	    first_flags = packed_flags;
	  else
	    __atomic_store_n (&p->flags, packed_flags, __ATOMIC_RELEASE);

	  n++;
	  avail++;

	  if (!(flags & VRING_DESC_F_NEXT))
	    break;

	  id = d.next;
	}

      packed_count[head] = n;
      outstanding += n;
      ASSERT (outstanding <= size);
      __atomic_store_n (&packed[first & mask].flags, first_flags, __ATOMIC_RELEASE);
      published++;
    }

  q->published = published;
  q->packed_outstanding = outstanding;
  q->packed_avail = avail;
}

VNET_DEV_NODE_FN (vnp_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_pkts = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  uword dma[VLIB_FRAME_SIZE];
  u32 flags[VLIB_FRAME_SIZE];
  u16 lengths[VLIB_FRAME_SIZE];
  u8 n_segs[VLIB_FRAME_SIZE];
  u32 drops[VLIB_FRAME_SIZE];
  u16 size = txq->size, mask = size - 1;
  u16 first_avail, ai;
  vnp_tx_drops_t dc = {
    .drops = drops,
  };
  vlib_buffer_t **bp = bufs;
  u32 *f = flags, n_left = n_pkts;
  u16 *l = lengths;
  uword *d = dma;
  u8 *ns = n_segs;

  vnet_dev_tx_queue_lock_if_needed (txq);
  vnp_txq_reclaim (vm, q, size);

  first_avail = q->avail_index;
  vlib_get_buffers (vm, from, bufs, n_pkts);
  clib_memset_u8 (n_segs, 1, n_pkts);

  /* dma[] points to the virtio-net header, 12 bytes before the packet data */
  vnet_dev_va_to_iova (dev, (void **) dma, (void **) bufs, n_pkts,
		       STRUCT_OFFSET_OF (vlib_buffer_t, data) - VIRTIO_NET_HDR_V1_SZ);

  while (n_left >= 8)
    {
      u32 or ;
      clib_prefetch_load (bp[4]);
      clib_prefetch_load (bp[5]);
      clib_prefetch_load (bp[6]);
      clib_prefetch_load (bp[7]);

      /* the virtio-net header is likely written in the cache line before the data */
      clib_prefetch_store (bp[4]->data - 1);
      clib_prefetch_store (bp[5]->data - 1);
      clib_prefetch_store (bp[6]->data - 1);
      clib_prefetch_store (bp[7]->data - 1);

      f[0] = bp[0]->flags;
      f[1] = bp[1]->flags;
      f[2] = bp[2]->flags;
      f[3] = bp[3]->flags;
      l[0] = bp[0]->current_length;
      l[1] = bp[1]->current_length;
      l[2] = bp[2]->current_length;
      l[3] = bp[3]->current_length;
      d[0] += bp[0]->current_data;
      d[1] += bp[1]->current_data;
      d[2] += bp[2]->current_data;
      d[3] += bp[3]->current_data;

      *virtio_net_hdr (bp[0]) = (virtio_net_hdr_t) {};
      *virtio_net_hdr (bp[1]) = (virtio_net_hdr_t) {};
      *virtio_net_hdr (bp[2]) = (virtio_net_hdr_t) {};
      *virtio_net_hdr (bp[3]) = (virtio_net_hdr_t) {};

      or = f[0] | f[1] | f[2] | f[3];

      if (PREDICT_FALSE (or &slowpath_mask))
	{
	  ns[0] = vnp_tx_prepare (vm, bp[0], f[0]);
	  ns[1] = vnp_tx_prepare (vm, bp[1], f[1]);
	  ns[2] = vnp_tx_prepare (vm, bp[2], f[2]);
	  ns[3] = vnp_tx_prepare (vm, bp[3], f[3]);
	}

      bp += 4;
      f += 4;
      l += 4;
      d += 4;
      ns += 4;
      n_left -= 4;
    }

  for (; n_left > 0; n_left--, bp++, f++, l++, d++, ns++)
    {
      f[0] = bp[0]->flags;
      l[0] = bp[0]->current_length;
      d[0] += bp[0]->current_data;
      *virtio_net_hdr (bp[0]) = (virtio_net_hdr_t) {};

      ns[0] = vnp_tx_prepare (vm, bp[0], f[0]);
    }

  vnp_u16_add (lengths, n_pkts, VIRTIO_NET_HDR_V1_SZ);

  if (q->indirect && q->packed)
    ai = vnp_txq_enqueue_ind_packed (vm, txq, n_pkts, from, bufs, dma, lengths, n_segs, &dc);
  else if (q->indirect)
    ai = vnp_txq_enqueue_ind_split (vm, txq, n_pkts, from, bufs, dma, lengths, n_segs, &dc);
  else
    ai = vnp_txq_enqueue_direct (vm, txq, n_pkts, from, bufs, dma, lengths, n_segs, &dc);

  if (ai != first_avail)
    {
      q->avail_index = ai;

      if (q->packed)
	{
	  vnp_txq_packed_publish (q, size);
	  __atomic_thread_fence (__ATOMIC_SEQ_CST);

	  if (__atomic_load_n (&q->device_event->flags, __ATOMIC_RELAXED) != VRING_EVENT_F_DISABLE)
	    vnp_reg_wr16 (q->notify, q->id);
	}
      else
	{
	  __atomic_store_n (&q->avail->idx, ai, __ATOMIC_RELEASE);
	  __atomic_thread_fence (__ATOMIC_SEQ_CST);

	  if (!(__atomic_load_n (&q->used->flags, __ATOMIC_RELAXED) & VRING_USED_F_NO_NOTIFY))
	    vnp_reg_wr16 (q->notify, q->id);
	}
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u16 avail = first_avail;

      for (u32 i = 0; i < n_pkts; i++)
	{
	  vlib_buffer_t *b = bufs[i];
	  u32 length = 0;
	  u16 head = 0, n_descs = 0;
	  virtio_net_hdr_t hdr = {};

	  if (avail != ai)
	    {
	      head = q->avail->ring[avail & mask];

	      if (q->buffer_indices[head] == from[i])
		{
		  length = vlib_buffer_length_in_chain (vm, b);
		  hdr = *virtio_net_hdr (b);
		  avail++;
		}
	    }

	  if (flags[i] & VLIB_BUFFER_IS_TRACED)
	    {
	      vnp_tx_trace_t *tr;

	      if (length && q->indirect)
		n_descs = q->desc[head].len / sizeof (virtq_desc_t);
	      else if (length)
		for (u16 id = head; q->desc[id].flags & VRING_DESC_F_NEXT; id = q->desc[id].next)
		  n_descs++;

	      tr = vlib_add_trace (vm, node, b, sizeof (*tr) + n_descs * sizeof (tr->descs[0]));
	      tr->length = length;
	      tr->queue_id = txq->queue_id;
	      tr->n_descs = n_descs;
	      tr->indirect = q->indirect != 0;
	      tr->packed = q->packed != 0;
	      tr->hdr = hdr;
	      tr->head = (virtq_desc_t) {};

	      if (length)
		tr->head = q->desc[head];

	      if (q->indirect)
		{
		  virtq_desc_t *table = vnp_txq_indirect (q, head);

		  for (u16 j = 0; j < n_descs; j++)
		    tr->descs[j] = table[j];
		}
	      else
		for (u16 j = 0, id = head; j < n_descs; j++)
		  {
		    id = q->desc[id].next;
		    tr->descs[j] = q->desc[id];
		  }
	    }
	}
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (PREDICT_FALSE (dc.n_invalid))
    vlib_error_count (vm, node->node_index, VNP_TX_INVALID, dc.n_invalid);

  if (PREDICT_FALSE (dc.n_full))
    vlib_error_count (vm, node->node_index, VNP_TX_FULL, dc.n_full);

  if (drops != dc.drops)
    vlib_buffer_free (vm, drops, dc.drops - drops);

  return n_pkts - dc.n_full;
}
