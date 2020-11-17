/*
 *------------------------------------------------------------------
 * vhost-user-output
 *
 * Copyright (c) 2014-2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stddef.h>
#include <fcntl.h>		/* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* for iovec */
#include <netinet/in.h>
#include <sys/vfs.h>

#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/virtio/vhost_user.h>
#include <vnet/devices/virtio/vhost_user_inline.h>

#include <vnet/gso/hdr_offset_parser.h>
/*
 * On the transmit side, we keep processing the buffers from vlib in the while
 * loop and prepare the copy order to be executed later. However, the static
 * array which we keep the copy order is limited to VHOST_USER_COPY_ARRAY_N
 * entries. In order to not corrupt memory, we have to do the copy when the
 * static array reaches the copy threshold. We subtract 40 in case the code
 * goes into the inner loop for a maximum of 64k frames which may require
 * more array entries. We subtract 200 because our default buffer size is
 * 2048 and the default desc len is likely 1536. While it takes less than 40
 * vlib buffers for the jumbo frame, it may take twice as much descriptors
 * for the same jumbo frame. Use 200 for the extra head room.
 */
#define VHOST_USER_TX_COPY_THRESHOLD (VHOST_USER_COPY_ARRAY_N - 200)

extern vnet_device_class_t vhost_user_device_class;

#define foreach_vhost_user_tx_func_error      \
  _(NONE, "no error")  \
  _(NOT_READY, "vhost vring not ready")  \
  _(DOWN, "vhost interface is down")  \
  _(PKT_DROP_NOBUF, "tx packet drops (no available descriptors)")  \
  _(PKT_DROP_NOMRG, "tx packet drops (cannot merge descriptors)")  \
  _(MMAP_FAIL, "mmap failure") \
  _(INDIRECT_OVERFLOW, "indirect descriptor table overflow")

typedef enum
{
#define _(f,s) VHOST_USER_TX_FUNC_ERROR_##f,
  foreach_vhost_user_tx_func_error
#undef _
    VHOST_USER_TX_FUNC_N_ERROR,
} vhost_user_tx_func_error_t;

static __clib_unused char *vhost_user_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_vhost_user_tx_func_error
#undef _
};

static __clib_unused u8 *
format_vhost_user_interface_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;
  vhost_user_main_t *vum = &vhost_user_main;

  if (i < vec_len (vum->show_dev_instance_by_real_dev_instance))
    show_dev_instance = vum->show_dev_instance_by_real_dev_instance[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  s = format (s, "VirtualEthernet0/0/%d", i);
  return s;
}

static __clib_unused int
vhost_user_name_renumber (vnet_hw_interface_t * hi, u32 new_dev_instance)
{
  // FIXME: check if the new dev instance is already used
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui = pool_elt_at_index (vum->vhost_user_interfaces,
					      hi->dev_instance);

  vec_validate_init_empty (vum->show_dev_instance_by_real_dev_instance,
			   hi->dev_instance, ~0);

  vum->show_dev_instance_by_real_dev_instance[hi->dev_instance] =
    new_dev_instance;

  vu_log_debug (vui, "renumbered vhost-user interface dev_instance %d to %d",
		hi->dev_instance, new_dev_instance);

  return 0;
}

/**
 * @brief Try once to lock the vring
 * @return 0 on success, non-zero on failure.
 */
static_always_inline int
vhost_user_vring_try_lock (vhost_user_intf_t * vui, u32 qid)
{
  return clib_atomic_test_and_set (vui->vring_locks[qid]);
}

/**
 * @brief Spin until the vring is successfully locked
 */
static_always_inline void
vhost_user_vring_lock (vhost_user_intf_t * vui, u32 qid)
{
  while (vhost_user_vring_try_lock (vui, qid))
    ;
}

/**
 * @brief Unlock the vring lock
 */
static_always_inline void
vhost_user_vring_unlock (vhost_user_intf_t * vui, u32 qid)
{
  clib_atomic_release (vui->vring_locks[qid]);
}

static_always_inline void
vhost_user_tx_trace (vhost_trace_t * t,
		     vhost_user_intf_t * vui, u16 qid,
		     vlib_buffer_t * b, vhost_user_vring_t * rxvq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 last_avail_idx = rxvq->last_avail_idx;
  u32 desc_current = rxvq->avail->ring[last_avail_idx & rxvq->qsz_mask];
  vring_desc_t *hdr_desc = 0;
  u32 hint = 0;

  clib_memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &rxvq->desc[desc_current];
  if (rxvq->desc[desc_current].flags & VRING_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, rxvq->desc[desc_current].addr, &hint);
    }
  if (rxvq->desc[desc_current].flags & VRING_DESC_F_NEXT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;
    }
  if (!(rxvq->desc[desc_current].flags & VRING_DESC_F_NEXT) &&
      !(rxvq->desc[desc_current].flags & VRING_DESC_F_INDIRECT))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;
    }

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;
}

static_always_inline u32
vhost_user_tx_copy (vhost_user_intf_t * vui, vhost_copy_t * cpy,
		    u16 copy_len, u32 * map_hint)
{
  void *dst0, *dst1, *dst2, *dst3;
  if (PREDICT_TRUE (copy_len >= 4))
    {
      if (PREDICT_FALSE (!(dst2 = map_guest_mem (vui, cpy[0].dst, map_hint))))
	return 1;
      if (PREDICT_FALSE (!(dst3 = map_guest_mem (vui, cpy[1].dst, map_hint))))
	return 1;
      while (PREDICT_TRUE (copy_len >= 4))
	{
	  dst0 = dst2;
	  dst1 = dst3;

	  if (PREDICT_FALSE
	      (!(dst2 = map_guest_mem (vui, cpy[2].dst, map_hint))))
	    return 1;
	  if (PREDICT_FALSE
	      (!(dst3 = map_guest_mem (vui, cpy[3].dst, map_hint))))
	    return 1;

	  CLIB_PREFETCH ((void *) cpy[2].src, 64, LOAD);
	  CLIB_PREFETCH ((void *) cpy[3].src, 64, LOAD);

	  clib_memcpy_fast (dst0, (void *) cpy[0].src, cpy[0].len);
	  clib_memcpy_fast (dst1, (void *) cpy[1].src, cpy[1].len);

	  vhost_user_log_dirty_pages_2 (vui, cpy[0].dst, cpy[0].len, 1);
	  vhost_user_log_dirty_pages_2 (vui, cpy[1].dst, cpy[1].len, 1);
	  copy_len -= 2;
	  cpy += 2;
	}
    }
  while (copy_len)
    {
      if (PREDICT_FALSE (!(dst0 = map_guest_mem (vui, cpy->dst, map_hint))))
	return 1;
      clib_memcpy_fast (dst0, (void *) cpy->src, cpy->len);
      vhost_user_log_dirty_pages_2 (vui, cpy->dst, cpy->len, 1);
      copy_len -= 1;
      cpy += 1;
    }
  return 0;
}

static_always_inline void
vhost_user_handle_tx_offload (vhost_user_intf_t * vui, vlib_buffer_t * b,
			      virtio_net_hdr_t * hdr)
{
  generic_header_offset_t gho = { 0 };
  int is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  int is_ip6 = b->flags & VNET_BUFFER_F_IS_IP6;

  ASSERT (!(is_ip4 && is_ip6));
  vnet_generic_header_offset_parser (b, &gho, 1 /* l2 */ , is_ip4, is_ip6);
  if (b->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM)
    {
      ip4_header_t *ip4;

      ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b) + gho.l3_hdr_offset);
      ip4->checksum = ip4_header_checksum (ip4);
    }

  /* checksum offload */
  if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
    {
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = gho.l4_hdr_offset;
      hdr->csum_offset = offsetof (udp_header_t, checksum);
    }
  else if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
    {
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = gho.l4_hdr_offset;
      hdr->csum_offset = offsetof (tcp_header_t, checksum);
    }

  /* GSO offload */
  if (b->flags & VNET_BUFFER_F_GSO)
    {
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  if (is_ip4 &&
	      (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4)))
	    {
	      hdr->gso_size = vnet_buffer2 (b)->gso_size;
	      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	    }
	  else if (is_ip6 &&
		   (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6)))
	    {
	      hdr->gso_size = vnet_buffer2 (b)->gso_size;
	      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	    }
	}
      else if ((vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_UFO)) &&
	       (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))
	{
	  hdr->gso_size = vnet_buffer2 (b)->gso_size;
	  hdr->gso_type = VIRTIO_NET_HDR_GSO_UDP;
	}
    }
}

static_always_inline void
vhost_user_mark_desc_available (vlib_main_t * vm, vhost_user_intf_t * vui,
				vhost_user_vring_t * rxvq,
				u16 * n_descs_processed, u8 chained,
				vlib_frame_t * frame, u32 n_left)
{
  u16 desc_idx, flags;
  vring_packed_desc_t *desc_table = rxvq->packed_desc;
  u16 last_used_idx = rxvq->last_used_idx;

  if (PREDICT_FALSE (*n_descs_processed == 0))
    return;

  if (rxvq->used_wrap_counter)
    flags = desc_table[last_used_idx & rxvq->qsz_mask].flags |
      (VRING_DESC_F_AVAIL | VRING_DESC_F_USED);
  else
    flags = desc_table[last_used_idx & rxvq->qsz_mask].flags &
      ~(VRING_DESC_F_AVAIL | VRING_DESC_F_USED);

  vhost_user_advance_last_used_idx (rxvq);

  for (desc_idx = 1; desc_idx < *n_descs_processed; desc_idx++)
    {
      if (rxvq->used_wrap_counter)
	desc_table[rxvq->last_used_idx & rxvq->qsz_mask].flags |=
	  (VRING_DESC_F_AVAIL | VRING_DESC_F_USED);
      else
	desc_table[rxvq->last_used_idx & rxvq->qsz_mask].flags &=
	  ~(VRING_DESC_F_AVAIL | VRING_DESC_F_USED);
      vhost_user_advance_last_used_idx (rxvq);
    }

  desc_table[last_used_idx & rxvq->qsz_mask].flags = flags;

  *n_descs_processed = 0;

  if (chained)
    {
      vring_packed_desc_t *desc_table = rxvq->packed_desc;

      while (desc_table[rxvq->last_used_idx & rxvq->qsz_mask].flags &
	     VRING_DESC_F_NEXT)
	vhost_user_advance_last_used_idx (rxvq);

      /* Advance past the current chained table entries */
      vhost_user_advance_last_used_idx (rxvq);
    }

  /* interrupt (call) handling */
  if ((rxvq->callfd_idx != ~0) &&
      (rxvq->avail_event->flags != VRING_EVENT_F_DISABLE))
    {
      vhost_user_main_t *vum = &vhost_user_main;

      rxvq->n_since_last_int += frame->n_vectors - n_left;
      if (rxvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, vui, rxvq);
    }
}

static_always_inline void
vhost_user_tx_trace_packed (vhost_trace_t * t, vhost_user_intf_t * vui,
			    u16 qid, vlib_buffer_t * b,
			    vhost_user_vring_t * rxvq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 last_avail_idx = rxvq->last_avail_idx;
  u32 desc_current = last_avail_idx & rxvq->qsz_mask;
  vring_packed_desc_t *hdr_desc = 0;
  u32 hint = 0;

  clib_memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &rxvq->packed_desc[desc_current];
  if (rxvq->packed_desc[desc_current].flags & VRING_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, rxvq->packed_desc[desc_current].addr,
				&hint);
    }
  if (rxvq->packed_desc[desc_current].flags & VRING_DESC_F_NEXT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;
    }
  if (!(rxvq->packed_desc[desc_current].flags & VRING_DESC_F_NEXT) &&
      !(rxvq->packed_desc[desc_current].flags & VRING_DESC_F_INDIRECT))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;
    }

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;
}

static_always_inline uword
vhost_user_device_class_packed (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vhost_user_main_t *vum = &vhost_user_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, rd->dev_instance);
  u32 qid;
  vhost_user_vring_t *rxvq;
  u8 error;
  u32 thread_index = vm->thread_index;
  vhost_cpu_t *cpu = &vum->cpus[thread_index];
  u32 map_hint = 0;
  u8 retry = 8;
  u16 copy_len;
  u16 tx_headers_len;
  vring_packed_desc_t *desc_table;
  u32 or_flags;
  u16 desc_head, desc_index, desc_len;
  u16 n_descs_processed;
  u8 indirect, chained;

  qid = VHOST_VRING_IDX_RX (*vec_elt_at_index (vui->per_cpu_tx_qid,
					       thread_index));
  rxvq = &vui->vrings[qid];

retry:
  error = VHOST_USER_TX_FUNC_ERROR_NONE;
  tx_headers_len = 0;
  copy_len = 0;
  n_descs_processed = 0;

  while (n_left > 0)
    {
      vlib_buffer_t *b0, *current_b0;
      uword buffer_map_addr;
      u32 buffer_len;
      u16 bytes_left;
      u32 total_desc_len = 0;
      u16 n_entries = 0;

      indirect = 0;
      chained = 0;
      if (PREDICT_TRUE (n_left > 1))
	vlib_prefetch_buffer_with_index (vm, buffers[1], LOAD);

      b0 = vlib_get_buffer (vm, buffers[0]);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cpu->current_trace = vlib_add_trace (vm, node, b0,
					       sizeof (*cpu->current_trace));
	  vhost_user_tx_trace_packed (cpu->current_trace, vui, qid / 2, b0,
				      rxvq);
	}

      desc_table = rxvq->packed_desc;
      desc_head = desc_index = rxvq->last_avail_idx & rxvq->qsz_mask;
      if (PREDICT_FALSE (!vhost_user_packed_desc_available (rxvq, desc_head)))
	{
	  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
	  goto done;
	}
      /*
       * Go deeper in case of indirect descriptor.
       * To test it, turn off mrg_rxbuf.
       */
      if (desc_table[desc_head].flags & VRING_DESC_F_INDIRECT)
	{
	  indirect = 1;
	  if (PREDICT_FALSE (desc_table[desc_head].len <
			     sizeof (vring_packed_desc_t)))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
	      goto done;
	    }
	  n_entries = desc_table[desc_head].len >> 4;
	  desc_table = map_guest_mem (vui, desc_table[desc_index].addr,
				      &map_hint);
	  if (PREDICT_FALSE (desc_table == 0))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
	      goto done;
	    }
	  desc_index = 0;
	}
      else if (rxvq->packed_desc[desc_head].flags & VRING_DESC_F_NEXT)
	chained = 1;

      desc_len = vui->virtio_net_hdr_sz;
      buffer_map_addr = desc_table[desc_index].addr;
      buffer_len = desc_table[desc_index].len;

      /* Get a header from the header array */
      virtio_net_hdr_mrg_rxbuf_t *hdr = &cpu->tx_headers[tx_headers_len];
      tx_headers_len++;
      hdr->hdr.flags = 0;
      hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
      hdr->num_buffers = 1;

      or_flags = (b0->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM) ||
	(b0->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM) ||
	(b0->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM);

      /* Guest supports csum offload and buffer requires checksum offload? */
      if (or_flags &&
	  (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)))
	vhost_user_handle_tx_offload (vui, b0, &hdr->hdr);

      /* Prepare a copy order executed later for the header */
      ASSERT (copy_len < VHOST_USER_COPY_ARRAY_N);
      vhost_copy_t *cpy = &cpu->copy[copy_len];
      copy_len++;
      cpy->len = vui->virtio_net_hdr_sz;
      cpy->dst = buffer_map_addr;
      cpy->src = (uword) hdr;

      buffer_map_addr += vui->virtio_net_hdr_sz;
      buffer_len -= vui->virtio_net_hdr_sz;
      bytes_left = b0->current_length;
      current_b0 = b0;
      while (1)
	{
	  if (buffer_len == 0)
	    {
	      /* Get new output */
	      if (chained)
		{
		  /*
		   * Next one is chained
		   * Test it with both indirect and mrg_rxbuf off
		   */
		  if (PREDICT_FALSE (!(desc_table[desc_index].flags &
				       VRING_DESC_F_NEXT)))
		    {
		      /*
		       * Last descriptor in chain.
		       * Dequeue queued descriptors for this packet
		       */
		      vhost_user_dequeue_chained_descs (rxvq,
							&n_descs_processed);
		      error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
		      goto done;
		    }
		  vhost_user_advance_last_avail_idx (rxvq);
		  desc_index = rxvq->last_avail_idx & rxvq->qsz_mask;
		  n_descs_processed++;
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		  total_desc_len += desc_len;
		  desc_len = 0;
		}
	      else if (indirect)
		{
		  /*
		   * Indirect table
		   * Test it with mrg_rxnuf off
		   */
		  if (PREDICT_TRUE (n_entries > 0))
		    n_entries--;
		  else
		    {
		      /* Dequeue queued descriptors for this packet */
		      vhost_user_dequeue_chained_descs (rxvq,
							&n_descs_processed);
		      error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
		      goto done;
		    }
		  total_desc_len += desc_len;
		  desc_index = (desc_index + 1) & rxvq->qsz_mask;
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		  desc_len = 0;
		}
	      else if (vui->virtio_net_hdr_sz == 12)
		{
		  /*
		   * MRG is available
		   * This is the default setting for the guest VM
		   */
		  virtio_net_hdr_mrg_rxbuf_t *hdr =
		    &cpu->tx_headers[tx_headers_len - 1];

		  desc_table[desc_index].len = desc_len;
		  vhost_user_advance_last_avail_idx (rxvq);
		  desc_head = desc_index =
		    rxvq->last_avail_idx & rxvq->qsz_mask;
		  hdr->num_buffers++;
		  n_descs_processed++;
		  desc_len = 0;

		  if (PREDICT_FALSE (!vhost_user_packed_desc_available
				     (rxvq, desc_index)))
		    {
		      /* Dequeue queued descriptors for this packet */
		      vhost_user_dequeue_descs (rxvq, hdr,
						&n_descs_processed);
		      error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
		      goto done;
		    }

		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		}
	      else
		{
		  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOMRG;
		  goto done;
		}
	    }

	  ASSERT (copy_len < VHOST_USER_COPY_ARRAY_N);
	  vhost_copy_t *cpy = &cpu->copy[copy_len];
	  copy_len++;
	  cpy->len = bytes_left;
	  cpy->len = (cpy->len > buffer_len) ? buffer_len : cpy->len;
	  cpy->dst = buffer_map_addr;
	  cpy->src = (uword) vlib_buffer_get_current (current_b0) +
	    current_b0->current_length - bytes_left;

	  bytes_left -= cpy->len;
	  buffer_len -= cpy->len;
	  buffer_map_addr += cpy->len;
	  desc_len += cpy->len;

	  CLIB_PREFETCH (&rxvq->packed_desc, CLIB_CACHE_LINE_BYTES, LOAD);

	  /* Check if vlib buffer has more data. If not, get more or break */
	  if (PREDICT_TRUE (!bytes_left))
	    {
	      if (PREDICT_FALSE
		  (current_b0->flags & VLIB_BUFFER_NEXT_PRESENT))
		{
		  current_b0 = vlib_get_buffer (vm, current_b0->next_buffer);
		  bytes_left = current_b0->current_length;
		}
	      else
		{
		  /* End of packet */
		  break;
		}
	    }
	}

      /* Move from available to used ring */
      total_desc_len += desc_len;
      rxvq->packed_desc[desc_head].len = total_desc_len;

      vhost_user_advance_last_avail_table_idx (vui, rxvq, chained);
      n_descs_processed++;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	cpu->current_trace->hdr = cpu->tx_headers[tx_headers_len - 1];

      n_left--;

      /*
       * Do the copy periodically to prevent
       * cpu->copy array overflow and corrupt memory
       */
      if (PREDICT_FALSE (copy_len >= VHOST_USER_TX_COPY_THRESHOLD) || chained)
	{
	  if (PREDICT_FALSE (vhost_user_tx_copy (vui, cpu->copy, copy_len,
						 &map_hint)))
	    vlib_error_count (vm, node->node_index,
			      VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);
	  copy_len = 0;

	  /* give buffers back to driver */
	  vhost_user_mark_desc_available (vm, vui, rxvq, &n_descs_processed,
					  chained, frame, n_left);
	}

      buffers++;
    }

done:
  if (PREDICT_TRUE (copy_len))
    {
      if (PREDICT_FALSE (vhost_user_tx_copy (vui, cpu->copy, copy_len,
					     &map_hint)))
	vlib_error_count (vm, node->node_index,
			  VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);

      vhost_user_mark_desc_available (vm, vui, rxvq, &n_descs_processed,
				      chained, frame, n_left);
    }

  /*
   * When n_left is set, error is always set to something too.
   * In case error is due to lack of remaining buffers, we go back up and
   * retry.
   * The idea is that it is better to waste some time on packets
   * that have been processed already than dropping them and get
   * more fresh packets with a good likelyhood that they will be dropped too.
   * This technique also gives more time to VM driver to pick-up packets.
   * In case the traffic flows from physical to virtual interfaces, this
   * technique will end-up leveraging the physical NIC buffer in order to
   * absorb the VM's CPU jitter.
   */
  if (n_left && (error == VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF) && retry)
    {
      retry--;
      goto retry;
    }

  vhost_user_vring_unlock (vui, qid);

  if (PREDICT_FALSE (n_left && error != VHOST_USER_TX_FUNC_ERROR_NONE))
    {
      vlib_error_count (vm, node->node_index, error, n_left);
      vlib_increment_simple_counter
	(vnet_main.interface_main.sw_if_counters +
	 VNET_INTERFACE_COUNTER_DROP, thread_index, vui->sw_if_index, n_left);
    }

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

VNET_DEVICE_CLASS_TX_FN (vhost_user_device_class) (vlib_main_t * vm,
						   vlib_node_runtime_t *
						   node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vhost_user_main_t *vum = &vhost_user_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, rd->dev_instance);
  u32 qid = ~0;
  vhost_user_vring_t *rxvq;
  u8 error;
  u32 thread_index = vm->thread_index;
  vhost_cpu_t *cpu = &vum->cpus[thread_index];
  u32 map_hint = 0;
  u8 retry = 8;
  u16 copy_len;
  u16 tx_headers_len;
  u32 or_flags;

  if (PREDICT_FALSE (!vui->admin_up))
    {
      error = VHOST_USER_TX_FUNC_ERROR_DOWN;
      goto done3;
    }

  if (PREDICT_FALSE (!vui->is_ready))
    {
      error = VHOST_USER_TX_FUNC_ERROR_NOT_READY;
      goto done3;
    }

  qid = VHOST_VRING_IDX_RX (*vec_elt_at_index (vui->per_cpu_tx_qid,
					       thread_index));
  rxvq = &vui->vrings[qid];
  if (PREDICT_FALSE (rxvq->avail == 0))
    {
      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
      goto done3;
    }

  if (PREDICT_FALSE (vui->use_tx_spinlock))
    vhost_user_vring_lock (vui, qid);

  if (vhost_user_is_packed_ring_supported (vui))
    return (vhost_user_device_class_packed (vm, node, frame));

retry:
  error = VHOST_USER_TX_FUNC_ERROR_NONE;
  tx_headers_len = 0;
  copy_len = 0;
  while (n_left > 0)
    {
      vlib_buffer_t *b0, *current_b0;
      u16 desc_head, desc_index, desc_len;
      vring_desc_t *desc_table;
      uword buffer_map_addr;
      u32 buffer_len;
      u16 bytes_left;

      if (PREDICT_TRUE (n_left > 1))
	vlib_prefetch_buffer_with_index (vm, buffers[1], LOAD);

      b0 = vlib_get_buffer (vm, buffers[0]);

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cpu->current_trace = vlib_add_trace (vm, node, b0,
					       sizeof (*cpu->current_trace));
	  vhost_user_tx_trace (cpu->current_trace, vui, qid / 2, b0, rxvq);
	}

      if (PREDICT_FALSE (rxvq->last_avail_idx == rxvq->avail->idx))
	{
	  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
	  goto done;
	}

      desc_table = rxvq->desc;
      desc_head = desc_index =
	rxvq->avail->ring[rxvq->last_avail_idx & rxvq->qsz_mask];

      /* Go deeper in case of indirect descriptor
       * I don't know of any driver providing indirect for RX. */
      if (PREDICT_FALSE (rxvq->desc[desc_head].flags & VRING_DESC_F_INDIRECT))
	{
	  if (PREDICT_FALSE
	      (rxvq->desc[desc_head].len < sizeof (vring_desc_t)))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
	      goto done;
	    }
	  if (PREDICT_FALSE
	      (!(desc_table =
		 map_guest_mem (vui, rxvq->desc[desc_index].addr,
				&map_hint))))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
	      goto done;
	    }
	  desc_index = 0;
	}

      desc_len = vui->virtio_net_hdr_sz;
      buffer_map_addr = desc_table[desc_index].addr;
      buffer_len = desc_table[desc_index].len;

      {
	// Get a header from the header array
	virtio_net_hdr_mrg_rxbuf_t *hdr = &cpu->tx_headers[tx_headers_len];
	tx_headers_len++;
	hdr->hdr.flags = 0;
	hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
	hdr->num_buffers = 1;	//This is local, no need to check

	or_flags = (b0->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM) ||
	  (b0->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM) ||
	  (b0->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM);

	/* Guest supports csum offload and buffer requires checksum offload? */
	if (or_flags
	    && (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)))
	  vhost_user_handle_tx_offload (vui, b0, &hdr->hdr);

	// Prepare a copy order executed later for the header
	ASSERT (copy_len < VHOST_USER_COPY_ARRAY_N);
	vhost_copy_t *cpy = &cpu->copy[copy_len];
	copy_len++;
	cpy->len = vui->virtio_net_hdr_sz;
	cpy->dst = buffer_map_addr;
	cpy->src = (uword) hdr;
      }

      buffer_map_addr += vui->virtio_net_hdr_sz;
      buffer_len -= vui->virtio_net_hdr_sz;
      bytes_left = b0->current_length;
      current_b0 = b0;
      while (1)
	{
	  if (buffer_len == 0)
	    {			//Get new output
	      if (desc_table[desc_index].flags & VRING_DESC_F_NEXT)
		{
		  //Next one is chained
		  desc_index = desc_table[desc_index].next;
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		}
	      else if (vui->virtio_net_hdr_sz == 12)	//MRG is available
		{
		  virtio_net_hdr_mrg_rxbuf_t *hdr =
		    &cpu->tx_headers[tx_headers_len - 1];

		  //Move from available to used buffer
		  rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].id =
		    desc_head;
		  rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].len =
		    desc_len;
		  vhost_user_log_dirty_ring (vui, rxvq,
					     ring[rxvq->last_used_idx &
						  rxvq->qsz_mask]);

		  rxvq->last_avail_idx++;
		  rxvq->last_used_idx++;
		  hdr->num_buffers++;
		  desc_len = 0;

		  if (PREDICT_FALSE
		      (rxvq->last_avail_idx == rxvq->avail->idx))
		    {
		      //Dequeue queued descriptors for this packet
		      rxvq->last_used_idx -= hdr->num_buffers - 1;
		      rxvq->last_avail_idx -= hdr->num_buffers - 1;
		      error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
		      goto done;
		    }

		  desc_table = rxvq->desc;
		  desc_head = desc_index =
		    rxvq->avail->ring[rxvq->last_avail_idx & rxvq->qsz_mask];
		  if (PREDICT_FALSE
		      (rxvq->desc[desc_head].flags & VRING_DESC_F_INDIRECT))
		    {
		      //It is seriously unlikely that a driver will put indirect descriptor
		      //after non-indirect descriptor.
		      if (PREDICT_FALSE
			  (rxvq->desc[desc_head].len < sizeof (vring_desc_t)))
			{
			  error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
			  goto done;
			}
		      if (PREDICT_FALSE
			  (!(desc_table =
			     map_guest_mem (vui,
					    rxvq->desc[desc_index].addr,
					    &map_hint))))
			{
			  error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
			  goto done;
			}
		      desc_index = 0;
		    }
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		}
	      else
		{
		  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOMRG;
		  goto done;
		}
	    }

	  {
	    ASSERT (copy_len < VHOST_USER_COPY_ARRAY_N);
	    vhost_copy_t *cpy = &cpu->copy[copy_len];
	    copy_len++;
	    cpy->len = bytes_left;
	    cpy->len = (cpy->len > buffer_len) ? buffer_len : cpy->len;
	    cpy->dst = buffer_map_addr;
	    cpy->src = (uword) vlib_buffer_get_current (current_b0) +
	      current_b0->current_length - bytes_left;

	    bytes_left -= cpy->len;
	    buffer_len -= cpy->len;
	    buffer_map_addr += cpy->len;
	    desc_len += cpy->len;

	    CLIB_PREFETCH (&rxvq->desc, CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  // Check if vlib buffer has more data. If not, get more or break.
	  if (PREDICT_TRUE (!bytes_left))
	    {
	      if (PREDICT_FALSE
		  (current_b0->flags & VLIB_BUFFER_NEXT_PRESENT))
		{
		  current_b0 = vlib_get_buffer (vm, current_b0->next_buffer);
		  bytes_left = current_b0->current_length;
		}
	      else
		{
		  //End of packet
		  break;
		}
	    }
	}

      //Move from available to used ring
      rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].id = desc_head;
      rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].len = desc_len;
      vhost_user_log_dirty_ring (vui, rxvq,
				 ring[rxvq->last_used_idx & rxvq->qsz_mask]);
      rxvq->last_avail_idx++;
      rxvq->last_used_idx++;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cpu->current_trace->hdr = cpu->tx_headers[tx_headers_len - 1];
	}

      n_left--;			//At the end for error counting when 'goto done' is invoked

      /*
       * Do the copy periodically to prevent
       * cpu->copy array overflow and corrupt memory
       */
      if (PREDICT_FALSE (copy_len >= VHOST_USER_TX_COPY_THRESHOLD))
	{
	  if (PREDICT_FALSE (vhost_user_tx_copy (vui, cpu->copy, copy_len,
						 &map_hint)))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);
	    }
	  copy_len = 0;

	  /* give buffers back to driver */
	  CLIB_MEMORY_BARRIER ();
	  rxvq->used->idx = rxvq->last_used_idx;
	  vhost_user_log_dirty_ring (vui, rxvq, idx);
	}
      buffers++;
    }

done:
  //Do the memory copies
  if (PREDICT_FALSE (vhost_user_tx_copy (vui, cpu->copy, copy_len,
					 &map_hint)))
    {
      vlib_error_count (vm, node->node_index,
			VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);
    }

  CLIB_MEMORY_BARRIER ();
  rxvq->used->idx = rxvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, rxvq, idx);

  /*
   * When n_left is set, error is always set to something too.
   * In case error is due to lack of remaining buffers, we go back up and
   * retry.
   * The idea is that it is better to waste some time on packets
   * that have been processed already than dropping them and get
   * more fresh packets with a good likelihood that they will be dropped too.
   * This technique also gives more time to VM driver to pick-up packets.
   * In case the traffic flows from physical to virtual interfaces, this
   * technique will end-up leveraging the physical NIC buffer in order to
   * absorb the VM's CPU jitter.
   */
  if (n_left && (error == VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF) && retry)
    {
      retry--;
      goto retry;
    }

  /* interrupt (call) handling */
  if ((rxvq->callfd_idx != ~0) &&
      !(rxvq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
    {
      rxvq->n_since_last_int += frame->n_vectors - n_left;

      if (rxvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, vui, rxvq);
    }

  vhost_user_vring_unlock (vui, qid);

done3:
  if (PREDICT_FALSE (n_left && error != VHOST_USER_TX_FUNC_ERROR_NONE))
    {
      vlib_error_count (vm, node->node_index, error, n_left);
      vlib_increment_simple_counter
	(vnet_main.interface_main.sw_if_counters
	 + VNET_INTERFACE_COUNTER_DROP,
	 thread_index, vui->sw_if_index, n_left);
    }

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static __clib_unused clib_error_t *
vhost_user_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index,
				     u32 qid, vnet_hw_if_rx_mode mode)
{
  vlib_main_t *vm = vnm->vlib_main;
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, hif->dev_instance);
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];

  if ((mode == VNET_HW_IF_RX_MODE_INTERRUPT) ||
      (mode == VNET_HW_IF_RX_MODE_ADAPTIVE))
    {
      if (txvq->kickfd_idx == ~0)
	{
	  // We cannot support interrupt mode if the driver opts out
	  return clib_error_return (0, "Driver does not support interrupt");
	}
      if (txvq->mode == VNET_HW_IF_RX_MODE_POLLING)
	{
	  vum->ifq_count++;
	  // Start the timer if this is the first encounter on interrupt
	  // interface/queue
	  if ((vum->ifq_count == 1) &&
	      (vum->coalesce_time > 0.0) && (vum->coalesce_frames > 0))
	    vlib_process_signal_event (vm,
				       vhost_user_send_interrupt_node.index,
				       VHOST_USER_EVENT_START_TIMER, 0);
	}
    }
  else if (mode == VNET_HW_IF_RX_MODE_POLLING)
    {
      if (((txvq->mode == VNET_HW_IF_RX_MODE_INTERRUPT) ||
	   (txvq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)) && vum->ifq_count)
	{
	  vum->ifq_count--;
	  // Stop the timer if there is no more interrupt interface/queue
	  if ((vum->ifq_count == 0) &&
	      (vum->coalesce_time > 0.0) && (vum->coalesce_frames > 0))
	    vlib_process_signal_event (vm,
				       vhost_user_send_interrupt_node.index,
				       VHOST_USER_EVENT_STOP_TIMER, 0);
	}
    }

  txvq->mode = mode;
  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    txvq->used->flags = VRING_USED_F_NO_NOTIFY;
  else if ((mode == VNET_HW_IF_RX_MODE_ADAPTIVE) ||
	   (mode == VNET_HW_IF_RX_MODE_INTERRUPT))
    txvq->used->flags = 0;
  else
    {
      vu_log_err (vui, "unhandled mode %d changed for if %d queue %d", mode,
		  hw_if_index, qid);
      return clib_error_return (0, "unsupported");
    }

  return 0;
}

static __clib_unused clib_error_t *
vhost_user_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				    u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, hif->dev_instance);
  u8 link_old, link_new;

  link_old = vui_is_link_up (vui);

  vui->admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  link_new = vui_is_link_up (vui);

  if (link_old != link_new)
    vnet_hw_interface_set_flags (vnm, vui->hw_if_index, link_new ?
				 VNET_HW_INTERFACE_FLAG_LINK_UP : 0);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vhost_user_device_class) = {
  .name = "vhost-user",
  .tx_function_n_errors = VHOST_USER_TX_FUNC_N_ERROR,
  .tx_function_error_strings = vhost_user_tx_func_error_strings,
  .format_device_name = format_vhost_user_interface_name,
  .name_renumber = vhost_user_name_renumber,
  .admin_up_down_function = vhost_user_interface_admin_up_down,
  .rx_mode_change_function = vhost_user_interface_rx_mode_change,
  .format_tx_trace = format_vhost_trace,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
