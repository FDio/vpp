/*
 *------------------------------------------------------------------
 * vhost-user-input
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
#include <vnet/udp/udp_packet.h>

#include <vnet/devices/virtio/vhost_user.h>
#include <vnet/devices/virtio/vhost_user_inline.h>

/*
 * When an RX queue is down but active, received packets
 * must be discarded. This value controls up to how many
 * packets will be discarded during each round.
 */
#define VHOST_USER_DOWN_DISCARD_COUNT 256

/*
 * When the number of available buffers gets under this threshold,
 * RX node will start discarding packets.
 */
#define VHOST_USER_RX_BUFFER_STARVATION 32

/*
 * On the receive side, the host should free descriptors as soon
 * as possible in order to avoid TX drop in the VM.
 * This value controls the number of copy operations that are stacked
 * before copy is done for all and descriptors are given back to
 * the guest.
 * The value 64 was obtained by testing (48 and 128 were not as good).
 */
#define VHOST_USER_RX_COPY_THRESHOLD 64

extern vlib_node_registration_t vhost_user_input_node;

#define foreach_vhost_user_input_func_error      \
  _(NO_ERROR, "no error")  \
  _(NO_BUFFER, "no available buffer")  \
  _(MMAP_FAIL, "mmap failure")  \
  _(INDIRECT_OVERFLOW, "indirect descriptor overflows table")  \
  _(UNDERSIZED_FRAME, "undersized ethernet frame received (< 14 bytes)") \
  _(NOT_READY, "vhost interface not ready or down") \
  _(FULL_RX_QUEUE, "full rx queue (possible driver tx drop)")

typedef enum
{
#define _(f,s) VHOST_USER_INPUT_FUNC_ERROR_##f,
  foreach_vhost_user_input_func_error
#undef _
    VHOST_USER_INPUT_FUNC_N_ERROR,
} vhost_user_input_func_error_t;

static __clib_unused char *vhost_user_input_func_error_strings[] = {
#define _(n,s) s,
  foreach_vhost_user_input_func_error
#undef _
};

static_always_inline void
vhost_user_rx_trace (vhost_trace_t * t,
		     vhost_user_intf_t * vui, u16 qid,
		     vlib_buffer_t * b, vhost_user_vring_t * txvq,
		     u16 last_avail_idx)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 desc_current = txvq->avail->ring[last_avail_idx & txvq->qsz_mask];
  vring_desc_t *hdr_desc = 0;
  virtio_net_hdr_mrg_rxbuf_t *hdr;
  u32 hint = 0;

  clib_memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &txvq->desc[desc_current];
  if (txvq->desc[desc_current].flags & VRING_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, txvq->desc[desc_current].addr, &hint);
    }
  if (txvq->desc[desc_current].flags & VRING_DESC_F_NEXT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;
    }
  if (!(txvq->desc[desc_current].flags & VRING_DESC_F_NEXT) &&
      !(txvq->desc[desc_current].flags & VRING_DESC_F_INDIRECT))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;
    }

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;

  if (!hdr_desc || !(hdr = map_guest_mem (vui, hdr_desc->addr, &hint)))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_MAP_ERROR;
    }
  else
    {
      u32 len = vui->virtio_net_hdr_sz;
      memcpy (&t->hdr, hdr, len > hdr_desc->len ? hdr_desc->len : len);
    }
}

static_always_inline u32
vhost_user_input_copy (vhost_user_intf_t * vui, vhost_copy_t * cpy,
		       u16 copy_len, u32 * map_hint)
{
  void *src0, *src1, *src2, *src3;
  if (PREDICT_TRUE (copy_len >= 4))
    {
      if (PREDICT_FALSE (!(src2 = map_guest_mem (vui, cpy[0].src, map_hint))))
	return 1;
      if (PREDICT_FALSE (!(src3 = map_guest_mem (vui, cpy[1].src, map_hint))))
	return 1;

      while (PREDICT_TRUE (copy_len >= 4))
	{
	  src0 = src2;
	  src1 = src3;

	  if (PREDICT_FALSE
	      (!(src2 = map_guest_mem (vui, cpy[2].src, map_hint))))
	    return 1;
	  if (PREDICT_FALSE
	      (!(src3 = map_guest_mem (vui, cpy[3].src, map_hint))))
	    return 1;

	  CLIB_PREFETCH (src2, 64, LOAD);
	  CLIB_PREFETCH (src3, 64, LOAD);

	  clib_memcpy_fast ((void *) cpy[0].dst, src0, cpy[0].len);
	  clib_memcpy_fast ((void *) cpy[1].dst, src1, cpy[1].len);
	  copy_len -= 2;
	  cpy += 2;
	}
    }
  while (copy_len)
    {
      if (PREDICT_FALSE (!(src0 = map_guest_mem (vui, cpy->src, map_hint))))
	return 1;
      clib_memcpy_fast ((void *) cpy->dst, src0, cpy->len);
      copy_len -= 1;
      cpy += 1;
    }
  return 0;
}

/**
 * Try to discard packets from the tx ring (VPP RX path).
 * Returns the number of discarded packets.
 */
static_always_inline u32
vhost_user_rx_discard_packet (vlib_main_t * vm,
			      vhost_user_intf_t * vui,
			      vhost_user_vring_t * txvq, u32 discard_max)
{
  /*
   * On the RX side, each packet corresponds to one descriptor
   * (it is the same whether it is a shallow descriptor, chained, or indirect).
   * Therefore, discarding a packet is like discarding a descriptor.
   */
  u32 discarded_packets = 0;
  u32 avail_idx = txvq->avail->idx;
  u16 mask = txvq->qsz_mask;
  u16 last_avail_idx = txvq->last_avail_idx;
  u16 last_used_idx = txvq->last_used_idx;
  while (discarded_packets != discard_max)
    {
      if (avail_idx == last_avail_idx)
	goto out;

      u16 desc_chain_head = txvq->avail->ring[last_avail_idx & mask];
      last_avail_idx++;
      txvq->used->ring[last_used_idx & mask].id = desc_chain_head;
      txvq->used->ring[last_used_idx & mask].len = 0;
      vhost_user_log_dirty_ring (vui, txvq, ring[last_used_idx & mask]);
      last_used_idx++;
      discarded_packets++;
    }

out:
  txvq->last_avail_idx = last_avail_idx;
  txvq->last_used_idx = last_used_idx;
  CLIB_MEMORY_STORE_BARRIER ();
  txvq->used->idx = txvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, txvq, idx);
  return discarded_packets;
}

/*
 * In case of overflow, we need to rewind the array of allocated buffers.
 */
static_always_inline void
vhost_user_input_rewind_buffers (vlib_main_t * vm,
				 vhost_cpu_t * cpu, vlib_buffer_t * b_head)
{
  u32 bi_current = cpu->rx_buffers[cpu->rx_buffers_len];
  vlib_buffer_t *b_current = vlib_get_buffer (vm, bi_current);
  b_current->current_length = 0;
  b_current->flags = 0;
  while (b_current != b_head)
    {
      cpu->rx_buffers_len++;
      bi_current = cpu->rx_buffers[cpu->rx_buffers_len];
      b_current = vlib_get_buffer (vm, bi_current);
      b_current->current_length = 0;
      b_current->flags = 0;
    }
  cpu->rx_buffers_len++;
}

static_always_inline void
vhost_user_handle_rx_offload (vlib_buffer_t * b0, u8 * b0_data,
			      virtio_net_hdr_t * hdr)
{
  u8 l4_hdr_sz = 0;
  u8 l4_proto = 0;
  ethernet_header_t *eh = (ethernet_header_t *) b0_data;
  u16 ethertype = clib_net_to_host_u16 (eh->type);
  u16 l2hdr_sz = sizeof (ethernet_header_t);

  if (ethernet_frame_is_tagged (ethertype))
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

      ethertype = clib_net_to_host_u16 (vlan->type);
      l2hdr_sz += sizeof (*vlan);
      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vlan++;
	  ethertype = clib_net_to_host_u16 (vlan->type);
	  l2hdr_sz += sizeof (*vlan);
	}
    }
  vnet_buffer (b0)->l2_hdr_offset = 0;
  vnet_buffer (b0)->l3_hdr_offset = l2hdr_sz;
  vnet_buffer (b0)->l4_hdr_offset = hdr->csum_start;
  b0->flags |= (VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 = (ip4_header_t *) (b0_data + l2hdr_sz);
      l4_proto = ip4->protocol;
      b0->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) (b0_data + l2hdr_sz);
      l4_proto = ip6->protocol;
      b0->flags |= VNET_BUFFER_F_IS_IP6;
    }

  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *)
	(b0_data + vnet_buffer (b0)->l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);
      b0->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      l4_hdr_sz = sizeof (udp_header_t);
      b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
    }

  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_UDP)
    {
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= VNET_BUFFER_F_GSO;
    }
  else if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
    {
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4);
    }
  else if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV6)
    {
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP6);
    }
}

static_always_inline void
vhost_user_input_do_interrupt (vlib_main_t * vm, vhost_user_intf_t * vui,
			       vhost_user_vring_t * txvq,
			       vhost_user_vring_t * rxvq)
{
  f64 now = vlib_time_now (vm);

  if ((txvq->n_since_last_int) && (txvq->int_deadline < now))
    vhost_user_send_call (vm, vui, txvq);

  if ((rxvq->n_since_last_int) && (rxvq->int_deadline < now))
    vhost_user_send_call (vm, vui, rxvq);
}

static_always_inline void
vhost_user_input_setup_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vhost_user_intf_t * vui,
			      u32 * current_config_index, u32 * next_index,
			      u32 ** to_next, u32 * n_left_to_next)
{
  vnet_feature_main_t *fm = &feature_main;
  u8 feature_arc_idx = fm->device_input_feature_arc_index;

  if (PREDICT_FALSE (vnet_have_features (feature_arc_idx, vui->sw_if_index)))
    {
      vnet_feature_config_main_t *cm;
      cm = &fm->feature_config_mains[feature_arc_idx];
      *current_config_index = vec_elt (cm->config_index_by_sw_if_index,
				       vui->sw_if_index);
      vnet_get_config_data (&cm->config_main, current_config_index,
			    next_index, 0);
    }

  vlib_get_new_next_frame (vm, node, *next_index, *to_next, *n_left_to_next);

  if (*next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT)
    {
      /* give some hints to ethernet-input */
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, *next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = vui->sw_if_index;
      ef->hw_if_index = vui->hw_if_index;
      vlib_frame_no_append (f);
    }
}

static_always_inline u32
vhost_user_if_input (vlib_main_t * vm,
		     vhost_user_main_t * vum,
		     vhost_user_intf_t * vui,
		     u16 qid, vlib_node_runtime_t * node,
		     vnet_hw_if_rx_mode mode, u8 enable_csum)
{
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];
  vnet_feature_main_t *fm = &feature_main;
  u16 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 n_left;
  u32 n_left_to_next, *to_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 map_hint = 0;
  vhost_cpu_t *cpu = &vum->cpus[vm->thread_index];
  u16 copy_len = 0;
  u8 feature_arc_idx = fm->device_input_feature_arc_index;
  u32 current_config_index = ~(u32) 0;
  u16 mask = txvq->qsz_mask;

  /* The descriptor table is not ready yet */
  if (PREDICT_FALSE (txvq->avail == 0))
    goto done;

  {
    /* do we have pending interrupts ? */
    vhost_user_vring_t *rxvq = &vui->vrings[VHOST_VRING_IDX_RX (qid)];
    vhost_user_input_do_interrupt (vm, vui, txvq, rxvq);
  }

  /*
   * For adaptive mode, it is optimized to reduce interrupts.
   * If the scheduler switches the input node to polling due
   * to burst of traffic, we tell the driver no interrupt.
   * When the traffic subsides, the scheduler switches the node back to
   * interrupt mode. We must tell the driver we want interrupt.
   */
  if (PREDICT_FALSE (mode == VNET_HW_IF_RX_MODE_ADAPTIVE))
    {
      if ((node->flags &
	   VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE) ||
	  !(node->flags &
	    VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	/* Tell driver we want notification */
	txvq->used->flags = 0;
      else
	/* Tell driver we don't want notification */
	txvq->used->flags = VRING_USED_F_NO_NOTIFY;
    }

  if (PREDICT_FALSE (txvq->avail->flags & 0xFFFE))
    goto done;

  n_left = (u16) (txvq->avail->idx - txvq->last_avail_idx);

  /* nothing to do */
  if (PREDICT_FALSE (n_left == 0))
    goto done;

  if (PREDICT_FALSE (!vui->admin_up || !(txvq->enabled)))
    {
      /*
       * Discard input packet if interface is admin down or vring is not
       * enabled.
       * "For example, for a networking device, in the disabled state
       * client must not supply any new RX packets, but must process
       * and discard any TX packets."
       */
      vhost_user_rx_discard_packet (vm, vui, txvq,
				    VHOST_USER_DOWN_DISCARD_COUNT);
      goto done;
    }

  if (PREDICT_FALSE (n_left == (mask + 1)))
    {
      /*
       * Informational error logging when VPP is not
       * receiving packets fast enough.
       */
      vlib_error_count (vm, node->node_index,
			VHOST_USER_INPUT_FUNC_ERROR_FULL_RX_QUEUE, 1);
    }

  if (n_left > VLIB_FRAME_SIZE)
    n_left = VLIB_FRAME_SIZE;

  /*
   * For small packets (<2kB), we will not need more than one vlib buffer
   * per packet. In case packets are bigger, we will just yield at some point
   * in the loop and come back later. This is not an issue as for big packet,
   * processing cost really comes from the memory copy.
   * The assumption is that big packets will fit in 40 buffers.
   */
  if (PREDICT_FALSE (cpu->rx_buffers_len < n_left + 1 ||
		     cpu->rx_buffers_len < 40))
    {
      u32 curr_len = cpu->rx_buffers_len;
      cpu->rx_buffers_len +=
	vlib_buffer_alloc (vm, cpu->rx_buffers + curr_len,
			   VHOST_USER_RX_BUFFERS_N - curr_len);

      if (PREDICT_FALSE
	  (cpu->rx_buffers_len < VHOST_USER_RX_BUFFER_STARVATION))
	{
	  /* In case of buffer starvation, discard some packets from the queue
	   * and log the event.
	   * We keep doing best effort for the remaining packets. */
	  u32 flush = (n_left + 1 > cpu->rx_buffers_len) ?
	    n_left + 1 - cpu->rx_buffers_len : 1;
	  flush = vhost_user_rx_discard_packet (vm, vui, txvq, flush);

	  n_left -= flush;
	  vlib_increment_simple_counter (vnet_main.
					 interface_main.sw_if_counters +
					 VNET_INTERFACE_COUNTER_DROP,
					 vm->thread_index, vui->sw_if_index,
					 flush);

	  vlib_error_count (vm, vhost_user_input_node.index,
			    VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER, flush);
	}
    }

  vhost_user_input_setup_frame (vm, node, vui, &current_config_index,
				&next_index, &to_next, &n_left_to_next);

  u16 last_avail_idx = txvq->last_avail_idx;
  u16 last_used_idx = txvq->last_used_idx;

  while (n_left > 0)
    {
      vlib_buffer_t *b_head, *b_current;
      u32 bi_current;
      u16 desc_current;
      u32 desc_data_offset;
      vring_desc_t *desc_table = txvq->desc;

      if (PREDICT_FALSE (cpu->rx_buffers_len <= 1))
	{
	  /* Not enough rx_buffers
	   * Note: We yeld on 1 so we don't need to do an additional
	   * check for the next buffer prefetch.
	   */
	  n_left = 0;
	  break;
	}

      desc_current = txvq->avail->ring[last_avail_idx & mask];
      cpu->rx_buffers_len--;
      bi_current = cpu->rx_buffers[cpu->rx_buffers_len];
      b_head = b_current = vlib_get_buffer (vm, bi_current);
      to_next[0] = bi_current;	//We do that now so we can forget about bi_current
      to_next++;
      n_left_to_next--;

      vlib_prefetch_buffer_with_index
	(vm, cpu->rx_buffers[cpu->rx_buffers_len - 1], LOAD);

      /* Just preset the used descriptor id and length for later */
      txvq->used->ring[last_used_idx & mask].id = desc_current;
      txvq->used->ring[last_used_idx & mask].len = 0;
      vhost_user_log_dirty_ring (vui, txvq, ring[last_used_idx & mask]);

      /* The buffer should already be initialized */
      b_head->total_length_not_including_first_buffer = 0;
      b_head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

      if (PREDICT_FALSE
	  (n_trace > 0 && vlib_trace_buffer (vm, node, next_index, b_head,
					     /* follow_chain */ 0)))
	{
	  vhost_trace_t *t0 =
	    vlib_add_trace (vm, node, b_head, sizeof (t0[0]));
	  vhost_user_rx_trace (t0, vui, qid, b_head, txvq, last_avail_idx);
	  n_trace--;
	  vlib_set_trace_count (vm, node, n_trace);
	}

      /* This depends on the setup but is very consistent
       * So I think the CPU branch predictor will make a pretty good job
       * at optimizing the decision. */
      if (txvq->desc[desc_current].flags & VRING_DESC_F_INDIRECT)
	{
	  desc_table = map_guest_mem (vui, txvq->desc[desc_current].addr,
				      &map_hint);
	  desc_current = 0;
	  if (PREDICT_FALSE (desc_table == 0))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
	      goto out;
	    }
	}

      desc_data_offset = vui->virtio_net_hdr_sz;

      if (enable_csum)
	{
	  virtio_net_hdr_mrg_rxbuf_t *hdr;
	  u8 *b_data;
	  u16 current;

	  hdr = map_guest_mem (vui, desc_table[desc_current].addr, &map_hint);
	  if (PREDICT_FALSE (hdr == 0))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
	      goto out;
	    }
	  if (hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
	    {
	      if ((desc_data_offset == desc_table[desc_current].len) &&
		  (desc_table[desc_current].flags & VRING_DESC_F_NEXT))
		{
		  current = desc_table[desc_current].next;
		  b_data = map_guest_mem (vui, desc_table[current].addr,
					  &map_hint);
		  if (PREDICT_FALSE (b_data == 0))
		    {
		      vlib_error_count (vm, node->node_index,
					VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL,
					1);
		      goto out;
		    }
		}
	      else
		b_data = (u8 *) hdr + desc_data_offset;

	      vhost_user_handle_rx_offload (b_head, b_data, &hdr->hdr);
	    }
	}

      while (1)
	{
	  /* Get more input if necessary. Or end of packet. */
	  if (desc_data_offset == desc_table[desc_current].len)
	    {
	      if (PREDICT_FALSE (desc_table[desc_current].flags &
				 VRING_DESC_F_NEXT))
		{
		  desc_current = desc_table[desc_current].next;
		  desc_data_offset = 0;
		}
	      else
		{
		  goto out;
		}
	    }

	  /* Get more output if necessary. Or end of packet. */
	  if (PREDICT_FALSE (b_current->current_length == buffer_data_size))
	    {
	      if (PREDICT_FALSE (cpu->rx_buffers_len == 0))
		{
		  /* Cancel speculation */
		  to_next--;
		  n_left_to_next++;

		  /*
		   * Checking if there are some left buffers.
		   * If not, just rewind the used buffers and stop.
		   * Note: Scheduled copies are not cancelled. This is
		   * not an issue as they would still be valid. Useless,
		   * but valid.
		   */
		  vhost_user_input_rewind_buffers (vm, cpu, b_head);
		  n_left = 0;
		  goto stop;
		}

	      /* Get next output */
	      cpu->rx_buffers_len--;
	      u32 bi_next = cpu->rx_buffers[cpu->rx_buffers_len];
	      b_current->next_buffer = bi_next;
	      b_current->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      bi_current = bi_next;
	      b_current = vlib_get_buffer (vm, bi_current);
	    }

	  /* Prepare a copy order executed later for the data */
	  ASSERT (copy_len < VHOST_USER_COPY_ARRAY_N);
	  vhost_copy_t *cpy = &cpu->copy[copy_len];
	  copy_len++;
	  u32 desc_data_l = desc_table[desc_current].len - desc_data_offset;
	  cpy->len = buffer_data_size - b_current->current_length;
	  cpy->len = (cpy->len > desc_data_l) ? desc_data_l : cpy->len;
	  cpy->dst = (uword) (vlib_buffer_get_current (b_current) +
			      b_current->current_length);
	  cpy->src = desc_table[desc_current].addr + desc_data_offset;

	  desc_data_offset += cpy->len;

	  b_current->current_length += cpy->len;
	  b_head->total_length_not_including_first_buffer += cpy->len;
	}

    out:

      n_rx_bytes += b_head->total_length_not_including_first_buffer;
      n_rx_packets++;

      b_head->total_length_not_including_first_buffer -=
	b_head->current_length;

      /* consume the descriptor and return it as used */
      last_avail_idx++;
      last_used_idx++;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b_head);

      vnet_buffer (b_head)->sw_if_index[VLIB_RX] = vui->sw_if_index;
      vnet_buffer (b_head)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      b_head->error = 0;

      if (current_config_index != ~(u32) 0)
	{
	  b_head->current_config_index = current_config_index;
	  vnet_buffer (b_head)->feature_arc_index = feature_arc_idx;
	}

      n_left--;

      /*
       * Although separating memory copies from virtio ring parsing
       * is beneficial, we can offer to perform the copies from time
       * to time in order to free some space in the ring.
       */
      if (PREDICT_FALSE (copy_len >= VHOST_USER_RX_COPY_THRESHOLD))
	{
	  if (PREDICT_FALSE (vhost_user_input_copy (vui, cpu->copy,
						    copy_len, &map_hint)))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
	    }
	  copy_len = 0;

	  /* give buffers back to driver */
	  CLIB_MEMORY_STORE_BARRIER ();
	  txvq->used->idx = last_used_idx;
	  vhost_user_log_dirty_ring (vui, txvq, idx);
	}
    }
stop:
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  txvq->last_used_idx = last_used_idx;
  txvq->last_avail_idx = last_avail_idx;

  /* Do the memory copies */
  if (PREDICT_FALSE (vhost_user_input_copy (vui, cpu->copy, copy_len,
					    &map_hint)))
    {
      vlib_error_count (vm, node->node_index,
			VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
    }

  /* give buffers back to driver */
  CLIB_MEMORY_STORE_BARRIER ();
  txvq->used->idx = txvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, txvq, idx);

  /* interrupt (call) handling */
  if ((txvq->callfd_idx != ~0) &&
      !(txvq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
    {
      txvq->n_since_last_int += n_rx_packets;

      if (txvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, vui, txvq);
    }

  /* increase rx counters */
  vlib_increment_combined_counter
    (vnet_main.interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, vm->thread_index, vui->sw_if_index,
     n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (vm->thread_index, n_rx_packets);

done:
  return n_rx_packets;
}

static_always_inline void
vhost_user_mark_desc_consumed (vhost_user_intf_t * vui,
			       vhost_user_vring_t * txvq, u16 desc_head,
			       u16 n_descs_processed)
{
  vring_packed_desc_t *desc_table = txvq->packed_desc;
  u16 desc_idx;
  u16 mask = txvq->qsz_mask;

  for (desc_idx = 0; desc_idx < n_descs_processed; desc_idx++)
    {
      if (txvq->used_wrap_counter)
	desc_table[(desc_head + desc_idx) & mask].flags |=
	  (VRING_DESC_F_AVAIL | VRING_DESC_F_USED);
      else
	desc_table[(desc_head + desc_idx) & mask].flags &=
	  ~(VRING_DESC_F_AVAIL | VRING_DESC_F_USED);
      vhost_user_advance_last_used_idx (txvq);
    }
}

static_always_inline void
vhost_user_rx_trace_packed (vhost_trace_t * t, vhost_user_intf_t * vui,
			    u16 qid, vhost_user_vring_t * txvq,
			    u16 desc_current)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vring_packed_desc_t *hdr_desc;
  virtio_net_hdr_mrg_rxbuf_t *hdr;
  u32 hint = 0;

  clib_memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &txvq->packed_desc[desc_current];
  if (txvq->packed_desc[desc_current].flags & VRING_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, txvq->packed_desc[desc_current].addr,
				&hint);
    }
  if (txvq->packed_desc[desc_current].flags & VRING_DESC_F_NEXT)
    t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;

  if (!(txvq->packed_desc[desc_current].flags & VRING_DESC_F_NEXT) &&
      !(txvq->packed_desc[desc_current].flags & VRING_DESC_F_INDIRECT))
    t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;

  if (!hdr_desc || !(hdr = map_guest_mem (vui, hdr_desc->addr, &hint)))
    t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_MAP_ERROR;
  else
    {
      u32 len = vui->virtio_net_hdr_sz;
      clib_memcpy_fast (&t->hdr, hdr,
			len > hdr_desc->len ? hdr_desc->len : len);
    }
}

static_always_inline u32
vhost_user_rx_discard_packet_packed (vlib_main_t * vm,
				     vhost_user_intf_t * vui,
				     vhost_user_vring_t * txvq,
				     u32 discard_max)
{
  u32 discarded_packets = 0;
  u16 mask = txvq->qsz_mask;
  u16 desc_current, desc_head;

  desc_head = desc_current = txvq->last_used_idx & mask;

  /*
   * On the RX side, each packet corresponds to one descriptor
   * (it is the same whether it is a shallow descriptor, chained, or indirect).
   * Therefore, discarding a packet is like discarding a descriptor.
   */
  while ((discarded_packets != discard_max) &&
	 vhost_user_packed_desc_available (txvq, desc_current))
    {
      vhost_user_advance_last_avail_idx (txvq);
      discarded_packets++;
      desc_current = (desc_current + 1) & mask;
    }

  if (PREDICT_TRUE (discarded_packets))
    vhost_user_mark_desc_consumed (vui, txvq, desc_head, discarded_packets);
  return (discarded_packets);
}

static_always_inline u32
vhost_user_input_copy_packed (vhost_user_intf_t * vui, vhost_copy_t * cpy,
			      u16 copy_len, u32 * map_hint)
{
  void *src0, *src1, *src2, *src3, *src4, *src5, *src6, *src7;
  u8 bad;
  u32 rc = VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR;

  if (PREDICT_TRUE (copy_len >= 8))
    {
      src4 = map_guest_mem (vui, cpy[0].src, map_hint);
      src5 = map_guest_mem (vui, cpy[1].src, map_hint);
      src6 = map_guest_mem (vui, cpy[2].src, map_hint);
      src7 = map_guest_mem (vui, cpy[3].src, map_hint);
      bad = (src4 == 0) + (src5 == 0) + (src6 == 0) + (src7 == 0);
      if (PREDICT_FALSE (bad))
	goto one_by_one;
      CLIB_PREFETCH (src4, 64, LOAD);
      CLIB_PREFETCH (src5, 64, LOAD);
      CLIB_PREFETCH (src6, 64, LOAD);
      CLIB_PREFETCH (src7, 64, LOAD);

      while (PREDICT_TRUE (copy_len >= 8))
	{
	  src0 = src4;
	  src1 = src5;
	  src2 = src6;
	  src3 = src7;

	  src4 = map_guest_mem (vui, cpy[4].src, map_hint);
	  src5 = map_guest_mem (vui, cpy[5].src, map_hint);
	  src6 = map_guest_mem (vui, cpy[6].src, map_hint);
	  src7 = map_guest_mem (vui, cpy[7].src, map_hint);
	  bad = (src4 == 0) + (src5 == 0) + (src6 == 0) + (src7 == 0);
	  if (PREDICT_FALSE (bad))
	    break;

	  CLIB_PREFETCH (src4, 64, LOAD);
	  CLIB_PREFETCH (src5, 64, LOAD);
	  CLIB_PREFETCH (src6, 64, LOAD);
	  CLIB_PREFETCH (src7, 64, LOAD);

	  clib_memcpy_fast ((void *) cpy[0].dst, src0, cpy[0].len);
	  clib_memcpy_fast ((void *) cpy[1].dst, src1, cpy[1].len);
	  clib_memcpy_fast ((void *) cpy[2].dst, src2, cpy[2].len);
	  clib_memcpy_fast ((void *) cpy[3].dst, src3, cpy[3].len);
	  copy_len -= 4;
	  cpy += 4;
	}
    }

one_by_one:
  while (copy_len)
    {
      if (PREDICT_FALSE (!(src0 = map_guest_mem (vui, cpy->src, map_hint))))
	{
	  rc = VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL;
	  break;
	}
      clib_memcpy_fast ((void *) cpy->dst, src0, cpy->len);
      copy_len -= 1;
      cpy += 1;
    }
  return rc;
}

static_always_inline u32
vhost_user_do_offload (vhost_user_intf_t * vui,
		       vring_packed_desc_t * desc_table, u16 desc_current,
		       u16 mask, vlib_buffer_t * b_head, u32 * map_hint)
{
  u32 rc = VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR;
  virtio_net_hdr_mrg_rxbuf_t *hdr;
  u8 *b_data;
  u32 desc_data_offset = vui->virtio_net_hdr_sz;

  hdr = map_guest_mem (vui, desc_table[desc_current].addr, map_hint);
  if (PREDICT_FALSE (hdr == 0))
    rc = VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL;
  else if (hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
    {
      if (desc_data_offset == desc_table[desc_current].len)
	{
	  desc_current = (desc_current + 1) & mask;
	  b_data =
	    map_guest_mem (vui, desc_table[desc_current].addr, map_hint);
	  if (PREDICT_FALSE (b_data == 0))
	    rc = VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL;
	  else
	    vhost_user_handle_rx_offload (b_head, b_data, &hdr->hdr);
	}
      else
	{
	  b_data = (u8 *) hdr + desc_data_offset;
	  vhost_user_handle_rx_offload (b_head, b_data, &hdr->hdr);
	}
    }

  return rc;
}

static_always_inline u32
vhost_user_compute_buffers_required (u32 desc_len, u32 buffer_data_size)
{
  div_t result;
  u32 buffers_required;

  if (PREDICT_TRUE (buffer_data_size == 2048))
    {
      buffers_required = desc_len >> 11;
      if ((desc_len & 2047) != 0)
	buffers_required++;
      return (buffers_required);
    }

  if (desc_len < buffer_data_size)
    return 1;

  result = div (desc_len, buffer_data_size);
  if (result.rem)
    buffers_required = result.quot + 1;
  else
    buffers_required = result.quot;

  return (buffers_required);
}

static_always_inline u32
vhost_user_compute_indirect_desc_len (vhost_user_intf_t * vui,
				      vhost_user_vring_t * txvq,
				      u32 buffer_data_size, u16 desc_current,
				      u32 * map_hint)
{
  vring_packed_desc_t *desc_table = txvq->packed_desc;
  u32 desc_len = 0;
  u16 desc_data_offset = vui->virtio_net_hdr_sz;
  u16 desc_idx = desc_current;
  u32 n_descs;

  n_descs = desc_table[desc_idx].len >> 4;
  desc_table = map_guest_mem (vui, desc_table[desc_idx].addr, map_hint);
  if (PREDICT_FALSE (desc_table == 0))
    return 0;

  for (desc_idx = 0; desc_idx < n_descs; desc_idx++)
    desc_len += desc_table[desc_idx].len;

  if (PREDICT_TRUE (desc_len > desc_data_offset))
    desc_len -= desc_data_offset;

  return vhost_user_compute_buffers_required (desc_len, buffer_data_size);
}

static_always_inline u32
vhost_user_compute_chained_desc_len (vhost_user_intf_t * vui,
				     vhost_user_vring_t * txvq,
				     u32 buffer_data_size, u16 * current,
				     u16 * n_left)
{
  vring_packed_desc_t *desc_table = txvq->packed_desc;
  u32 desc_len = 0;
  u16 mask = txvq->qsz_mask;

  while (desc_table[*current].flags & VRING_DESC_F_NEXT)
    {
      desc_len += desc_table[*current].len;
      (*n_left)++;
      *current = (*current + 1) & mask;
      vhost_user_advance_last_avail_idx (txvq);
    }
  desc_len += desc_table[*current].len;
  (*n_left)++;
  *current = (*current + 1) & mask;
  vhost_user_advance_last_avail_idx (txvq);

  if (PREDICT_TRUE (desc_len > vui->virtio_net_hdr_sz))
    desc_len -= vui->virtio_net_hdr_sz;

  return vhost_user_compute_buffers_required (desc_len, buffer_data_size);
}

static_always_inline void
vhost_user_assemble_packet (vring_packed_desc_t * desc_table,
			    u16 * desc_idx, vlib_buffer_t * b_head,
			    vlib_buffer_t ** b_current, u32 ** next,
			    vlib_buffer_t *** b, u32 * bi_current,
			    vhost_cpu_t * cpu, u16 * copy_len,
			    u32 * buffers_used, u32 buffers_required,
			    u32 * desc_data_offset, u32 buffer_data_size,
			    u16 mask)
{
  u32 desc_data_l;

  while (*desc_data_offset < desc_table[*desc_idx].len)
    {
      /* Get more output if necessary. Or end of packet. */
      if (PREDICT_FALSE ((*b_current)->current_length == buffer_data_size))
	{
	  /* Get next output */
	  u32 bi_next = **next;
	  (*next)++;
	  (*b_current)->next_buffer = bi_next;
	  (*b_current)->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  *bi_current = bi_next;
	  *b_current = **b;
	  (*b)++;
	  (*buffers_used)++;
	  ASSERT (*buffers_used <= buffers_required);
	}

      /* Prepare a copy order executed later for the data */
      ASSERT (*copy_len < VHOST_USER_COPY_ARRAY_N);
      vhost_copy_t *cpy = &cpu->copy[*copy_len];
      (*copy_len)++;
      desc_data_l = desc_table[*desc_idx].len - *desc_data_offset;
      cpy->len = buffer_data_size - (*b_current)->current_length;
      cpy->len = (cpy->len > desc_data_l) ? desc_data_l : cpy->len;
      cpy->dst = (uword) (vlib_buffer_get_current (*b_current) +
			  (*b_current)->current_length);
      cpy->src = desc_table[*desc_idx].addr + *desc_data_offset;

      *desc_data_offset += cpy->len;

      (*b_current)->current_length += cpy->len;
      b_head->total_length_not_including_first_buffer += cpy->len;
    }
  *desc_idx = (*desc_idx + 1) & mask;;
  *desc_data_offset = 0;
}

static_always_inline u32
vhost_user_if_input_packed (vlib_main_t * vm, vhost_user_main_t * vum,
			    vhost_user_intf_t * vui, u16 qid,
			    vlib_node_runtime_t * node,
			    vnet_hw_if_rx_mode mode, u8 enable_csum)
{
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];
  vnet_feature_main_t *fm = &feature_main;
  u8 feature_arc_idx = fm->device_input_feature_arc_index;
  u16 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 n_left = 0;
  u32 buffers_required = 0;
  u32 n_left_to_next, *to_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 map_hint = 0;
  vhost_cpu_t *cpu = &vum->cpus[vm->thread_index];
  u16 copy_len = 0;
  u32 current_config_index = ~0;
  u16 mask = txvq->qsz_mask;
  u16 desc_current, desc_head, last_used_idx;
  vring_packed_desc_t *desc_table = 0;
  u32 n_descs_processed = 0;
  u32 rv;
  vlib_buffer_t **b;
  u32 *next;
  u32 buffers_used = 0;
  u16 current, n_descs_to_process;

  /* The descriptor table is not ready yet */
  if (PREDICT_FALSE (txvq->packed_desc == 0))
    goto done;

  /* do we have pending interrupts ? */
  vhost_user_vring_t *rxvq = &vui->vrings[VHOST_VRING_IDX_RX (qid)];
  vhost_user_input_do_interrupt (vm, vui, txvq, rxvq);

  /*
   * For adaptive mode, it is optimized to reduce interrupts.
   * If the scheduler switches the input node to polling due
   * to burst of traffic, we tell the driver no interrupt.
   * When the traffic subsides, the scheduler switches the node back to
   * interrupt mode. We must tell the driver we want interrupt.
   */
  if (PREDICT_FALSE (mode == VNET_HW_IF_RX_MODE_ADAPTIVE))
    {
      if ((node->flags &
	   VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE) ||
	  !(node->flags &
	    VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	/* Tell driver we want notification */
	txvq->used_event->flags = 0;
      else
	/* Tell driver we don't want notification */
	txvq->used_event->flags = VRING_EVENT_F_DISABLE;
    }

  last_used_idx = txvq->last_used_idx & mask;
  desc_head = desc_current = last_used_idx;

  if (vhost_user_packed_desc_available (txvq, desc_current) == 0)
    goto done;

  if (PREDICT_FALSE (!vui->admin_up || !vui->is_ready || !(txvq->enabled)))
    {
      /*
       * Discard input packet if interface is admin down or vring is not
       * enabled.
       * "For example, for a networking device, in the disabled state
       * client must not supply any new RX packets, but must process
       * and discard any TX packets."
       */
      rv = vhost_user_rx_discard_packet_packed (vm, vui, txvq,
						VHOST_USER_DOWN_DISCARD_COUNT);
      vlib_error_count (vm, vhost_user_input_node.index,
			VHOST_USER_INPUT_FUNC_ERROR_NOT_READY, rv);
      goto done;
    }

  vhost_user_input_setup_frame (vm, node, vui, &current_config_index,
				&next_index, &to_next, &n_left_to_next);

  /*
   * Compute n_left and total buffers needed
   */
  desc_table = txvq->packed_desc;
  current = desc_current;
  while (vhost_user_packed_desc_available (txvq, current) &&
	 (n_left < VLIB_FRAME_SIZE))
    {
      if (desc_table[current].flags & VRING_DESC_F_INDIRECT)
	{
	  buffers_required +=
	    vhost_user_compute_indirect_desc_len (vui, txvq, buffer_data_size,
						  current, &map_hint);
	  n_left++;
	  current = (current + 1) & mask;
	  vhost_user_advance_last_avail_idx (txvq);
	}
      else
	{
	  buffers_required +=
	    vhost_user_compute_chained_desc_len (vui, txvq, buffer_data_size,
						 &current, &n_left);
	}
    }

  /* Something is broken if we need more than 10000 buffers */
  if (PREDICT_FALSE ((buffers_required == 0) || (buffers_required > 10000)))
    {
      rv = vhost_user_rx_discard_packet_packed (vm, vui, txvq, n_left);
      vlib_error_count (vm, vhost_user_input_node.index,
			VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER, rv);
      goto done;
    }

  vec_validate (cpu->to_next_list, buffers_required);
  rv = vlib_buffer_alloc (vm, cpu->to_next_list, buffers_required);
  if (PREDICT_FALSE (rv != buffers_required))
    {
      vlib_buffer_free (vm, cpu->to_next_list, rv);
      rv = vhost_user_rx_discard_packet_packed (vm, vui, txvq, n_left);
      vlib_error_count (vm, vhost_user_input_node.index,
			VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER, rv);
      goto done;
    }

  next = cpu->to_next_list;
  vec_validate (cpu->rx_buffers_pdesc, buffers_required);
  vlib_get_buffers (vm, next, cpu->rx_buffers_pdesc, buffers_required);
  b = cpu->rx_buffers_pdesc;
  n_descs_processed = n_left;

  while (n_left)
    {
      vlib_buffer_t *b_head, *b_current;
      u32 bi_current;
      u32 desc_data_offset;
      u16 desc_idx = desc_current;
      u32 n_descs;

      desc_table = txvq->packed_desc;
      to_next[0] = bi_current = next[0];
      b_head = b_current = b[0];
      b++;
      buffers_used++;
      ASSERT (buffers_used <= buffers_required);
      to_next++;
      next++;
      n_left_to_next--;

      /* The buffer should already be initialized */
      b_head->total_length_not_including_first_buffer = 0;
      b_head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      desc_data_offset = vui->virtio_net_hdr_sz;
      n_descs_to_process = 1;

      if (desc_table[desc_idx].flags & VRING_DESC_F_INDIRECT)
	{
	  n_descs = desc_table[desc_idx].len >> 4;
	  desc_table = map_guest_mem (vui, desc_table[desc_idx].addr,
				      &map_hint);
	  desc_idx = 0;
	  if (PREDICT_FALSE (desc_table == 0) ||
	      (enable_csum &&
	       (PREDICT_FALSE
		(vhost_user_do_offload
		 (vui, desc_table, desc_idx, mask, b_head,
		  &map_hint) != VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR))))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
	      to_next--;
	      next--;
	      n_left_to_next++;
	      buffers_used--;
	      b--;
	      goto out;
	    }
	  while (n_descs)
	    {
	      vhost_user_assemble_packet (desc_table, &desc_idx, b_head,
					  &b_current, &next, &b, &bi_current,
					  cpu, &copy_len, &buffers_used,
					  buffers_required, &desc_data_offset,
					  buffer_data_size, mask);
	      n_descs--;
	    }
	}
      else
	{
	  if (enable_csum)
	    {
	      rv = vhost_user_do_offload (vui, desc_table, desc_idx, mask,
					  b_head, &map_hint);
	      if (PREDICT_FALSE (rv != VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR))
		{
		  vlib_error_count (vm, node->node_index, rv, 1);
		  to_next--;
		  next--;
		  n_left_to_next++;
		  buffers_used--;
		  b--;
		  goto out;
		}
	    }
	  /*
	   * For chained descriptor, we process all chains in a single while
	   * loop. So count how many descriptors in the chain.
	   */
	  n_descs_to_process = 1;
	  while (desc_table[desc_idx].flags & VRING_DESC_F_NEXT)
	    {
	      vhost_user_assemble_packet (desc_table, &desc_idx, b_head,
					  &b_current, &next, &b, &bi_current,
					  cpu, &copy_len, &buffers_used,
					  buffers_required, &desc_data_offset,
					  buffer_data_size, mask);
	      n_descs_to_process++;
	    }
	  vhost_user_assemble_packet (desc_table, &desc_idx, b_head,
				      &b_current, &next, &b, &bi_current,
				      cpu, &copy_len, &buffers_used,
				      buffers_required, &desc_data_offset,
				      buffer_data_size, mask);
	}

      n_rx_bytes += b_head->total_length_not_including_first_buffer;
      n_rx_packets++;

      b_head->total_length_not_including_first_buffer -=
	b_head->current_length;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b_head);

      vnet_buffer (b_head)->sw_if_index[VLIB_RX] = vui->sw_if_index;
      vnet_buffer (b_head)->sw_if_index[VLIB_TX] = ~0;
      b_head->error = 0;

      if (current_config_index != ~0)
	{
	  b_head->current_config_index = current_config_index;
	  vnet_buffer (b_head)->feature_arc_index = feature_arc_idx;
	}

    out:
      ASSERT (n_left >= n_descs_to_process);
      n_left -= n_descs_to_process;

      /* advance to next descrptor */
      desc_current = (desc_current + n_descs_to_process) & mask;

      /*
       * Although separating memory copies from virtio ring parsing
       * is beneficial, we can offer to perform the copies from time
       * to time in order to free some space in the ring.
       */
      if (PREDICT_FALSE (copy_len >= VHOST_USER_RX_COPY_THRESHOLD))
	{
	  rv = vhost_user_input_copy_packed (vui, cpu->copy, copy_len,
					     &map_hint);
	  if (PREDICT_FALSE (rv != VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR))
	    vlib_error_count (vm, node->node_index, rv, 1);
	  copy_len = 0;
	}
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  /* Do the memory copies */
  rv = vhost_user_input_copy_packed (vui, cpu->copy, copy_len, &map_hint);
  if (PREDICT_FALSE (rv != VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR))
    vlib_error_count (vm, node->node_index, rv, 1);

  /* Must do the tracing before giving buffers back to driver */
  if (PREDICT_FALSE (n_trace))
    {
      u32 left = n_rx_packets;

      b = cpu->rx_buffers_pdesc;
      while (n_trace && left)
	{
	  if (PREDICT_TRUE
	      (vlib_trace_buffer
	       (vm, node, next_index, b[0], /* follow_chain */ 0)))
	    {
	      vhost_trace_t *t0;
	      t0 = vlib_add_trace (vm, node, b[0], sizeof (t0[0]));
	      vhost_user_rx_trace_packed (t0, vui, qid, txvq, last_used_idx);
	      last_used_idx = (last_used_idx + 1) & mask;
	      n_trace--;
	      vlib_set_trace_count (vm, node, n_trace);
	    }
	  left--;
	  b++;
	}
    }

  /*
   * Give buffers back to driver.
   */
  vhost_user_mark_desc_consumed (vui, txvq, desc_head, n_descs_processed);

  /* interrupt (call) handling */
  if ((txvq->callfd_idx != ~0) &&
      (txvq->avail_event->flags != VRING_EVENT_F_DISABLE))
    {
      txvq->n_since_last_int += n_rx_packets;
      if (txvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, vui, txvq);
    }

  /* increase rx counters */
  vlib_increment_combined_counter
    (vnet_main.interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, vm->thread_index, vui->sw_if_index,
     n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (vm->thread_index, n_rx_packets);

  if (PREDICT_FALSE (buffers_used < buffers_required))
    vlib_buffer_free (vm, next, buffers_required - buffers_used);

done:
  return n_rx_packets;
}

VLIB_NODE_FN (vhost_user_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  vhost_user_main_t *vum = &vhost_user_main;
  uword n_rx_packets = 0;
  vhost_user_intf_t *vui;
  vnet_device_input_runtime_t *rt =
    (vnet_device_input_runtime_t *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  vec_foreach (dq, rt->devices_and_queues)
  {
    if ((node->state == VLIB_NODE_STATE_POLLING) ||
	clib_atomic_swap_acq_n (&dq->interrupt_pending, 0))
      {
	vui =
	  pool_elt_at_index (vum->vhost_user_interfaces, dq->dev_instance);
	if (vhost_user_is_packed_ring_supported (vui))
	  {
	    if (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_CSUM))
	      n_rx_packets += vhost_user_if_input_packed (vm, vum, vui,
							  dq->queue_id, node,
							  dq->mode, 1);
	    else
	      n_rx_packets += vhost_user_if_input_packed (vm, vum, vui,
							  dq->queue_id, node,
							  dq->mode, 0);
	  }
	else
	  {
	    if (vui->features & VIRTIO_FEATURE (VIRTIO_NET_F_CSUM))
	      n_rx_packets += vhost_user_if_input (vm, vum, vui, dq->queue_id,
						   node, dq->mode, 1);
	    else
	      n_rx_packets += vhost_user_if_input (vm, vum, vui, dq->queue_id,
						   node, dq->mode, 0);
	  }
      }
  }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vhost_user_input_node) = {
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "vhost-user-input",
  .sibling_of = "device-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_vhost_trace,

  .n_errors = VHOST_USER_INPUT_FUNC_N_ERROR,
  .error_strings = vhost_user_input_func_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
