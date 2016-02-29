/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

#include <linux/if_packet.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/af_packet/af_packet.h>

#define foreach_af_packet_input_error      \
  _(NO_BUFFS, "no buffers")

typedef enum {
#define _(f,s) AF_PACKET_INPUT_ERROR_##f,
  foreach_af_packet_input_error
#undef _
  AF_PACKET_INPUT_N_ERROR,
} af_packet_input_error_t;

static char * af_packet_input_error_strings[] = {
#define _(n,s) s,
    foreach_af_packet_input_error
#undef _
};

enum {
  AF_PACKET_INPUT_NEXT_DROP,
  AF_PACKET_INPUT_NEXT_ETHERNET_INPUT,
  AF_PACKET_INPUT_N_NEXT,
};

typedef struct {
  u32 next_index;
  u32 hw_if_index;
  int block;
  struct tpacket_block_desc tbd;
  struct tpacket3_hdr th;
} af_packet_input_trace_t;

static u8 * format_af_packet_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  af_packet_input_trace_t * t = va_arg (*args, af_packet_input_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s, "af_packet: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);

  s = format (s, "\n%Ublock_desc:\n%Ublock %u version %u offset_to_priv %u",
	      format_white_space, indent + 2,
	      format_white_space, indent + 4,
	      t->block,
	      t->tbd.version,
	      t->tbd.offset_to_priv);
  s = format (s, "\n%Ubd_hdr:\n%Ustatus 0x%x num_pkts %u off_to_first_pkt %u "
	      "blk_len %u seq_num %u",
	      format_white_space, indent + 2,
	      format_white_space, indent + 4,
	      t->tbd.hdr.bh1.block_status,
	      t->tbd.hdr.bh1.num_pkts,
	      t->tbd.hdr.bh1.offset_to_first_pkt,
	      t->tbd.hdr.bh1.blk_len,
	      t->tbd.hdr.bh1.seq_num);
  s = format (s, "\n%Utpacket3_hdr:\n%Unext_off %u sec %u nsec %u snaplen %u "
	      "len %u\n%Ustatus 0x%x mac %u net %u",
	      format_white_space, indent + 2,
	      format_white_space, indent + 4,
	      t->th.tp_next_offset,
	      t->th.tp_sec,
	      t->th.tp_nsec,
	      t->th.tp_snaplen,
	      t->th.tp_len,
	      format_white_space, indent + 4,
	      t->th.tp_status,
	      t->th.tp_mac,
	      t->th.tp_net);
  s = format (s, "\n%Utpacket3_hdr_variant1:\n%Urx_hash 0x%x vlan_tcid %u "
	      "vlan_tpid %u padding %u",
	      format_white_space, indent + 2,
	      format_white_space, indent + 4,
	      t->th.hv1.tp_rxhash,
	      t->th.hv1.tp_vlan_tci,
	      t->th.hv1.tp_vlan_tpid,
	      t->th.hv1.tp_padding);

  return s;
}

always_inline uword
af_packet_device_input_fn  (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, u32 device_idx)
{
  af_packet_main_t * apm = &af_packet_main;
  af_packet_if_t * apif = vec_elt_at_index(apm->interfaces, device_idx);
  int block, next_block;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 * to_next = 0;
  u32 next_index = AF_PACKET_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  uword n_left;
  uword n_alloc = 0;
  u32 block_nr = apif->rx_req->tp_block_nr;
  u32 block_sz = apif->rx_req->tp_block_size;
  u8 do_next_block = 1;
  u32 count_no_buffs = 0;

  n_left = vec_len (apm->rx_buffers);
  if (PREDICT_FALSE(n_left < VLIB_FRAME_SIZE))
    {
      vec_validate(apm->rx_buffers, VLIB_FRAME_SIZE + n_left - 1);
      n_alloc = vlib_buffer_alloc(vm, &apm->rx_buffers[n_left], VLIB_FRAME_SIZE);
      _vec_len (apm->rx_buffers) = n_left + n_alloc;
    }

  next_block = block = apif->next_rx_block;

  do
    {
      struct tpacket_block_desc * tbd;
      struct tpacket3_hdr *th;
      u32 n_left_from, bi0;
      uword last_empty_buffer;
      vlib_buffer_t * b0;
      u32 next0 = AF_PACKET_INPUT_NEXT_ETHERNET_INPUT;

      tbd = (struct tpacket_block_desc *) (apif->rx_ring + (block * block_sz));

      if (tbd->hdr.bh1.block_status & TP_STATUS_USER)
	{
	  next_block = (block + 1) % block_nr;

	  n_left_from = tbd->hdr.bh1.num_pkts;
	  th = (struct tpacket3_hdr *) ((u8 *) tbd + tbd->hdr.bh1.offset_to_first_pkt);

	  while (n_left_from > 0)
	  {
            if (PREDICT_FALSE(vec_len (apm->rx_buffers) == 0))
	      {
		  count_no_buffs++;
		  n_left_from--;
		  continue;
	      }

	    u32 n_left_to_next;
	    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	    while (n_left_from > 0 && n_left_to_next > 0)
	      {
		/* grab free buffer */
		last_empty_buffer = vec_len (apm->rx_buffers) - 1;
		bi0 = apm->rx_buffers[last_empty_buffer];
		b0 = vlib_get_buffer (vm, bi0);
		_vec_len (apm->rx_buffers) = last_empty_buffer;
		to_next[0] = bi0;
		to_next += 1;
		n_left_from--;
		n_left_to_next--;
		n_rx_packets++;

		/* fill buffer header */
		b0->current_data = 0;
		b0->clone_count = 0;
		b0->current_length = th->tp_snaplen;
		b0->total_length_not_including_first_buffer = 0;
		b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		vnet_buffer(b0)->sw_if_index[VLIB_RX] = apif->sw_if_index;
		vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0;

		/* copy data */
		memcpy (b0->data, (u8 *) th + th->tp_mac, th->tp_snaplen);
		n_rx_bytes += th->tp_snaplen;

		/* trace */
		VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);
		if (PREDICT_FALSE(n_trace > 0))
		  {
		    af_packet_input_trace_t *tr;
		    vlib_trace_buffer (vm, node, next0,b0, /* follow_chain */ 1);
		    vlib_set_trace_count (vm, node, --n_trace);
		    tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
		    tr->next_index = next0;
		    tr->hw_if_index = apif->hw_if_index;
		    memcpy(&tr->tbd, tbd, sizeof(struct tpacket_block_desc));
		    memcpy(&tr->th, th, sizeof(struct tpacket3_hdr));
		  }
		/* enque and take next packet */
		vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
						 n_left_to_next, bi0, next0);
						 /* next packet */
		th = (struct tpacket3_hdr *) ((u8 *) th + th->tp_next_offset);
	      }
	    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	  }

	  CLIB_MEMORY_BARRIER();
	  tbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
	}
      else
	{
	  /* this block is not ready and
	     we already received some packets */
	  if (n_rx_packets)
	    do_next_block = 0;
	}

      block = (block + 1) % block_nr;
      /* protect us form infinite loop */
      if (block == apif->next_rx_block)
	do_next_block = 0;
    }
  while (do_next_block);

  apif->next_rx_block = next_block;

  if (count_no_buffs)
    vlib_error_count (vm, node->node_index, AF_PACKET_INPUT_ERROR_NO_BUFFS,
		      count_no_buffs);

  vlib_increment_combined_counter
    (vnet_get_main()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     os_get_cpu_number(),
     apif->hw_if_index,
     n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

static uword
af_packet_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  int i;
  u32 n_rx_packets = 0;

  af_packet_main_t * apm = &af_packet_main;

  clib_bitmap_foreach (i, apm->pending_input_bitmap,
    ({
      clib_bitmap_set (apm->pending_input_bitmap, i, 1);
      n_rx_packets += af_packet_device_input_fn(vm, node, frame, i);
    }));

  return n_rx_packets;
}


VLIB_REGISTER_NODE (af_packet_input_node) = {
  .function = af_packet_input_fn,
  .name = "af-packet-input",
  .format_trace = format_af_packet_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = AF_PACKET_INPUT_N_ERROR,
  .error_strings = af_packet_input_error_strings,

  .n_next_nodes = AF_PACKET_INPUT_N_NEXT,
  .next_nodes = {
    [AF_PACKET_INPUT_NEXT_DROP] = "error-drop",
    [AF_PACKET_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
  },
};

