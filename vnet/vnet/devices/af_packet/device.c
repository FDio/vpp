/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#define foreach_af_packet_tx_func_error	       \
_(FRAME_NOT_READY, "tx frame not ready")

typedef enum {
#define _(f,s) AF_PACKET_TX_ERROR_##f,
  foreach_af_packet_tx_func_error
#undef _
  AF_PACKET_TX_N_ERROR,
} af_packet_tx_func_error_t;

static char * af_packet_tx_func_error_strings[] = {
#define _(n,s) s,
    foreach_af_packet_tx_func_error
#undef _
};


static u8 * format_af_packet_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  af_packet_main_t * apm = &af_packet_main;
  af_packet_if_t * apif = vec_elt_at_index (apm->interfaces, i);

  s = format (s, "host-%s", apif->host_if_name);
  return s;
}

static u8 * format_af_packet_device (u8 * s, va_list * args)
{
  s = format (s, "Linux PACKET socket interface");
  return s;
}

static u8 * format_af_packet_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static uword
af_packet_interface_tx (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  af_packet_main_t * apm = &af_packet_main;
  u32 * buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_sent = 0;
  vnet_interface_output_runtime_t * rd = (void *) node->runtime_data;
  af_packet_if_t * apif = vec_elt_at_index (apm->interfaces, rd->dev_instance);
  int block = 0;
  u32 block_size = apif->tx_req->tp_block_size;
  u32 frame_size = apif->tx_req->tp_frame_size;
  u32 frame_num = apif->tx_req->tp_frame_nr;
  u8 * block_start = apif->tx_ring + block * block_size;
  u32 tx_frame = apif->next_tx_frame;
  struct tpacket2_hdr * tph;
  u32 frame_not_ready = 0;

  while(n_left > 0)
    {
      u32 len;
      u32 offset = 0;
      vlib_buffer_t * b0;
      n_left--;
      u32 bi = buffers[0];
      buffers++;

      tph = (struct tpacket2_hdr *) (block_start + tx_frame * frame_size);

      if(tph->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING))
	{
	  frame_not_ready++;
	  goto next;
	}

      do
	{
	  b0 = vlib_get_buffer (vm, bi);
	  len = b0->current_length;
	  memcpy((u8 *) tph + TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + offset,
		 vlib_buffer_get_current(b0), len);
	  offset += len;
	}
      while ((bi = b0->next_buffer));

      tph->tp_len = tph->tp_snaplen = offset;
      tph->tp_status = TP_STATUS_SEND_REQUEST;
      n_sent++;
next:
      tx_frame = (tx_frame + 1) % frame_num;
    }

  CLIB_MEMORY_BARRIER();

  if (n_sent)
    {
      apif->next_tx_frame = tx_frame;
      if (sendto(apif->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) == -1)
	clib_unix_error("tx sendto failure");
    }

  if (frame_not_ready)
    vlib_error_count (vm, node->node_index, AF_PACKET_TX_ERROR_FRAME_NOT_READY,
		      frame_not_ready);

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static void
af_packet_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index,
				  u32 node_index)
{
  af_packet_main_t * apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t * apif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      apif->per_interface_next_index = node_index;
      return;
    }

  apif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main(), af_packet_input_node.index, node_index);
}

static void af_packet_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
af_packet_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  af_packet_main_t * apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t * apif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  apif->is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  return 0;
}

static clib_error_t *
af_packet_subif_add_del_function (vnet_main_t * vnm,
				 u32 hw_if_index,
				 struct vnet_sw_interface_t * st,
				 int is_add)
{
  /* Nothing for now */
  return 0;
}

VNET_DEVICE_CLASS (af_packet_device_class) = {
  .name = "af-packet",
  .tx_function = af_packet_interface_tx,
  .format_device_name = format_af_packet_device_name,
  .format_device = format_af_packet_device,
  .format_tx_trace = format_af_packet_tx_trace,
  .tx_function_n_errors = AF_PACKET_TX_N_ERROR,
  .tx_function_error_strings = af_packet_tx_func_error_strings,
  .rx_redirect_to_node = af_packet_set_interface_next_node,
  .clear_counters = af_packet_clear_hw_interface_counters,
  .admin_up_down_function = af_packet_interface_admin_up_down,
  .subif_add_del_function = af_packet_subif_add_del_function,
  .no_flatten_output_chains = 1,
};