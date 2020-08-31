/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vppinfra/error.h>

#include <wg/wg.h>
#include <wg/wg_send.h>

#define foreach_wg_output_error                                     \
_(NONE, "No error")							\
_(PEER, "Peer error")                     \
_(KEYPAIR, "Keypair error")

typedef enum
{
#define _(sym,str) WG_OUTPUT_ERROR_##sym,
  foreach_wg_output_error
#undef _
    WG_OUTPUT_N_ERROR,
} wg_output_error_t;

static char *wg_output_error_strings[] = {
#define _(sym,string) string,
  foreach_wg_output_error
#undef _
};

typedef struct
{
  ip4_address_t src;
  ip4_address_t dst;
  u16 port_src;
  u16 port_dst;
} wg_output_tun_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_wg_output_tun_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_output_tun_trace_t *t = va_arg (*args, wg_output_tun_trace_t *);

  s = format (s, "WG tunnel output: \n");
  s = format (s, "  Encrypted packet: %U->%U\n",
	      format_ip4_address, &t->src, format_ip4_address, &t->dst);
  s = format (s, "  Port: %u->%u", t->port_src, t->port_dst);
  return s;
}

#endif /* CLIB_MARCH_VARIANT */


typedef enum
{
  WG_OUTPUT_TUN_NEXT_ERROR,
  WG_OUTPUT_TUN_NEXT_INTERFACE_OUTPUT,
  WG_OUTPUT_TUN_N_NEXT,
} wg_output_next_t;

VLIB_NODE_FN (wg_output_tun_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  u32 n_left_from;
  u32 *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;

  while (n_left_from > 0)
    {
      u16 port_src = 0;
      u16 port_dst = 0;

      ip4_header_t *iph_out = vlib_buffer_get_current (b[0]);
      u8 *plain_data = vlib_buffer_get_current (b[0]) + sizeof (ip4_header_t);
      u16 plain_data_len =
	clib_net_to_host_u16 (((ip4_header_t *) plain_data)->length);

      u32 sw_if_index_buf = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      next[0] = WG_OUTPUT_TUN_NEXT_ERROR;

      wg_peer_t *peer_iter;
      /* *INDENT-OFF* */
      pool_foreach (peer_iter, wmp->peers,
      ({
        if (peer_iter->tun_sw_if_index == sw_if_index_buf)
        {
          peer = peer_iter;
          break;
        }
      }));
      /* *INDENT-ON* */

      if (!peer || peer->is_dead)
	{
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_PEER];
	  goto out;
	}

      if (!peer->remote.r_current)
	{
	  wg_send_handshake (vm, peer, false);
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_KEYPAIR];
	  goto out;
	}

      size_t encrypted_packet_len = message_data_len (plain_data_len);
      message_data_t *encrypted_packet =
	clib_mem_alloc (encrypted_packet_len);

      enum noise_state_crypt state;
      state =
	noise_remote_encrypt (wmp->vlib_main,
			      &peer->remote,
			      &encrypted_packet->receiver_index,
			      &encrypted_packet->counter, plain_data,
			      plain_data_len,
			      encrypted_packet->encrypted_data);
      switch (state)
	{
	case SC_OK:
	  break;
	case SC_KEEP_KEY_FRESH:
	  wg_send_handshake (vm, peer, false);
	  break;
	case SC_FAILED:
	  wg_send_handshake (vm, peer, false);	//TODO: Maybe wrong
	  clib_mem_free (encrypted_packet);
	  goto out;
	default:
	  break;
	}

      // Here we are sure that can send packet to next node.
      next[0] = WG_OUTPUT_TUN_NEXT_INTERFACE_OUTPUT;
      encrypted_packet->header.type = MESSAGE_DATA;

      clib_memcpy (plain_data + sizeof (udp_header_t),
		   (u8 *) encrypted_packet, encrypted_packet_len);
      clib_mem_free (encrypted_packet);

      udp_header_t *udp_out =
	vlib_buffer_get_current (b[0]) + sizeof (ip4_header_t);

      port_src = wmp->port_src;
      port_dst = peer->port;
      iph_out->protocol = IP_PROTOCOL_UDP;
      udp_out->src_port = clib_host_to_net_u16 (port_src);
      udp_out->dst_port = clib_host_to_net_u16 (port_dst);
      udp_out->length =
	clib_host_to_net_u16 (encrypted_packet_len + sizeof (udp_header_t));
      udp_out->checksum = 0;
      b[0]->current_length =
	encrypted_packet_len + sizeof (ip4_header_t) + sizeof (udp_header_t);
      iph_out->length = clib_host_to_net_u16 (b[0]->current_length);
      iph_out->checksum = ip4_header_checksum (iph_out);

      wg_timers_any_authenticated_packet_traversal (peer);
      wg_timers_any_authenticated_packet_sent (peer);
      wg_timers_data_sent (peer);

    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_output_tun_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->src = iph_out->src_address;
	  t->dst = iph_out->dst_address;
	  t->port_src = port_src;
	  t->port_dst = port_dst;
	}
      n_left_from -= 1;
      next += 1;
      b += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg_output_tun_node) =
{
  .name = "wg-output-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_output_tun_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_output_error_strings),
  .error_strings = wg_output_error_strings,
  .n_next_nodes = WG_OUTPUT_TUN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [WG_OUTPUT_TUN_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [WG_OUTPUT_TUN_NEXT_ERROR] = "error-drop",
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
