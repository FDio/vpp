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
} wg_output_tun_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_wg_output_tun_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "wg_output \n");
  return s;
}

#endif /* CLIB_MARCH_VARIANT */


typedef enum
{
  WG_OUTPUT_TUN_NEXT_ERROR,
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
      noise_keypair_t *keypair;

      ip4_header_t *iph_out = vlib_buffer_get_current (b[0]);
      u8 *plain_data = vlib_buffer_get_current (b[0]) + sizeof (ip4_header_t);
      u16 plain_data_len =
	clib_net_to_host_u16 (((ip4_header_t *) plain_data)->length);

      u32 sw_if_index_buf = vnet_buffer (b[0])->sw_if_index[VLIB_TX];

      wg_peer_t *peer_iter;
      pool_foreach (peer_iter, wmp->peers, (
					     {
					     if (peer_iter->tun_sw_if_index ==
						 sw_if_index_buf)
					     {
					     peer = peer_iter; break;}
					     }
		    ));
      vnet_feature_next_u16 (&next[0], b[0]);

      if (!peer || peer->is_dead)
	{
	  next[0] = WG_OUTPUT_TUN_NEXT_ERROR;
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_PEER];
	  goto out;
	}

      keypair = peer->keypairs.current_keypair;
      if (!keypair)
	{
	  wg_send_handshake (vm, peer, false);
	  next[0] = WG_OUTPUT_TUN_NEXT_ERROR;
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_KEYPAIR];
	  goto out;
	}

      wg_send_keep_key_fresh (vm, peer);

      size_t encrypted_packet_len = message_data_len (plain_data_len);
      message_data_t *encrypted_packet =
	clib_mem_alloc (encrypted_packet_len);

      u64 nonce = peer->keypairs.current_keypair->sending.counter.counter;
      wg_encrypt_message (encrypted_packet, plain_data, plain_data_len,
			  peer->keypairs.current_keypair, nonce);

      clib_memcpy (plain_data + sizeof (udp_header_t),
		   (u8 *) encrypted_packet, encrypted_packet_len);
      clib_mem_free (encrypted_packet);

      udp_header_t *udp0 =
	vlib_buffer_get_current (b[0]) + sizeof (ip4_header_t);

      u16 port_src = wmp->port_src;
      u16 port_dst = peer->port;
      iph_out->protocol = IP_PROTOCOL_UDP;
      udp0->src_port = clib_host_to_net_u16 (port_src);
      udp0->dst_port = clib_host_to_net_u16 (port_dst);
      udp0->length =
	clib_host_to_net_u16 (encrypted_packet_len + sizeof (udp_header_t));
      udp0->checksum = 0;
      b[0]->current_length =
	encrypted_packet_len + sizeof (ip4_header_t) + sizeof (udp_header_t);
      iph_out->length = clib_host_to_net_u16 (b[0]->current_length);
      iph_out->checksum = ip4_header_checksum (iph_out);

      wg_timers_any_authenticated_packet_traversal (peer);
      wg_timers_any_authenticated_packet_sent (peer);
      wg_timers_data_sent (peer);

      peer->keypairs.current_keypair->sending.counter.counter++;
    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_output_tun_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
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
