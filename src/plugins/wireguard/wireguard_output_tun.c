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

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_send.h>

#define foreach_wg_output_error                                         \
 _(NONE, "No error")							\
 _(PEER, "Peer error")                                                  \
 _(KEYPAIR, "Keypair error")                                            \
 _(HANDSHAKE_SEND, "Handshake sending failed")                          \
 _(TOO_BIG, "packet too big")                                           \

#define WG_OUTPUT_SCRATCH_SIZE 2048

typedef struct wg_output_scratch_t_
{
  u8 scratch[WG_OUTPUT_SCRATCH_SIZE];
} wg_output_scratch_t;

/* Cache line aligned per-thread scratch space */
static wg_output_scratch_t *wg_output_scratchs;

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

typedef enum
{
  WG_OUTPUT_NEXT_ERROR,
  WG_OUTPUT_NEXT_INTERFACE_OUTPUT,
  WG_OUTPUT_N_NEXT,
} wg_output_next_t;

typedef struct
{
  ip4_udp_header_t hdr;
} wg_output_tun_trace_t;

u8 *
format_ip4_udp_header (u8 * s, va_list * args)
{
  ip4_udp_header_t *hdr = va_arg (*args, ip4_udp_header_t *);

  s = format (s, "%U:$U",
	      format_ip4_header, &hdr->ip4, format_udp_header, &hdr->udp);

  return (s);
}

/* packet trace format function */
static u8 *
format_wg_output_tun_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  wg_output_tun_trace_t *t = va_arg (*args, wg_output_tun_trace_t *);

  s = format (s, "Encrypted packet: %U\n", format_ip4_udp_header, &t->hdr);
  return s;
}

VLIB_NODE_FN (wg_output_tun_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  u32 n_left_from;
  u32 *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  wg_main_t *wmp = &wg_main;
  u32 handsh_fails = 0;
  wg_peer_t *peer = NULL;

  while (n_left_from > 0)
    {
      ip4_udp_header_t *hdr = vlib_buffer_get_current (b[0]);
      u8 *plain_data = (vlib_buffer_get_current (b[0]) +
			sizeof (ip4_udp_header_t));
      u16 plain_data_len =
	clib_net_to_host_u16 (((ip4_header_t *) plain_data)->length);

      next[0] = WG_OUTPUT_NEXT_ERROR;

      peer =
	wg_peer_get_by_adj_index (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);

      if (!peer || peer->is_dead)
	{
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_PEER];
	  goto out;
	}

      if (PREDICT_FALSE (!peer->remote.r_current))
	{
	  if (PREDICT_FALSE (!wg_send_handshake (vm, peer, false)))
	    handsh_fails++;
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_KEYPAIR];
	  goto out;
	}

      size_t encrypted_packet_len = message_data_len (plain_data_len);

      /*
       * Ensure there is enough space to write the encrypted data
       * into the packet
       */
      if (PREDICT_FALSE (encrypted_packet_len >= WG_OUTPUT_SCRATCH_SIZE) ||
	  PREDICT_FALSE ((b[0]->current_data + encrypted_packet_len) >=
			 vlib_buffer_get_default_data_size (vm)))
	{
	  b[0]->error = node->errors[WG_OUTPUT_ERROR_TOO_BIG];
	  goto out;
	}

      message_data_t *encrypted_packet =
	(message_data_t *) wg_output_scratchs[thread_index].scratch;

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
	  if (PREDICT_FALSE (!wg_send_handshake (vm, peer, false)))
	    handsh_fails++;
	  break;
	case SC_FAILED:
	  //TODO: Maybe wrong
	  if (PREDICT_FALSE (!wg_send_handshake (vm, peer, false)))
	    handsh_fails++;
	  clib_mem_free (encrypted_packet);
	  goto out;
	default:
	  break;
	}

      // Here we are sure that can send packet to next node.
      next[0] = WG_OUTPUT_NEXT_INTERFACE_OUTPUT;
      encrypted_packet->header.type = MESSAGE_DATA;

      clib_memcpy (plain_data, (u8 *) encrypted_packet, encrypted_packet_len);

      hdr->udp.length = clib_host_to_net_u16 (encrypted_packet_len +
					      sizeof (udp_header_t));
      b[0]->current_length = (encrypted_packet_len +
			      sizeof (ip4_header_t) + sizeof (udp_header_t));
      ip4_header_set_len_w_chksum
	(&hdr->ip4, clib_host_to_net_u16 (b[0]->current_length));

      wg_timers_any_authenticated_packet_traversal (peer);
      wg_timers_any_authenticated_packet_sent (peer);
      wg_timers_data_sent (peer);

    out:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  wg_output_tun_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->hdr = *hdr;
	}
      n_left_from -= 1;
      next += 1;
      b += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       WG_OUTPUT_ERROR_HANDSHAKE_SEND, handsh_fails);

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
  .n_next_nodes = WG_OUTPUT_N_NEXT,
  .next_nodes = {
        [WG_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [WG_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */

static clib_error_t *
wireguard_output_module_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (wg_output_scratchs, tm->n_vlib_mains,
			CLIB_CACHE_LINE_BYTES);
  return (NULL);
}

VLIB_INIT_FUNCTION (wireguard_output_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
