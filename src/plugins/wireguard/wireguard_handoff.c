/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_peer.h>

#define foreach_wg_handoff_error  \
_(CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym,str) WG_HANDOFF_ERROR_##sym,
  foreach_wg_handoff_error
#undef _
    HANDOFF_N_ERROR,
} ipsec_handoff_error_t;

static char *wg_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_wg_handoff_error
#undef _
};

typedef enum
{
  WG_HANDOFF_HANDSHAKE,
  WG_HANDOFF_INP_DATA,
  WG_HANDOFF_OUT_TUN,
} wg_handoff_mode_t;

typedef struct wg_handoff_trace_t_
{
  u32 next_worker_index;
  index_t peer;
} wg_handoff_trace_t;

static u8 *
format_wg_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  wg_handoff_trace_t *t = va_arg (*args, wg_handoff_trace_t *);

  s = format (s, "next-worker %d peer %d", t->next_worker_index, t->peer);

  return s;
}

static_always_inline uword
wg_handoff (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * frame, u32 fq_index, wg_handoff_mode_t mode)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  wg_main_t *wmp;

  wmp = &wg_main;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      const wg_peer_t *peer;
      index_t peeri = INDEX_INVALID;

      if (PREDICT_FALSE (mode == WG_HANDOFF_HANDSHAKE))
	{
	  ti[0] = 0;
	}
      else if (mode == WG_HANDOFF_INP_DATA)
	{
	  message_data_t *data = vlib_buffer_get_current (b[0]);
	  u32 *entry =
	    wg_index_table_lookup (&wmp->index_table, data->receiver_index);
	  peeri = *entry;
	  peer = wg_peer_get (peeri);

	  ti[0] = peer->input_thread_index;
	}
      else
	{
	  peeri = wg_peer_get_by_adj_index (vnet_buffer (b[0])->ip.adj_index);
	  peer = wg_peer_get (peeri);
	  ti[0] = peer->output_thread_index;
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  wg_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	  t->peer = peeri;
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 WG_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}

VLIB_NODE_FN (wg_handshake_handoff) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  wg_main_t *wmp = &wg_main;

  return wg_handoff (vm, node, from_frame, wmp->in_fq_index,
		     WG_HANDOFF_HANDSHAKE);
}

VLIB_NODE_FN (wg_input_data_handoff) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  wg_main_t *wmp = &wg_main;

  return wg_handoff (vm, node, from_frame, wmp->in_fq_index,
		     WG_HANDOFF_INP_DATA);
}

VLIB_NODE_FN (wg_output_tun_handoff) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  wg_main_t *wmp = &wg_main;

  return wg_handoff (vm, node, from_frame, wmp->out_fq_index,
		     WG_HANDOFF_OUT_TUN);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg_handshake_handoff) =
{
  .name = "wg-handshake-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_handoff_error_strings),
  .error_strings = wg_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (wg_input_data_handoff) =
{
  .name = "wg-input-data-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_handoff_error_strings),
  .error_strings = wg_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (wg_output_tun_handoff) =
{
  .name = "wg-output-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_wg_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (wg_handoff_error_strings),
  .error_strings = wg_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes =  {
    [0] = "error-drop",
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
