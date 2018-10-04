/*
 * tmc_node.c - Node implementing TCP MSS clamping
 *
 * Copyright (c) 2018 Cisco and/or its affiliates
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
#include <vppinfra/error.h>
#include <tmc/tmc.h>
#include <vnet/fib/fib_types.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

extern vlib_node_registration_t tmc_ip4_node;
extern vlib_node_registration_t tmc_ip6_node;

typedef struct tmc_trace_t_
{
  u32 mss;
  u32 clamped;
} tmc_trace_t;

/* packet trace format function */
static u8 *
format_tmc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tmc_trace_t *t = va_arg (*args, tmc_trace_t *);

  s = format (s, "mss: %d clamped:%d\n", t->mss, t->clamped);
  return s;
}

#define foreach_tmc_error \
_(CLAMPED, "clamped")

typedef enum
{
#define _(sym,str) TMC_ERROR_##sym,
  foreach_tmc_error
#undef _
    TMC_N_ERROR,
} tmc_error_t;

static char *tmc_error_strings[] = {
#define _(sym,string) string,
  foreach_tmc_error
#undef _
};

typedef enum
{
  TMC_NEXT_DROP,
  TMC_N_NEXT,
} tmc_next_t;

/*
 * fixup the window size if it's a syn packet
 * return !0 if the window was changed
 */
always_inline tcp_header_t *
tmc_window_fixup (vlib_buffer_t * b0, void *ip0,
		  u32 sw_if_index0, u16 offset0)
{
  tcp_header_t *tcp0;

  tcp0 = ip0 + offset0;

  if (PREDICT_FALSE (tcp_syn (tcp0)))
    {
      u8 opt_len, opts_len, kind;
      const u8 *data;

      opts_len = (tcp_doff (tcp0) << 2) - sizeof (tcp_header_t);
      data = (const u8 *) (tcp0 + 1);

      for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
	{
	  kind = data[0];

	  /* Get options length */
	  if (kind == TCP_OPTION_EOL)
	    break;
	  else if (kind == TCP_OPTION_NOOP)
	    {
	      opt_len = 1;
	      continue;
	    }
	  else
	    {
	      /* broken options */
	      if (opts_len < 2)
		return NULL;
	      opt_len = data[1];

	      /* weird option length */
	      if (opt_len < 2 || opt_len > opts_len)
		return NULL;
	    }

	  /* Parse options */
	  switch (kind)
	    {
	    case TCP_OPTION_MSS:
	      if (opt_len == TCP_OPTION_LEN_MSS)
		{
		  *((u16 *) (data + 2)) = tmc_db[sw_if_index0];
		  return (tcp0);
		}
	      break;
	    default:
	      break;
	    }
	}
    }

  return NULL;
}

always_inline uword
tmc_inline (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * frame, fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next;
  tmc_next_t next_index;
  u32 pkts_clamped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

/*       while (n_left_from >= 4 && n_left_to_next >= 2) */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0, next0 = TMC_NEXT_DROP;
	  tcp_header_t *tcp0;
	  vlib_buffer_t *b0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  tcp0 = NULL;

	  vnet_feature_next (&next0, b0);

	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      ip4_header_t *ip0;

	      ip0 = (vlib_buffer_get_current (b0) +
		     vnet_buffer (b0)->ip.save_rewrite_length);

	      if (PREDICT_FALSE (IP_PROTOCOL_TCP == ip0->protocol))
		{
		  tcp0 = tmc_window_fixup (b0, ip0, sw_if_index0,
					   sizeof (ip4_header_t));
		  if (tcp0)
		    {
		      tcp0->checksum = 0;
		      tcp0->checksum =
			ip4_tcp_udp_compute_checksum (vm, b0, ip0);
		    }
		}
	    }
	  else if (FIB_PROTOCOL_IP6 == fproto)
	    {
	      ip6_header_t *ip0;

	      ip0 = (vlib_buffer_get_current (b0) +
		     vnet_buffer (b0)->ip.save_rewrite_length);

	      if (PREDICT_FALSE (IP_PROTOCOL_TCP == ip0->protocol))
		{
		  tcp0 = tmc_window_fixup (b0, ip0,
					   sw_if_index0,
					   sizeof (ip6_header_t));
		  if (tcp0)
		    {
		      int bogus = ~0;

		      tcp0->checksum = 0;
		      tcp0->checksum =
			ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0,
							   &bogus);
		    }
		}
	    }

	  pkts_clamped += (tcp0 != NULL);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      tmc_trace_t *t;

	      t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->mss = tmc_db[sw_if_index0];
	      t->clamped = (tcp0 != NULL);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (FIB_PROTOCOL_IP4 == fproto)
    vlib_node_increment_counter (vm, tmc_ip4_node.index,
				 TMC_ERROR_CLAMPED, pkts_clamped);
  else
    vlib_node_increment_counter (vm, tmc_ip6_node.index,
				 TMC_ERROR_CLAMPED, pkts_clamped);

  return frame->n_vectors;
}

static uword
tmc_ip4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (tmc_inline (vm, node, frame, FIB_PROTOCOL_IP4));
}

static uword
tmc_ip6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (tmc_inline (vm, node, frame, FIB_PROTOCOL_IP6));
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tmc_ip4_node) =
{
  .function = tmc_ip4,
  .name = "tcp-mss-clamping-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_tmc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(tmc_error_strings),
  .error_strings = tmc_error_strings,

  .n_next_nodes = TMC_N_NEXT,
  .next_nodes = {
        [TMC_NEXT_DROP] = "error-drop",
  },
};
VLIB_REGISTER_NODE (tmc_ip6_node) =
{
  .function = tmc_ip6,
  .name = "tcp-mss-clamping-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_tmc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(tmc_error_strings),
  .error_strings = tmc_error_strings,

  .n_next_nodes = TMC_N_NEXT,
  .next_nodes = {
        [TMC_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (tmc_ip4_feat, static) =
{
  .arc_name = "ip4-output",
  .node_name = "tcp-mss-clamping-ip4",
};
VNET_FEATURE_INIT (tmc_ip6_feat, static) =
{
  .arc_name = "ip6-output",
  .node_name = "tcp-mss-clamping-ip6",
};
/* *INDENT-ON */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
