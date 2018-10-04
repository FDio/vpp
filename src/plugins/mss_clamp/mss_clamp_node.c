/*
 * mss_clamp_node.c - Node implementing TCP MSS clamping
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
#include <mss_clamp/mss_clamp.h>
#include <vnet/fib/fib_types.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

extern vlib_node_registration_t mssc_ip4_in_node, mssc_ip4_out_node;
extern vlib_node_registration_t mssc_ip6_in_node, mssc_ip6_out_node;

typedef struct mssc_trace_t_
{
  u32 max_mss;
  u32 clamped;
} mssc_trace_t;

/* packet trace format function */
static u8 *
format_mssc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mssc_trace_t *t = va_arg (*args, mssc_trace_t *);

  s = format (s, "max mss: %d clamped: %d", t->max_mss, t->clamped);
  return s;
}

#define foreach_mssc_error \
_(CLAMPED, "clamped")

typedef enum
{
#define _(sym,str) MSSC_ERROR_##sym,
  foreach_mssc_error
#undef _
    MSSC_N_ERROR,
} mssc_error_t;

static char *mssc_error_strings[] = {
#define _(sym,string) string,
  foreach_mssc_error
#undef _
};

typedef enum
{
  MSSC_NEXT_DROP,
  MSSC_N_NEXT,
} mssc_next_t;

/*
 * fixup the maximum segment size if it's a syn packet
 * return 1 if the mss was changed otherwise 0
 */
always_inline u32
mssc_mss_fixup (vlib_buffer_t * b0, tcp_header_t * tcp0, u16 max_mss0)
{
  ip_csum_t sum0;

  if (PREDICT_FALSE (tcp_syn (tcp0)))
    {
      u8 opt_len, opts_len, kind;
      const u8 *data;
      u16 mss0, new_mss0;

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
		return 0;
	      opt_len = data[1];

	      /* weird option length */
	      if (opt_len < 2 || opt_len > opts_len)
		return 0;
	    }

	  if (kind == TCP_OPTION_MSS)
	    {
	      mss0 = *(u16 *) (data + 2);
	      if (clib_net_to_host_u16 (mss0) > max_mss0)
		{
		  new_mss0 = clib_host_to_net_u16 (max_mss0);
		  *((u16 *) (data + 2)) = new_mss0;
		  sum0 = tcp0->checksum;
		  sum0 =
		    ip_csum_update (sum0, mss0, new_mss0, tcp_header_t,
				    checksum);
		  tcp0->checksum = ip_csum_fold (sum0);
		  return 1;
		}
	    }
	}
    }

  return 0;
}

always_inline uword
mssc_inline (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * frame, vlib_dir_t dir, fib_protocol_t fproto)
{
  mssc_main_t *cm = &mssc_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;
  u32 pkts_clamped = 0;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      u32 sw_if_index0, sw_if_index1;
      const u8 *h0, *h1;
      u32 clamped0, clamped1;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[2], LOAD);
	vlib_prefetch_buffer_header (b[3], LOAD);
	vlib_prefetch_buffer_data (b[2], LOAD);
	vlib_prefetch_buffer_data (b[3], LOAD);
      }

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[dir];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[dir];
      clamped0 = clamped1 = 0;

      /* speculatively enqueue b0 to the current next frame */
      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);

      h0 = (u8 *) vlib_buffer_get_current (b[0]);
      h1 = (u8 *) vlib_buffer_get_current (b[1]);
      if (VLIB_TX == dir)
	{
	  h0 += vnet_buffer (b[0])->ip.save_rewrite_length;
	  h1 += vnet_buffer (b[1])->ip.save_rewrite_length;
	}

      if (FIB_PROTOCOL_IP4 == fproto)
	{
	  ip4_header_t *ip0 = (ip4_header_t *) h0;
	  ip4_header_t *ip1 = (ip4_header_t *) h1;

	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      clamped0 = mssc_mss_fixup (b[0],
					 ip4_next_header (ip0),
					 cm->max_mss4[sw_if_index0]);
	    }
	  if (IP_PROTOCOL_TCP == ip1->protocol)
	    {
	      clamped1 = mssc_mss_fixup (b[1],
					 ip4_next_header (ip1),
					 cm->max_mss4[sw_if_index1]);
	    }
	}
      else if (FIB_PROTOCOL_IP6 == fproto)
	{
	  ip6_header_t *ip0 = (ip6_header_t *) h0;
	  ip6_header_t *ip1 = (ip6_header_t *) h1;

	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      clamped0 = mssc_mss_fixup (b[0],
					 ip6_next_header (ip0),
					 cm->max_mss6[sw_if_index0]);
	    }
	  if (IP_PROTOCOL_TCP == ip1->protocol)
	    {
	      clamped1 = mssc_mss_fixup (b[1],
					 ip6_next_header (ip1),
					 cm->max_mss6[sw_if_index1]);
	    }
	}

      pkts_clamped += clamped0 + clamped1;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      mssc_trace_t *t;

	      t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->max_mss =
		(FIB_PROTOCOL_IP4 ==
		 fproto) ? cm->
		max_mss4[sw_if_index0] : cm->max_mss6[sw_if_index0];
	      t->clamped = clamped0;
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      mssc_trace_t *t;

	      t = vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->max_mss =
		(FIB_PROTOCOL_IP4 ==
		 fproto) ? cm->
		max_mss4[sw_if_index1] : cm->max_mss6[sw_if_index1];
	      t->clamped = clamped1;
	    }
	}

      b += 2;
      next += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      u32 sw_if_index0;
      const u8 *h0;
      u32 clamped0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[dir];
      clamped0 = 0;

      /* speculatively enqueue b0 to the current next frame */
      vnet_feature_next_u16 (&next[0], b[0]);

      h0 = (u8 *) vlib_buffer_get_current (b[0]);
      if (VLIB_TX == dir)
	h0 += vnet_buffer (b[0])->ip.save_rewrite_length;

      if (FIB_PROTOCOL_IP4 == fproto)
	{
	  ip4_header_t *ip0 = (ip4_header_t *) h0;

	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      clamped0 = mssc_mss_fixup (b[0],
					 ip4_next_header (ip0),
					 cm->max_mss4[sw_if_index0]);
	    }
	}
      else if (FIB_PROTOCOL_IP6 == fproto)
	{
	  ip6_header_t *ip0 = (ip6_header_t *) h0;

	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      clamped0 = mssc_mss_fixup (b[0],
					 ip6_next_header (ip0),
					 cm->max_mss6[sw_if_index0]);
	    }
	}

      pkts_clamped += clamped0;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  mssc_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->max_mss =
	    (FIB_PROTOCOL_IP4 ==
	     fproto) ? cm->
	    max_mss4[sw_if_index0] : cm->max_mss6[sw_if_index0];
	  t->clamped = clamped0;
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (FIB_PROTOCOL_IP4 == fproto)
    {
      if (dir == VLIB_RX)
	vlib_node_increment_counter (vm, mssc_ip4_in_node.index,
				     MSSC_ERROR_CLAMPED, pkts_clamped);
      else
	vlib_node_increment_counter (vm, mssc_ip4_out_node.index,
				     MSSC_ERROR_CLAMPED, pkts_clamped);
    }
  else
    {
      if (dir == VLIB_RX)
	vlib_node_increment_counter (vm, mssc_ip6_in_node.index,
				     MSSC_ERROR_CLAMPED, pkts_clamped);
      else
	vlib_node_increment_counter (vm, mssc_ip6_out_node.index,
				     MSSC_ERROR_CLAMPED, pkts_clamped);
    }

  return frame->n_vectors;
}

static uword
mssc_ip4_in (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * frame)
{
  return (mssc_inline (vm, node, frame, VLIB_RX, FIB_PROTOCOL_IP4));
}

static uword
mssc_ip4_out (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return (mssc_inline (vm, node, frame, VLIB_TX, FIB_PROTOCOL_IP4));
}

static uword
mssc_ip6_in (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * frame)
{
  return (mssc_inline (vm, node, frame, VLIB_RX, FIB_PROTOCOL_IP6));
}

static uword
mssc_ip6_out (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return (mssc_inline (vm, node, frame, VLIB_TX, FIB_PROTOCOL_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mssc_ip4_in_node) =
{
  .function = mssc_ip4_in,
  .name = "tcp-mss-clamping-ip4-in",
  .vector_size = sizeof (u32),
  .format_trace = format_mssc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mssc_error_strings),
  .error_strings = mssc_error_strings,

  .n_next_nodes = MSSC_N_NEXT,
  .next_nodes = {
        [MSSC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (mssc_ip4_out_node) =
{
  .function = mssc_ip4_out,
  .name = "tcp-mss-clamping-ip4-out",
  .vector_size = sizeof (u32),
  .format_trace = format_mssc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mssc_error_strings),
  .error_strings = mssc_error_strings,

  .n_next_nodes = MSSC_N_NEXT,
  .next_nodes = {
        [MSSC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (mssc_ip6_in_node) =
{
  .function = mssc_ip6_in,
  .name = "tcp-mss-clamping-ip6-in",
  .vector_size = sizeof (u32),
  .format_trace = format_mssc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mssc_error_strings),
  .error_strings = mssc_error_strings,

  .n_next_nodes = MSSC_N_NEXT,
  .next_nodes = {
        [MSSC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (mssc_ip6_out_node) =
{
  .function = mssc_ip6_out,
  .name = "tcp-mss-clamping-ip6-out",
  .vector_size = sizeof (u32),
  .format_trace = format_mssc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mssc_error_strings),
  .error_strings = mssc_error_strings,

  .n_next_nodes = MSSC_N_NEXT,
  .next_nodes = {
        [MSSC_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (mssc_ip4_in_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "tcp-mss-clamping-ip4-in",
  .runs_after = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (mssc_ip4_out_feat, static) =
{
  .arc_name = "ip4-output",
  .node_name = "tcp-mss-clamping-ip4-out",
};

VNET_FEATURE_INIT (mssc_ip6_in_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "tcp-mss-clamping-ip6-in",
  .runs_after = VNET_FEATURES ("ip6-policer-classify"),
};

VNET_FEATURE_INIT (mssc_ip6_out_feat, static) =
{
  .arc_name = "ip6-output",
  .node_name = "tcp-mss-clamping-ip6-out",
};
/* *INDENT-ON */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
