/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_learn.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <vlibmemory/api.h>

#include <vnet/util/throttle.h>
#include <vnet/l2/l2_input.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_learn_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 gl_l2_input_feat_next[32];

  /**
   * logger - VLIB log class
   */
  vlib_log_class_t gl_logger;

  /**
   * throttles for the DP leanring
   */
  throttle_t gl_l2_throttle;
  throttle_t gl_l3_throttle;
} gbp_learn_main_t;

/**
 * The maximum learning rate per-hashed EP
 */
#define GBP_ENDPOINT_HASH_LEARN_RATE (1e-2)

static gbp_learn_main_t gbp_learn_main;

#define GBP_LEARN_DBG(...)                                      \
    vlib_log_debug (gbp_learn_main.gl_logger, __VA_ARGS__);

#define foreach_gbp_learn                      \
  _(DROP,    "drop")

typedef enum
{
#define _(sym,str) GBP_LEARN_ERROR_##sym,
  foreach_gbp_learn
#undef _
    GBP_LEARN_N_ERROR,
} gbp_learn_error_t;

static char *gbp_learn_error_strings[] = {
#define _(sym,string) string,
  foreach_gbp_learn
#undef _
};

typedef enum
{
#define _(sym,str) GBP_LEARN_NEXT_##sym,
  foreach_gbp_learn
#undef _
    GBP_LEARN_N_NEXT,
} gbp_learn_next_t;

typedef struct gbp_learn_l2_t_
{
  ip46_address_t ip;
  mac_address_t mac;
  u32 sw_if_index;
  u32 bd_index;
  epg_id_t epg;
  ip46_address_t outer_src;
  ip46_address_t outer_dst;
} gbp_learn_l2_t;


static void
gbp_learn_l2_cp (const gbp_learn_l2_t * gl2)
{
  ip46_address_t *ips = NULL;

  GBP_LEARN_DBG ("L2 EP: %U %U, %d",
		 format_mac_address_t, &gl2->mac,
		 format_ip46_address, &gl2->ip, IP46_TYPE_ANY, gl2->epg);

  vec_add1 (ips, gl2->ip);

  ASSERT (!ip46_address_is_zero (&gl2->outer_src));
  ASSERT (!ip46_address_is_zero (&gl2->outer_dst));

  /*
   * flip the source and dst, since that's how it was received, this API
   * takes how it's sent
   */
  gbp_endpoint_update (gl2->sw_if_index, ips,
		       &gl2->mac, gl2->epg,
		       (GBP_ENDPOINT_FLAG_LEARNT |
			GBP_ENDPOINT_FLAG_REMOTE),
		       &gl2->outer_dst, &gl2->outer_src, NULL);
}

static void
gbp_learn_l2_ip4_dp (const u8 * mac, const ip4_address_t * ip,
		     u32 bd_index, u32 sw_if_index, epg_id_t epg,
		     const ip4_address_t * outer_src,
		     const ip4_address_t * outer_dst)
{
  gbp_learn_l2_t gl2 = {
    .sw_if_index = sw_if_index,
    .bd_index = bd_index,
    .epg = epg,
    .ip.ip4 = *ip,
    .outer_src.ip4 = *outer_src,
    .outer_dst.ip4 = *outer_dst,
  };
  mac_address_from_bytes (&gl2.mac, mac);

  ASSERT (!ip46_address_is_zero (&gl2.outer_src));
  ASSERT (!ip46_address_is_zero (&gl2.outer_dst));

  vl_api_rpc_call_main_thread (gbp_learn_l2_cp, (u8 *) & gl2, sizeof (gl2));
}

static void
gbp_learn_l2_ip6_dp (const u8 * mac, const ip6_address_t * ip,
		     u32 bd_index, u32 sw_if_index, epg_id_t epg,
		     const ip4_address_t * outer_src,
		     const ip4_address_t * outer_dst)
{
  gbp_learn_l2_t gl2 = {
    .sw_if_index = sw_if_index,
    .bd_index = bd_index,
    .epg = epg,
    .ip.ip6 = *ip,
    .outer_src.ip4 = *outer_src,
    .outer_dst.ip4 = *outer_dst,
  };
  mac_address_from_bytes (&gl2.mac, mac);

  vl_api_rpc_call_main_thread (gbp_learn_l2_cp, (u8 *) & gl2, sizeof (gl2));
}

static void
gbp_learn_l2_dp (const u8 * mac, u32 bd_index, u32 sw_if_index,
		 epg_id_t epg,
		 const ip4_address_t * outer_src,
		 const ip4_address_t * outer_dst)
{
  gbp_learn_l2_t gl2 = {
    .sw_if_index = sw_if_index,
    .bd_index = bd_index,
    .epg = epg,
    .outer_src.ip4 = *outer_src,
    .outer_dst.ip4 = *outer_dst,
  };
  mac_address_from_bytes (&gl2.mac, mac);

  vl_api_rpc_call_main_thread (gbp_learn_l2_cp, (u8 *) & gl2, sizeof (gl2));
}

/**
 * per-packet trace data
 */
typedef struct gbp_learn_l2_trace_t_
{
  /* per-pkt trace data */
  mac_address_t mac;
  u32 sw_if_index;
  u32 new;
  u32 throttled;
  u32 epg;
  u32 d_bit;
} gbp_learn_l2_trace_t;

always_inline void
gbp_learn_get_outer (const ethernet_header_t * eh0,
		     ip4_address_t * outer_src, ip4_address_t * outer_dst)
{
  ip4_header_t *ip0;
  u8 *buff;

  /* rewind back to the ivxlan header */
  buff = (u8 *) eh0;
  buff -= (sizeof (vxlan_gbp_header_t) +
	   sizeof (udp_header_t) + sizeof (ip4_header_t));

  ip0 = (ip4_header_t *) buff;

  *outer_src = ip0->src_address;
  *outer_dst = ip0->dst_address;
}

static uword
gbp_learn_l2 (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index, seed;
  gbp_learn_main_t *glm;
  f64 time_now;

  glm = &gbp_learn_main;
  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  time_now = vlib_time_now (vm);
  thread_index = vm->thread_index;

  seed = throttle_seed (&glm->gl_l2_throttle, thread_index, time_now);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip4_address_t outer_src, outer_dst;
	  u32 bi0, sw_if_index0, t0, epg0;
	  const ethernet_header_t *eh0;
	  gbp_bridge_domain_t *gb0;
	  gbp_learn_next_t next0;
	  gbp_endpoint_t *ge0;
	  vlib_buffer_t *b0;

	  next0 = GBP_LEARN_NEXT_DROP;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  eh0 = vlib_buffer_get_current (b0);
	  epg0 = vnet_buffer2 (b0)->gbp.src_epg;

	  next0 = vnet_l2_feature_next (b0, glm->gl_l2_input_feat_next,
					L2INPUT_FEAT_GBP_LEARN);

	  ge0 = gbp_endpoint_find_mac (eh0->src_address,
				       vnet_buffer (b0)->l2.bd_index);
	  gb0 =
	    gbp_bridge_domain_get_by_bd_index (vnet_buffer (b0)->l2.bd_index);

	  if ((vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_D) ||
	      (gb0->gb_flags & GBP_BD_FLAG_DO_NOT_LEARN))
	    {
	      t0 = 1;
	      goto trace;
	    }

	  /*
	   * check for new EP or a moved EP
	   */
	  if (NULL == ge0 || ge0->ge_sw_if_index != sw_if_index0)

	    {
	      /*
	       * use the last 4 bytes of the mac address as the hash for the EP
	       */
	      t0 = throttle_check (&glm->gl_l2_throttle, thread_index,
				   *((u32 *) (eh0->src_address + 2)), seed);
	      if (!t0)
		{
		  gbp_learn_get_outer (eh0, &outer_src, &outer_dst);

		  switch (clib_net_to_host_u16 (eh0->type))
		    {
		    case ETHERNET_TYPE_IP4:
		      {
			const ip4_header_t *ip0;

			ip0 = (ip4_header_t *) (eh0 + 1);

			gbp_learn_l2_ip4_dp (eh0->src_address,
					     &ip0->src_address,
					     vnet_buffer (b0)->l2.bd_index,
					     sw_if_index0, epg0,
					     &outer_src, &outer_dst);

			break;
		      }
		    case ETHERNET_TYPE_IP6:
		      {
			const ip6_header_t *ip0;

			ip0 = (ip6_header_t *) (eh0 + 1);

			gbp_learn_l2_ip6_dp (eh0->src_address,
					     &ip0->src_address,
					     vnet_buffer (b0)->l2.bd_index,
					     sw_if_index0, epg0,
					     &outer_src, &outer_dst);

			break;
		      }
		    default:
		      gbp_learn_l2_dp (eh0->src_address,
				       vnet_buffer (b0)->l2.bd_index,
				       sw_if_index0, epg0,
				       &outer_src, &outer_dst);
		      break;
		    }
		}
	    }
	  else
	    {
	      /*
	       * this update could happen simultaneoulsy from multiple workers
	       * but that's ok we are not interested in being very accurate.
	       */
	      t0 = 0;
	      ge0->ge_last_time = time_now;
	    }
	trace:
	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_learn_l2_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      clib_memcpy (t->mac.bytes, eh0->src_address, 6);
	      t->new = (NULL == ge0);
	      t->throttled = t0;
	      t->sw_if_index = sw_if_index0;
	      t->epg = epg0;
	      t->d_bit = ! !(vnet_buffer2 (b0)->gbp.flags &
			     VXLAN_GBP_GPFLAGS_D);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_gbp_learn_l2_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_learn_l2_trace_t *t = va_arg (*args, gbp_learn_l2_trace_t *);

  s = format (s, "new:%d throttled:%d d-bit:%d mac:%U itf:%d epg:%d",
	      t->new, t->throttled, t->d_bit,
	      format_mac_address_t, &t->mac, t->sw_if_index, t->epg);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_learn_l2_node) = {
  .function = gbp_learn_l2,
  .name = "gbp-learn-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_learn_l2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_learn_error_strings),
  .error_strings = gbp_learn_error_strings,

  .n_next_nodes = GBP_LEARN_N_NEXT,

  .next_nodes = {
    [GBP_LEARN_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_learn_l2_node, gbp_learn_l2);
/* *INDENT-ON* */

typedef struct gbp_learn_l3_t_
{
  ip46_address_t ip;
  u32 fib_index;
  u32 sw_if_index;
  epg_id_t epg;
  ip46_address_t outer_src;
  ip46_address_t outer_dst;
} gbp_learn_l3_t;

static void
gbp_learn_l3_cp (const gbp_learn_l3_t * gl3)
{
  ip46_address_t *ips = NULL;

  GBP_LEARN_DBG ("L3 EP: %U, %d", format_ip46_address, &gl3->ip,
		 IP46_TYPE_ANY, gl3->epg);

  vec_add1 (ips, gl3->ip);

  gbp_endpoint_update (gl3->sw_if_index, ips, NULL, gl3->epg,
		       (GBP_ENDPOINT_FLAG_REMOTE |
			GBP_ENDPOINT_FLAG_LEARNT),
		       &gl3->outer_dst, &gl3->outer_src, NULL);
}

static void
gbp_learn_ip4_dp (const ip4_address_t * ip,
		  u32 fib_index, u32 sw_if_index, epg_id_t epg,
		  const ip4_address_t * outer_src,
		  const ip4_address_t * outer_dst)
{
  /* *INDENT-OFF* */
  gbp_learn_l3_t gl3 = {
    .ip = {
      .ip4 = *ip,
    },
    .sw_if_index = sw_if_index,
    .fib_index = fib_index,
    .epg = epg,
    .outer_src.ip4 = *outer_src,
    .outer_dst.ip4 = *outer_dst,
  };
  /* *INDENT-ON* */

  vl_api_rpc_call_main_thread (gbp_learn_l3_cp, (u8 *) & gl3, sizeof (gl3));
}

static void
gbp_learn_ip6_dp (const ip6_address_t * ip,
		  u32 fib_index, u32 sw_if_index, epg_id_t epg,
		  const ip4_address_t * outer_src,
		  const ip4_address_t * outer_dst)
{
  /* *INDENT-OFF* */
  gbp_learn_l3_t gl3 = {
    .ip = {
      .ip6 = *ip,
    },
    .sw_if_index = sw_if_index,
    .fib_index = fib_index,
    .epg = epg,
    .outer_src.ip4 = *outer_src,
    .outer_dst.ip4 = *outer_dst,
  };
  /* *INDENT-ON* */

  vl_api_rpc_call_main_thread (gbp_learn_l3_cp, (u8 *) & gl3, sizeof (gl3));
}

/**
 * per-packet trace data
 */
typedef struct gbp_learn_l3_trace_t_
{
  /* per-pkt trace data */
  ip46_address_t ip;
  u32 sw_if_index;
  u32 new;
  u32 throttled;
  u32 epg;
} gbp_learn_l3_trace_t;

static uword
gbp_learn_l3 (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame,
	      fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next, next_index, thread_index, seed;
  gbp_learn_main_t *glm;
  f64 time_now;

  glm = &gbp_learn_main;
  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  time_now = vlib_time_now (vm);
  thread_index = vm->thread_index;

  seed = throttle_seed (&glm->gl_l3_throttle, thread_index, time_now);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0, t0, epg0, fib_index0;
	  CLIB_UNUSED (const ip4_header_t *) ip4_0;
	  CLIB_UNUSED (const ip6_header_t *) ip6_0;
	  ip4_address_t outer_src, outer_dst;
	  ethernet_header_t *eth0;
	  gbp_learn_next_t next0;
	  gbp_endpoint_t *ge0;
	  vlib_buffer_t *b0;

	  next0 = GBP_LEARN_NEXT_DROP;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  epg0 = vnet_buffer2 (b0)->gbp.src_epg;
	  ip6_0 = NULL;
	  ip4_0 = NULL;

	  vnet_feature_next (&next0, b0);

	  if (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_D)
	    {
	      t0 = 1;
	      ge0 = NULL;
	      goto trace;
	    }

	  fib_index0 = fib_table_get_index_for_sw_if_index (fproto,
							    sw_if_index0);

	  if (FIB_PROTOCOL_IP6 == fproto)
	    {
	      ip6_0 = vlib_buffer_get_current (b0);
	      eth0 = (ethernet_header_t *) (((u8 *) ip6_0) - sizeof (*eth0));

	      gbp_learn_get_outer (eth0, &outer_src, &outer_dst);

	      ge0 = gbp_endpoint_find_ip6 (&ip6_0->src_address, fib_index0);

	      if (NULL == ge0)
		{
		  t0 = throttle_check (&glm->gl_l3_throttle,
				       thread_index,
				       ip6_address_hash_to_u32
				       (&ip6_0->src_address), seed);

		  if (!t0)
		    {
		      gbp_learn_ip6_dp (&ip6_0->src_address,
					fib_index0, sw_if_index0, epg0,
					&outer_src, &outer_dst);
		    }
		}
	      else
		{
		  /*
		   * this update could happen simultaneoulsy from multiple
		   * workers but that's ok we are not interested in being
		   * very accurate.
		   */
		  t0 = 0;
		  ge0->ge_last_time = time_now;
		}
	    }
	  else
	    {
	      ip4_0 = vlib_buffer_get_current (b0);
	      eth0 = (ethernet_header_t *) (((u8 *) ip4_0) - sizeof (*eth0));

	      gbp_learn_get_outer (eth0, &outer_src, &outer_dst);
	      ge0 = gbp_endpoint_find_ip4 (&ip4_0->src_address, fib_index0);

	      if (NULL == ge0)
		{
		  t0 = throttle_check (&glm->gl_l3_throttle, thread_index,
				       ip4_0->src_address.as_u32, seed);

		  if (!t0)
		    {
		      gbp_learn_ip4_dp (&ip4_0->src_address,
					fib_index0, sw_if_index0, epg0,
					&outer_src, &outer_dst);
		    }
		}
	      else
		{
		  /*
		   * this update could happen simultaneoulsy from multiple
		   * workers but that's ok we are not interested in being
		   * very accurate.
		   */
		  t0 = 0;
		  ge0->ge_last_time = time_now;
		}
	    }
	trace:
	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_learn_l3_trace_t *t;

	      t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      if (FIB_PROTOCOL_IP6 == fproto && ip6_0)
		ip46_address_set_ip6 (&t->ip, &ip6_0->src_address);
	      if (FIB_PROTOCOL_IP4 == fproto && ip4_0)
		ip46_address_set_ip4 (&t->ip, &ip4_0->src_address);
	      t->new = (NULL == ge0);
	      t->throttled = t0;
	      t->sw_if_index = sw_if_index0;
	      t->epg = epg0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_gbp_learn_l3_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_learn_l3_trace_t *t = va_arg (*args, gbp_learn_l3_trace_t *);

  s = format (s, "new:%d throttled:%d ip:%U itf:%d epg:%d",
	      t->new, t->throttled,
	      format_ip46_address, &t->ip, IP46_TYPE_ANY, t->sw_if_index,
	      t->epg);

  return s;
}

static uword
gbp_learn_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_learn_l3 (vm, node, frame, FIB_PROTOCOL_IP4));
}

static uword
gbp_learn_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_learn_l3 (vm, node, frame, FIB_PROTOCOL_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_learn_ip4_node) = {
  .function = gbp_learn_ip4,
  .name = "gbp-learn-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_learn_l3_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_learn_ip4_node, gbp_learn_ip4);

VNET_FEATURE_INIT (gbp_learn_ip4, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "gbp-learn-ip4",
};

VLIB_REGISTER_NODE (gbp_learn_ip6_node) = {
  .function = gbp_learn_ip6,
  .name = "gbp-learn-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_learn_l3_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_learn_ip6_node, gbp_learn_ip6);

VNET_FEATURE_INIT (gbp_learn_ip6, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "gbp-learn-ip6",
};

/* *INDENT-ON* */

void
gbp_learn_enable (u32 sw_if_index, gbb_learn_mode_t mode)
{
  if (GBP_LEARN_MODE_L2 == mode)
    l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_LEARN, 1);
  else
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "gbp-learn-ip4", sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast",
				   "gbp-learn-ip6", sw_if_index, 1, 0, 0);
    }
}

void
gbp_learn_disable (u32 sw_if_index, gbb_learn_mode_t mode)
{
  if (GBP_LEARN_MODE_L2 == mode)
    l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_LEARN, 0);
  else
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "gbp-learn-ip4", sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast",
				   "gbp-learn-ip6", sw_if_index, 0, 0, 0);
    }
}

static clib_error_t *
gbp_learn_init (vlib_main_t * vm)
{
  gbp_learn_main_t *glm = &gbp_learn_main;
  vlib_thread_main_t *tm = &vlib_thread_main;

  /* Initialize the feature next-node indices */
  feat_bitmap_init_next_nodes (vm,
			       gbp_learn_l2_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       glm->gl_l2_input_feat_next);

  throttle_init (&glm->gl_l2_throttle,
		 tm->n_vlib_mains, GBP_ENDPOINT_HASH_LEARN_RATE);

  throttle_init (&glm->gl_l3_throttle,
		 tm->n_vlib_mains, GBP_ENDPOINT_HASH_LEARN_RATE);

  glm->gl_logger = vlib_log_register_class ("gbp", "learn");

  return 0;
}

VLIB_INIT_FUNCTION (gbp_learn_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
