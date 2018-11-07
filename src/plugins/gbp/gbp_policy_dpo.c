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

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_recirc.h>

/**
 * DPO pool
 */
static gbp_policy_dpo_t *gbp_policy_dpo_pool;

/**
 * DPO type registered for these GBP FWD
 */
static dpo_type_t gbp_policy_dpo_type;

static inline gbp_policy_dpo_t *
gbp_policy_dpo_get_i (index_t index)
{
  return (pool_elt_at_index (gbp_policy_dpo_pool, index));
}

gbp_policy_dpo_t *
gbp_policy_dpo_get (index_t index)
{
  return (gbp_policy_dpo_get_i (index));
}

static gbp_policy_dpo_t *
gbp_policy_dpo_alloc (void)
{
  gbp_policy_dpo_t *gpd;

  pool_get_zero (gbp_policy_dpo_pool, gpd);

  return (gpd);
}

static inline gbp_policy_dpo_t *
gbp_policy_dpo_get_from_dpo (const dpo_id_t * dpo)
{
  ASSERT (gbp_policy_dpo_type == dpo->dpoi_type);

  return (gbp_policy_dpo_get_i (dpo->dpoi_index));
}

static inline index_t
gbp_policy_dpo_get_index (gbp_policy_dpo_t * gpd)
{
  return (gpd - gbp_policy_dpo_pool);
}

static void
gbp_policy_dpo_lock (dpo_id_t * dpo)
{
  gbp_policy_dpo_t *gpd;

  gpd = gbp_policy_dpo_get_from_dpo (dpo);
  gpd->gpd_locks++;
}

static void
gbp_policy_dpo_unlock (dpo_id_t * dpo)
{
  gbp_policy_dpo_t *gpd;

  gpd = gbp_policy_dpo_get_from_dpo (dpo);
  gpd->gpd_locks--;

  if (0 == gpd->gpd_locks)
    {
      dpo_reset (&gpd->gpd_dpo);
      pool_put (gbp_policy_dpo_pool, gpd);
    }
}

static u32
gbp_policy_dpo_get_urpf (const dpo_id_t * dpo)
{
  gbp_policy_dpo_t *gpd;

  gpd = gbp_policy_dpo_get_from_dpo (dpo);

  return (gpd->gpd_sw_if_index);
}

void
gbp_policy_dpo_add_or_lock (dpo_proto_t dproto,
			    epg_id_t epg, u32 sw_if_index, dpo_id_t * dpo)
{
  gbp_policy_dpo_t *gpd;
  dpo_id_t parent = DPO_INVALID;

  gpd = gbp_policy_dpo_alloc ();

  gpd->gpd_proto = dproto;
  gpd->gpd_sw_if_index = sw_if_index;
  gpd->gpd_epg = epg;

  if (~0 != sw_if_index)
    {
      /*
       * stack on the DVR DPO for the output interface
       */
      dvr_dpo_add_or_lock (sw_if_index, dproto, &parent);
    }
  else
    {
      dpo_copy (&parent, drop_dpo_get (dproto));
    }

  dpo_stack (gbp_policy_dpo_type, dproto, &gpd->gpd_dpo, &parent);
  dpo_set (dpo, gbp_policy_dpo_type, dproto, gbp_policy_dpo_get_index (gpd));
}

u8 *
format_gbp_policy_dpo (u8 * s, va_list * ap)
{
  index_t index = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);
  gbp_policy_dpo_t *gpd = gbp_policy_dpo_get_i (index);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "gbp-policy-dpo: %U, epg:%d out:%U",
	      format_dpo_proto, gpd->gpd_proto,
	      gpd->gpd_epg,
	      format_vnet_sw_if_index_name, vnm, gpd->gpd_sw_if_index);
  s = format (s, "\n%U", format_white_space, indent + 2);
  s = format (s, "%U", format_dpo_id, &gpd->gpd_dpo, indent + 4);

  return (s);
}

/**
 * Interpose a policy DPO
 */
static void
gbp_policy_dpo_interpose (const dpo_id_t * original,
			  const dpo_id_t * parent, dpo_id_t * clone)
{
  gbp_policy_dpo_t *gpd, *gpd_clone;

  gpd_clone = gbp_policy_dpo_alloc ();
  gpd = gbp_policy_dpo_get (original->dpoi_index);

  gpd_clone->gpd_proto = gpd->gpd_proto;
  gpd_clone->gpd_epg = gpd->gpd_epg;
  gpd_clone->gpd_sw_if_index = gpd->gpd_sw_if_index;

  dpo_stack (gbp_policy_dpo_type,
	     gpd_clone->gpd_proto, &gpd_clone->gpd_dpo, parent);

  dpo_set (clone,
	   gbp_policy_dpo_type,
	   gpd_clone->gpd_proto, gbp_policy_dpo_get_index (gpd_clone));
}

const static dpo_vft_t gbp_policy_dpo_vft = {
  .dv_lock = gbp_policy_dpo_lock,
  .dv_unlock = gbp_policy_dpo_unlock,
  .dv_format = format_gbp_policy_dpo,
  .dv_get_urpf = gbp_policy_dpo_get_urpf,
  .dv_mk_interpose = gbp_policy_dpo_interpose,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char *const gbp_policy_dpo_ip4_nodes[] = {
  "ip4-gbp-policy-dpo",
  NULL,
};

const static char *const gbp_policy_dpo_ip6_nodes[] = {
  "ip6-gbp-policy-dpo",
  NULL,
};

const static char *const *const gbp_policy_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = gbp_policy_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = gbp_policy_dpo_ip6_nodes,
};

dpo_type_t
gbp_policy_dpo_get_type (void)
{
  return (gbp_policy_dpo_type);
}

static clib_error_t *
gbp_policy_dpo_module_init (vlib_main_t * vm)
{
  gbp_policy_dpo_type = dpo_register_new_type (&gbp_policy_dpo_vft,
					       gbp_policy_dpo_nodes);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_policy_dpo_module_init);

typedef struct gbp_policy_dpo_trace_t_
{
  u32 src_epg;
  u32 dst_epg;
  u32 acl_index;
  u32 a_bit;
} gbp_policy_dpo_trace_t;

typedef enum
{
  GBP_POLICY_DROP,
  GBP_POLICY_N_NEXT,
} gbp_policy_next_t;

always_inline uword
gbp_policy_dpo_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, u8 is_ip6)
{
  gbp_main_t *gm = &gbp_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const gbp_policy_dpo_t *gpd0;
	  u32 bi0, next0;
	  gbp_contract_key_t key0;
	  gbp_contract_t *gc0;
	  vlib_buffer_t *b0;
	  index_t gci0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GBP_POLICY_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  gc0 = NULL;
	  gpd0 =
	    gbp_policy_dpo_get_i (vnet_buffer (b0)->ip.adj_index[VLIB_TX]);
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = gpd0->gpd_dpo.dpoi_index;

	  if (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_A)
	    {
	      next0 = gpd0->gpd_dpo.dpoi_next_node;
	      key0.as_u32 = ~0;
	      goto trace;
	    }

	  key0.gck_src = vnet_buffer2 (b0)->gbp.src_epg;
	  key0.gck_dst = gpd0->gpd_epg;

	  if (EPG_INVALID != key0.gck_src)
	    {
	      if (PREDICT_FALSE (key0.gck_src == key0.gck_dst))
		{
		  /*
		   * intra-epg allowed
		   */
		  next0 = gpd0->gpd_dpo.dpoi_next_node;
		  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
		}
	      else
		{
		  gci0 = gbp_contract_find (&key0);

		  if (INDEX_INVALID != gci0)
		    {
		      fa_5tuple_opaque_t pkt_5tuple0;
		      u8 action0 = 0;
		      u32 acl_pos_p0, acl_match_p0;
		      u32 rule_match_p0, trace_bitmap0;
		      /*
		       * tests against the ACL
		       */
		      gc0 = gbp_contract_get (gci0);
		      acl_plugin_fill_5tuple_inline (gm->
						     acl_plugin.p_acl_main,
						     gc0->gc_lc_index, b0,
						     is_ip6,
						     /* is_input */ 1,
						     /* is_l2_path */ 0,
						     &pkt_5tuple0);
		      acl_plugin_match_5tuple_inline (gm->
						      acl_plugin.p_acl_main,
						      gc0->gc_lc_index,
						      &pkt_5tuple0, is_ip6,
						      &action0, &acl_pos_p0,
						      &acl_match_p0,
						      &rule_match_p0,
						      &trace_bitmap0);

		      if (action0 > 0)
			{
			  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
			  next0 = gpd0->gpd_dpo.dpoi_next_node;
			}
		    }
		}
	    }
	  else
	    {
	      /*
	       * the src EPG is not set when the packet arrives on an EPG
	       * uplink interface and we do not need to apply policy
	       */
	      next0 = gpd0->gpd_dpo.dpoi_next_node;
	    }
	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gbp_policy_dpo_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->src_epg = key0.gck_src;
	      tr->dst_epg = key0.gck_dst;
	      tr->acl_index = (gc0 ? gc0->gc_acl_index : ~0);
	      tr->a_bit = vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_A;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static u8 *
format_gbp_policy_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_policy_dpo_trace_t *t = va_arg (*args, gbp_policy_dpo_trace_t *);

  s = format (s, " src-epg:%d dst-epg:%d acl-index:%d a-bit:%d",
	      t->src_epg, t->dst_epg, t->acl_index, t->a_bit);

  return s;
}

static uword
ip4_gbp_policy_dpo (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return (gbp_policy_dpo_inline (vm, node, from_frame, 0));
}

static uword
ip6_gbp_policy_dpo (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return (gbp_policy_dpo_inline (vm, node, from_frame, 1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_gbp_policy_dpo_node) = {
    .function = ip4_gbp_policy_dpo,
    .name = "ip4-gbp-policy-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_policy_dpo_trace,
    .n_next_nodes = GBP_POLICY_N_NEXT,
    .next_nodes =
    {
        [GBP_POLICY_DROP] = "ip4-drop",
    }
};
VLIB_REGISTER_NODE (ip6_gbp_policy_dpo_node) = {
    .function = ip6_gbp_policy_dpo,
    .name = "ip6-gbp-policy-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_policy_dpo_trace,
    .n_next_nodes = GBP_POLICY_N_NEXT,
    .next_nodes =
    {
        [GBP_POLICY_DROP] = "ip6-drop",
    }
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_gbp_policy_dpo_node, ip4_gbp_policy_dpo)
VLIB_NODE_FUNCTION_MULTIARCH (ip6_gbp_policy_dpo_node, ip6_gbp_policy_dpo)
/* *INDENT-ON* */

 /**
 * per-packet trace data
 */
typedef struct gbp_classify_trace_t_
{
  /* per-pkt trace data */
  epg_id_t src_epg;
} gbp_classify_trace_t;

typedef enum gbp_lpm_classify_next_t_
{
  GPB_LPM_CLASSIFY_DROP,
} gbp_lpm_classify_next_t;

/*
 * Determine the SRC EPG from a LPM
 */
always_inline uword
gbp_lpm_classify_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame, fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0, fib_index0, lbi0;
	  gbp_lpm_classify_next_t next0;
	  const gbp_policy_dpo_t *gpd0;
	  const gbp_recirc_t *gr0;
	  const dpo_id_t *dpo0;
	  load_balance_t *lb0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  vlib_buffer_t *b0;
	  epg_id_t src_epg0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GPB_LPM_CLASSIFY_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  gr0 = gbp_recirc_get (sw_if_index0);
	  fib_index0 = gr0->gr_fib_index[fproto];

	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      ip4_0 = vlib_buffer_get_current (b0);
	      lbi0 = ip4_fib_forwarding_lookup (fib_index0,
						&ip4_0->src_address);
	    }
	  else
	    {
	      ip6_0 = vlib_buffer_get_current (b0);
	      lbi0 = ip6_fib_table_fwding_lookup (&ip6_main, fib_index0,
						  &ip6_0->src_address);
	    }

	  lb0 = load_balance_get (lbi0);
	  dpo0 = load_balance_get_bucket_i (lb0, 0);

	  if (gbp_policy_dpo_type == dpo0->dpoi_type)
	    {
	      gpd0 = gbp_policy_dpo_get_i (dpo0->dpoi_index);
	      src_epg0 = gpd0->gpd_epg;
	      vnet_feature_next (&next0, b0);
	    }
	  else
	    {
	      /* could not classify => drop */
	      src_epg0 = 0;
	    }

	  vnet_buffer2 (b0)->gbp.src_epg = src_epg0;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->src_epg = src_epg0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
gbp_ip4_lpm_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, FIB_PROTOCOL_IP4));
}

static uword
gbp_ip6_lpm_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, FIB_PROTOCOL_IP6));
}

 /* packet trace format function */
static u8 *
format_gbp_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_classify_trace_t *t = va_arg (*args, gbp_classify_trace_t *);

  s = format (s, "src-epg:%d", t->src_epg);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_ip4_lpm_classify_node) = {
  .function = gbp_ip4_lpm_classify,
  .name = "ip4-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip4-drop"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip4_lpm_classify_node, gbp_ip4_lpm_classify);

VLIB_REGISTER_NODE (gbp_ip6_lpm_classify_node) = {
  .function = gbp_ip6_lpm_classify,
  .name = "ip6-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip6-drop"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip6_lpm_classify_node, gbp_ip6_lpm_classify);

VNET_FEATURE_INIT (gbp_ip4_lpm_classify_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-gbp-lpm-classify",
  .runs_before = VNET_FEATURES ("nat44-out2in"),
};
VNET_FEATURE_INIT (gbp_ip6_lpm_classify_feat_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-gbp-lpm-classify",
  .runs_before = VNET_FEATURES ("nat66-out2in"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
