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
#include <vnet/dpo/drop_dpo.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>
#include <vnet/vxlan-gbp/vxlan_gbp.h>

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_recirc.h>

#ifndef CLIB_MARCH_VARIANT
/**
 * DPO pool
 */
gbp_policy_dpo_t *gbp_policy_dpo_pool;

/**
 * DPO type registered for these GBP FWD
 */
dpo_type_t gbp_policy_dpo_type;

static gbp_policy_dpo_t *
gbp_policy_dpo_alloc (void)
{
  gbp_policy_dpo_t *gpd;

  pool_get_aligned_zero (gbp_policy_dpo_pool, gpd, CLIB_CACHE_LINE_BYTES);

  return (gpd);
}

static inline gbp_policy_dpo_t *
gbp_policy_dpo_get_from_dpo (const dpo_id_t * dpo)
{
  ASSERT (gbp_policy_dpo_type == dpo->dpoi_type);

  return (gbp_policy_dpo_get (dpo->dpoi_index));
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
			    sclass_t sclass, u32 sw_if_index, dpo_id_t * dpo)
{
  gbp_policy_dpo_t *gpd;
  dpo_id_t parent = DPO_INVALID;

  gpd = gbp_policy_dpo_alloc ();

  gpd->gpd_proto = dproto;
  gpd->gpd_sw_if_index = sw_if_index;
  gpd->gpd_sclass = sclass;

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
  gbp_policy_dpo_t *gpd = gbp_policy_dpo_get (index);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "gbp-policy-dpo: %U, sclass:%d out:%U",
	      format_dpo_proto, gpd->gpd_proto,
	      (int) gpd->gpd_sclass,
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
  gpd_clone->gpd_sclass = gpd->gpd_sclass;
  gpd_clone->gpd_sw_if_index = gpd->gpd_sw_if_index;

  /*
   * if no interface is provided, grab one from the parent
   * on which we stack
   */
  if (~0 == gpd_clone->gpd_sw_if_index)
    gpd_clone->gpd_sw_if_index = dpo_get_urpf (parent);

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
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
#define _(sym,str) GBP_POLICY_DPO_ERROR_##sym,
  foreach_gbp_policy_error
#undef _
    GBP_POLICY_N_ERROR,
} gbp_policy_dpo_error_t;

static char *gbp_policy_dpo_error_strings[] = {
#define _(sym,string) string,
  foreach_gbp_policy_error
#undef _
};

typedef struct gbp_policy_dpo_trace_t_
{
  u32 sclass;
  u32 dclass;
  u32 acl_index;
  u32 flags;
  u32 action;
} gbp_policy_dpo_trace_t;

typedef enum
{
  GBP_POLICY_DROP,
  GBP_POLICY_N_NEXT,
} gbp_policy_next_t;

always_inline u32
gbp_rule_l3_redirect (const gbp_rule_t * gu, vlib_buffer_t * b0, int is_ip6)
{
  gbp_policy_node_t pnode;
  const dpo_id_t *dpo;
  dpo_proto_t dproto;

  pnode = (is_ip6 ? GBP_POLICY_NODE_IP6 : GBP_POLICY_NODE_IP4);
  dproto = (is_ip6 ? DPO_PROTO_IP6 : DPO_PROTO_IP4);
  dpo = &gu->gu_dpo[pnode][dproto];

  /* The flow hash is still valid as this is a IP packet being switched */
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo->dpoi_index;

  return (dpo->dpoi_next_node);
}

always_inline uword
gbp_policy_dpo_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, u8 is_ip6)
{
  gbp_main_t *gm = &gbp_main;
  u32 n_left_from, next_index, *from, *to_next, thread_index;
  u32 n_allow_intra, n_allow_a_bit, n_allow_sclass_1;
  gbp_rule_t *gu;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  n_allow_intra = n_allow_a_bit = n_allow_sclass_1 = 0;
  thread_index = vm->thread_index;

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
	  u8 action0;

	  action0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GBP_POLICY_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  gc0 = NULL;
	  gpd0 = gbp_policy_dpo_get (vnet_buffer (b0)->ip.adj_index[VLIB_TX]);
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = gpd0->gpd_dpo.dpoi_index;

	  /*
	   * Reflection check; in and out on an ivxlan tunnel
	   */
	  if ((~0 != vxlan_gbp_tunnel_by_sw_if_index (gpd0->gpd_sw_if_index))
	      && (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_R))
	    {
	      goto trace;
	    }

	  if (vnet_buffer2 (b0)->gbp.flags & VXLAN_GBP_GPFLAGS_A)
	    {
	      next0 = gpd0->gpd_dpo.dpoi_next_node;
	      key0.as_u32 = ~0;
	      n_allow_a_bit++;
	      goto trace;
	    }

	  key0.gck_src = vnet_buffer2 (b0)->gbp.sclass;
	  key0.gck_dst = gpd0->gpd_sclass;

	  if (SCLASS_INVALID != key0.gck_src)
	    {
	      if (PREDICT_FALSE (key0.gck_src == key0.gck_dst))
		{
		  /*
		   * intra-epg allowed
		   */
		  next0 = gpd0->gpd_dpo.dpoi_next_node;
		  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
		  n_allow_intra++;
		  action0 = 0;
		}
	      else if (PREDICT_FALSE (key0.gck_src == 1 || key0.gck_dst == 1))
		{
		  /*
		   * sclass or dclass 1 allowed
		   */
		  next0 = gpd0->gpd_dpo.dpoi_next_node;
		  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_A;
		  n_allow_sclass_1++;
		  action0 = 0;
		}
	      else
		{
		  gci0 = gbp_contract_find (&key0);

		  if (INDEX_INVALID != gci0)
		    {
		      fa_5tuple_opaque_t pkt_5tuple0;
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
			  gu = gbp_rule_get (gc0->gc_rules[rule_match_p0]);
			  action0 = gu->gu_action;

			  switch (gu->gu_action)
			    {
			    case GBP_RULE_PERMIT:
			      next0 = gpd0->gpd_dpo.dpoi_next_node;
			      break;
			    case GBP_RULE_DENY:
			      next0 = GBP_POLICY_DROP;
			      break;
			    case GBP_RULE_REDIRECT:
			      next0 = gbp_rule_l3_redirect (gu, b0, is_ip6);
			      break;
			    }
			}
		      if (next0 == GBP_POLICY_DROP)
			{
			  vlib_increment_combined_counter
			    (&gbp_contract_drop_counters,
			     thread_index,
			     gci0, 1, vlib_buffer_length_in_chain (vm, b0));
			  b0->error =
			    node->errors[GBP_POLICY_DPO_ERROR_DROP_CONTRACT];
			}
		      else
			{
			  vlib_increment_combined_counter
			    (&gbp_contract_permit_counters,
			     thread_index,
			     gci0, 1, vlib_buffer_length_in_chain (vm, b0));
			}

		    }
		  else
		    {
		      b0->error =
			node->errors[GBP_POLICY_DPO_ERROR_DROP_NO_CONTRACT];
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
	      tr->sclass = key0.gck_src;
	      tr->dclass = key0.gck_dst;
	      tr->acl_index = (gc0 ? gc0->gc_acl_index : ~0);
	      tr->flags = vnet_buffer2 (b0)->gbp.flags;
	      tr->action = action0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_DPO_ERROR_ALLOW_INTRA,
			       n_allow_intra);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_DPO_ERROR_ALLOW_A_BIT,
			       n_allow_a_bit);
  vlib_node_increment_counter (vm, node->node_index,
			       GBP_POLICY_DPO_ERROR_ALLOW_SCLASS_1,
			       n_allow_sclass_1);
  return from_frame->n_vectors;
}

static u8 *
format_gbp_policy_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_policy_dpo_trace_t *t = va_arg (*args, gbp_policy_dpo_trace_t *);

  s = format (s, " sclass:%d dclass:%d acl-index:%d flags:%U action:%d",
	      t->sclass, t->dclass, t->acl_index,
	      format_vxlan_gbp_header_gpflags, t->flags, t->action);

  return s;
}

VLIB_NODE_FN (ip4_gbp_policy_dpo_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return (gbp_policy_dpo_inline (vm, node, from_frame, 0));
}

VLIB_NODE_FN (ip6_gbp_policy_dpo_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * from_frame)
{
  return (gbp_policy_dpo_inline (vm, node, from_frame, 1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_gbp_policy_dpo_node) = {
    .name = "ip4-gbp-policy-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_policy_dpo_trace,

    .n_errors = ARRAY_LEN(gbp_policy_dpo_error_strings),
    .error_strings = gbp_policy_dpo_error_strings,

    .n_next_nodes = GBP_POLICY_N_NEXT,
    .next_nodes =
    {
        [GBP_POLICY_DROP] = "ip4-drop",
    }
};
VLIB_REGISTER_NODE (ip6_gbp_policy_dpo_node) = {
    .name = "ip6-gbp-policy-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_policy_dpo_trace,

    .n_errors = ARRAY_LEN(gbp_policy_dpo_error_strings),
    .error_strings = gbp_policy_dpo_error_strings,

    .n_next_nodes = GBP_POLICY_N_NEXT,
    .next_nodes =
    {
        [GBP_POLICY_DROP] = "ip6-drop",
    }
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
