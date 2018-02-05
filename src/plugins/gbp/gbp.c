/*
 * gbp.h : Group Based Policy
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

/**
 * IP4 destintion address to destination EPG mapping table
 */
typedef struct gbp_ip4_to_epg_db_t_
{
  /**
   * use a simple hash table
   */
  uword *g4ie_hash;
} gbp_ip4_to_epg_db_t;

static gbp_ip4_to_epg_db_t gbp_ip4_to_epg_db;

/**
 * IP6 destintion address to destination EPG mapping table
 */
typedef struct gbp_ip6_to_epg_db_t_
{
  /**
   * use a memroy hash table
   */
  uword *g6ie_hash;
} gbp_ip6_to_epg_db_t;

static gbp_ip6_to_epg_db_t gbp_ip6_to_epg_db;

/**
 * Result of a interface to EPG mapping.
 * multiple Endpoints can occur on the same interface, so this
 * mapping needs to be reference counted.
 */
typedef struct gbp_itf_t_
{
  epg_id_t gi_epg;
  u32 gi_ref_count;
} gbp_itf_t;

const static gbp_itf_t ITF_INVALID = {
  .gi_epg = EPG_INVALID,
  .gi_ref_count = 0,
};

/**
 * Interface to source EPG DB - a per-interface vector
 */
typedef struct gbp_itf_to_epg_db_t_
{
  gbp_itf_t *gte_vec;
} gbp_itf_to_epg_db_t;

static gbp_itf_to_epg_db_t gbp_itf_to_epg_db;

/**
 * Pool of GBP endpoints
 */
static gbp_endpoint_t *gbp_endpoint_pool;

/**
 * DB of endpoints
 */
static uword *gbp_endpoint_db;

/**
 * EPG src,dst pair to ACL mapping table, aka contract DB
 */
typedef struct gbp_contract_db_t_
{
  /**
   * We can form a u64 key from the pair, so use a simple hash table
   */
  uword *gc_hash;
} gbp_contract_db_t;

/**
 * Since contract DB instance
 */
static gbp_contract_db_t gbp_contract_db;

static void
gbp_ip_epg_update (const ip46_address_t * ip, epg_id_t epg_id)
{
  /*
   * we are dealing only with addresses here so this limited
   * is_ip4 check is ok
   */
  if (ip46_address_is_ip4 (ip))
    {
      hash_set (gbp_ip4_to_epg_db.g4ie_hash, ip->ip4.as_u32, epg_id);
    }
  else
    {
      hash_set_mem (gbp_ip6_to_epg_db.g6ie_hash, &ip->ip6, epg_id);
    }
}

static void
gbp_ip_epg_delete (const ip46_address_t * ip)
{
  if (ip46_address_is_ip4 (ip))
    {
      hash_unset (gbp_ip4_to_epg_db.g4ie_hash, ip->ip4.as_u32);
    }
  else
    {
      hash_unset_mem (gbp_ip6_to_epg_db.g6ie_hash, &ip->ip6);
    }
}

static void
gbp_itf_epg_update (u32 sw_if_index, epg_id_t src_epg)
{
  vec_validate_init_empty (gbp_itf_to_epg_db.gte_vec,
			   sw_if_index, ITF_INVALID);

  if (0 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count)
    {
      vnet_feature_enable_disable ("ip4-unicast", "gbp4",
				   sw_if_index, 1, NULL, 0);
      vnet_feature_enable_disable ("ip6-unicast", "gbp6",
				   sw_if_index, 1, NULL, 0);
    }
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = src_epg;
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count++;
}

static void
gbp_itf_epg_delete (u32 sw_if_index)
{
  if (vec_len (gbp_itf_to_epg_db.gte_vec) <= sw_if_index)
    return;

  if (1 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count)
    {
      gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = EPG_INVALID;

      vnet_feature_enable_disable ("ip4-unicast", "gbp4",
				   sw_if_index, 0, NULL, 0);
      vnet_feature_enable_disable ("ip6-unicast", "gbp6",
				   sw_if_index, 0, NULL, 0);
    }
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count--;
}

void
gbp_endpoint_update (u32 sw_if_index,
		     const ip46_address_t * ip, epg_id_t epg_id)
{
  gbp_endpoint_key_t key = {
    .gek_ip = *ip,
    .gek_sw_if_index = sw_if_index,
  };
  gbp_endpoint_t *gbpe;
  uword *p;

  p = hash_get_mem (gbp_endpoint_db, &key);

  if (p)
    {
      gbpe = pool_elt_at_index (gbp_endpoint_pool, p[0]);
    }
  else
    {
      pool_get (gbp_endpoint_pool, gbpe);

      gbpe->ge_key = clib_mem_alloc (sizeof (gbp_endpoint_key_t));
      clib_memcpy (gbpe->ge_key, &key, sizeof (gbp_endpoint_key_t));

      hash_set_mem (gbp_endpoint_db, gbpe->ge_key, gbpe - gbp_endpoint_pool);
    }

  gbpe->ge_epg_id = epg_id;

  gbp_itf_epg_update (gbpe->ge_key->gek_sw_if_index, gbpe->ge_epg_id);
  gbp_ip_epg_update (&gbpe->ge_key->gek_ip, gbpe->ge_epg_id);
}

void
gbp_endpoint_delete (u32 sw_if_index, const ip46_address_t * ip)
{
  gbp_endpoint_key_t key = {
    .gek_ip = *ip,
    .gek_sw_if_index = sw_if_index,
  };
  gbp_endpoint_t *gbpe;
  uword *p;

  p = hash_get_mem (gbp_endpoint_db, &key);

  if (p)
    {
      gbpe = pool_elt_at_index (gbp_endpoint_pool, p[0]);

      hash_unset_mem (gbp_endpoint_db, gbpe->ge_key);

      gbp_itf_epg_delete (gbpe->ge_key->gek_sw_if_index);
      gbp_ip_epg_delete (&gbpe->ge_key->gek_ip);

      clib_mem_free (gbpe->ge_key);

      pool_put (gbp_endpoint_pool, gbpe);
    }
}

void
gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx)
{
  gbp_endpoint_t *gbpe;

  /* *INDENT-OFF* */
  pool_foreach(gbpe, gbp_endpoint_pool,
  {
    if (!cb(gbpe, ctx))
      break;
  });
  /* *INDENT-ON* */
}

void
gbp_contract_update (epg_id_t src_epg, epg_id_t dst_epg, u32 acl_index)
{
  gbp_contract_key_t key = {
    .gck_src = src_epg,
    .gck_dst = dst_epg,
  };

  hash_set (gbp_contract_db.gc_hash, key.as_u64, acl_index);
}

void
gbp_contract_delete (epg_id_t src_epg, epg_id_t dst_epg)
{
  gbp_contract_key_t key = {
    .gck_src = src_epg,
    .gck_dst = dst_epg,
  };

  hash_unset (gbp_contract_db.gc_hash, key.as_u64);
}

void
gbp_contract_walk (gbp_contract_cb_t cb, void *ctx)
{
  gbp_contract_key_t key;
  u32 acl_index;

  /* *INDENT-OFF* */
  hash_foreach(key.as_u64, acl_index, gbp_contract_db.gc_hash,
  ({
    gbp_contract_t gbpc = {
      .gc_key = key,
      .gc_acl_index = acl_index,
    };

    if (!cb(&gbpc, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
gbp_endpoint_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  epg_id_t epg_id = EPG_INVALID;
  ip46_address_t ip = { };
  u32 sw_if_index = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "epg %d", &epg_id))
	;
      else if (unformat (input, "ip %U", unformat_ip4_address, &ip.ip4))
	;
      else if (unformat (input, "ip %U", unformat_ip6_address, &ip.ip6))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (EPG_INVALID == epg_id)
    return clib_error_return (0, "EPG-ID must be specified");
  if (ip46_address_is_zero (&ip))
    return clib_error_return (0, "IP address must be specified");

  if (add)
    gbp_endpoint_update (sw_if_index, &ip, epg_id);
  else
    gbp_endpoint_delete (sw_if_index, &ip);

  return (NULL);
}

static clib_error_t *
gbp_contract_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  epg_id_t src_epg_id = EPG_INVALID, dst_epg_id = EPG_INVALID;
  u32 acl_index = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "src-epg %d", &src_epg_id))
	;
      else if (unformat (input, "dst-epg %d", &dst_epg_id))
	;
      else if (unformat (input, "acl-index %d", &acl_index))
	;
      else
	break;
    }

  if (EPG_INVALID == src_epg_id)
    return clib_error_return (0, "Source EPG-ID must be specified");
  if (EPG_INVALID == dst_epg_id)
    return clib_error_return (0, "Destination EPG-ID must be specified");

  if (add)
    {
      gbp_contract_update (src_epg_id, dst_epg_id, acl_index);
    }
  else
    {
      gbp_contract_delete (src_epg_id, dst_epg_id);
    }

  return (NULL);
}

/*?
 * Configure a GBP Endpoint
 *
 * @cliexpar
 * @cliexstart{set gbp endpoint [del] <interface> epg <ID> ip <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_cli_node, static) = {
  .path = "gbp endpoint",
  .short_help = "gbp endpoint [del] <interface> epg <ID> ip <IP>",
  .function = gbp_endpoint_cli,
};

/*?
 * Configure a GBP Contract
 *
 * @cliexpar
 * @cliexstart{set gbp contract [del] src-epg <ID> dst-epg <ID> acl-index <ACL>}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (gbp_contract_cli_node, static) = {
  .path = "gbp contract",
  .short_help = "gbp contract [del] src-epg <ID> dst-epg <ID> acl-index <ACL>",
  .function = gbp_contract_cli,
};
/* *INDENT-ON* */

static int
gbp_endpoint_show_one (gbp_endpoint_t * gbpe, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  {%U, %U} -> %d",
		   format_vnet_sw_if_index_name, vnm,
		   gbpe->ge_key->gek_sw_if_index,
		   format_ip46_address, &gbpe->ge_key->gek_ip, IP46_TYPE_ANY,
		   gbpe->ge_epg_id);

  return (1);
}

static clib_error_t *
gbp_endpoint_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip46_address_t ip, *ipp;
  epg_id_t epg_id;
  u32 sw_if_index;

  vlib_cli_output (vm, "Endpoints:");
  gbp_endpoint_walk (gbp_endpoint_show_one, vm);

  vlib_cli_output (vm, "\nSource interface to EPG:");

  vec_foreach_index (sw_if_index, gbp_itf_to_epg_db.gte_vec)
  {
    if (EPG_INVALID != gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg)
      {
	vlib_cli_output (vm, "  %U -> %d",
			 format_vnet_sw_if_index_name, vnm, sw_if_index,
			 gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg);
      }
  }

  vlib_cli_output (vm, "\nDestination IP4 to EPG:");

  /* *INDENT-OFF* */
  hash_foreach (ip.ip4.as_u32, epg_id, gbp_ip4_to_epg_db.g4ie_hash,
  {
    vlib_cli_output (vm, "  %U -> %d", format_ip46_address, &ip,
                     IP46_TYPE_IP4, epg_id);
  });
  /* *INDENT-ON* */

  vlib_cli_output (vm, "\nDestination IP6 to EPG:");

  /* *INDENT-OFF* */
  hash_foreach_mem (ipp, epg_id, gbp_ip6_to_epg_db.g6ie_hash,
  {
    vlib_cli_output (vm, "  %U -> %d", format_ip46_address, ipp,
                     IP46_TYPE_IP6, epg_id);
  });
  /* *INDENT-ON* */

  return (NULL);
}

static clib_error_t *
gbp_contract_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  gbp_contract_key_t key;
  epg_id_t epg_id;

  vlib_cli_output (vm, "Contracts:");

  /* *INDENT-OFF* */
  hash_foreach (key.as_u64, epg_id, gbp_contract_db.gc_hash,
  {
    vlib_cli_output (vm, "  {%d,%d} -> %d", key.gck_src,
                     key.gck_dst, epg_id);
  });
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * Show Group Based Policy Endpoints and derived information
 *
 * @cliexpar
 * @cliexstart{show gbp endpoint}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_show_node, static) = {
  .path = "show gbp endpoint",
  .short_help = "show gbp endpoint\n",
  .function = gbp_endpoint_show,
};
/* *INDENT-ON* */

/*?
 * Show Group Based Policy Contracts
 *
 * @cliexpar
 * @cliexstart{show gbp contract}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_contract_show_node, static) = {
  .path = "show gbp contract",
  .short_help = "show gbp contract\n",
  .function = gbp_contract_show,
};
/* *INDENT-ON* */

#define foreach_gbp                    \
  _(DENY,    "deny")

typedef enum
{
#define _(sym,str) GBP_ERROR_##sym,
  foreach_gbp
#undef _
    GBP_N_ERROR,
} gbp_error_t;

static char *gbp_error_strings[] = {
#define _(sym,string) string,
  foreach_gbp
#undef _
};

typedef enum
{
#define _(sym,str) GBP_NEXT_##sym,
  foreach_gbp
#undef _
    GBP_N_NEXT,
} gbp_next_t;

/**
 * per-packet trace data
 */
typedef struct gbp_trace_t_
{
  /* per-pkt trace data */
  epg_id_t src_epg;
  epg_id_t dst_epg;
  u32 acl_index;
} gbp_trace_t;

static inline uword
gbp_inline (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  gbp_next_t next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  gbp_next_t next0;
	  u32 bi0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  gbp_contract_key_t key0;
	  u32 acl_index0;
	  uword *p;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  /* deny by default */
	  next0 = GBP_NEXT_DENY;

	  b0 = vlib_get_buffer (vm, bi0);
	  if (is_ip6)
	    ip6_0 = vlib_buffer_get_current (b0);
	  else
	    ip4_0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /*
	   * determine the src and dst EPG
	   */
	  key0.gck_src = gbp_itf_to_epg_db.gte_vec[sw_if_index0].gi_epg;

	  if (is_ip6)
	    p = hash_get_mem (gbp_ip6_to_epg_db.g6ie_hash,
			      &ip6_0->dst_address);
	  else
	    p = hash_get (gbp_ip4_to_epg_db.g4ie_hash,
			  ip4_0->dst_address.as_u32);

	  if (NULL != p)
	    {
	      key0.gck_dst = p[0];

	      /*
	       * If the src and dst are the same, then let it through
	       */
	      if (key0.gck_dst == key0.gck_src)
		{
		  vnet_feature_next (sw_if_index0, &next0, b0);
		  acl_index0 = ~0;
		}
	      else
		{
		  /*
		   * find this src,dst pair in the egp->acl DB
		   */
		  p = hash_get (gbp_contract_db.gc_hash, key0.as_u64);

		  if (NULL != p)
		    {
		      acl_index0 = p[0];

		      /*
		       * the ACL index stored is NULL, this means any-any so let it pass
		       */
		      if (~0 == acl_index0)
			{
			  vnet_feature_next (sw_if_index0, &next0, b0);
			}
		      else
			{
			  /*
			   * TODO tests against the ACL
			   */
			}
		    }
		  else
		    {
		      /*
		       * no ACL to apply for packets between these two EPGs.
		       * GBP is a whitelist model, so no ACL implies deny, which
		       * is the default result
		       */
		      acl_index0 = ~0;
		    }
		}
	    }
	  else
	    {
	      /*
	       * cannot determine the destinaiotn EPG, so we cannot enforce policy
	       * on this node. permit.
	       */
	      vnet_feature_next (sw_if_index0, &next0, b0);

	      key0.gck_dst = ~0;
	      acl_index0 = ~0;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->src_epg = key0.gck_src;
	      t->dst_epg = key0.gck_dst;
	      t->acl_index = acl_index0;
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
format_gbp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_trace_t *t = va_arg (*args, gbp_trace_t *);

  s = format (s, "gbp: src:%d dst:%d acl:%d",
	      t->src_epg, t->dst_epg, t->acl_index);

  return s;
}

static inline uword
gbp_4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_inline (vm, node, frame, 0));
}

static inline uword
gbp_6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_inline (vm, node, frame, 1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_4_node) = {
  .function = gbp_4,
  .name = "gbp4",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_error_strings),
  .error_strings = gbp_error_strings,

  .n_next_nodes = GBP_N_NEXT,

  .next_nodes = {
    [GBP_NEXT_DENY] = "ip4-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_4_node, gbp_4);

VNET_FEATURE_INIT (gbp_4_node, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "gbp4",
    .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};

VLIB_REGISTER_NODE (gbp_6_node) = {
  .function = gbp_6,
  .name = "gbp6",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_error_strings),
  .error_strings = gbp_error_strings,

  .n_next_nodes = GBP_N_NEXT,

  .next_nodes = {
    [GBP_NEXT_DENY] = "ip6-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_6_node, gbp_6);

VNET_FEATURE_INIT (gbp_6_node, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "gbp6",
    .runs_after = VNET_FEATURES ("acl-plugin-out-ip6-fa"),
};
/* *INDENT-ON* */

static clib_error_t *
gbp_init (vlib_main_t * vm)
{
  gbp_endpoint_db = hash_create_mem (0,
				     sizeof (gbp_endpoint_key_t),
				     sizeof (u32));
  gbp_ip6_to_epg_db.g6ie_hash =
    hash_create_mem (0, sizeof (ip6_address_t), sizeof (u32));
  return 0;
}

VLIB_INIT_FUNCTION (gbp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
