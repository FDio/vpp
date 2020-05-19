/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>

#include <calico/calico.h>

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

typedef struct calico_tx_db_t_
{
  /* TX VIPs */
  uword *ctd_vip;
} calico_tx_db_t;

calico_vip_tx_t *calico_vip_pool;
calico_client_rx_t *calico_client_pool;
calico_translation_t *calico_translation_pool;

clib_bihash_40_32_t calico_session_db;
calico_tx_db_t calico_tx_db;
calico_rx_db_t calico_rx_db;

dpo_type_t calico_tx_dpo;
dpo_type_t calico_rx_dpo;

static fib_source_t calico_fib_source;
static fib_node_type_t calico_translation_fib_node_type;

vlib_combined_counter_main_t calico_translation_counters = {
  .name = "calico-translation",
  .stat_segment_name = "/net/calico-translation",
};

static calico_vip_tx_t *
calico_vip_find (const ip_address_t * ip)
{
  uword *p;

  p = hash_get_mem (calico_tx_db.ctd_vip, ip);

  if (p)
    return (pool_elt_at_index (calico_vip_pool, p[0]));

  return (NULL);
}

static void
calico_vip_add (const ip_address_t * ip, index_t cvipi)
{
  hash_set_mem_alloc (&calico_tx_db.ctd_vip, ip, cvipi);
}

static void
calico_vip_add_translation (calico_vip_tx_t * cvip,
			    u16 port, ip_protocol_t proto, index_t cti)
{
  u32 key;

  key = proto;
  key = (key << 16) | port;

  hash_set (cvip->cvip_translations, key, cti);
}

static void
calico_vip_remove_translation (calico_vip_tx_t * cvip,
			       u16 port, ip_protocol_t proto)
{
  u32 key;

  key = proto;
  key = (key << 16) | port;

  hash_unset (cvip->cvip_translations, key);
}

static void
calico_tracker_release (calico_ep_trk_t * trk)
{
  fib_entry_untrack (trk->ct_fei, trk->ct_sibling);
}

static void
calico_tracker_track (index_t cti,
		      const calico_endpoint_t * path, calico_ep_trk_t * trk)
{
  fib_prefix_t pfx;

  ip_address_to_fib_prefix (&path->ce_ip, &pfx);

  clib_memcpy (&trk->ct_ep, path, sizeof (trk->ct_ep));

  trk->ct_fei = fib_entry_track (CALICO_FIB_TABLE,
				 &pfx,
				 calico_translation_fib_node_type,
				 cti, &trk->ct_sibling);

  fib_entry_contribute_forwarding (trk->ct_fei,
				   fib_forw_chain_type_from_fib_proto
				   (pfx.fp_proto), &trk->ct_dpo);
}

static void
calico_translation_stack (calico_translation_t * ct)
{
  fib_protocol_t fproto;
  calico_ep_trk_t *trk;
  dpo_proto_t dproto;
  index_t lbi;

  fproto = ip_address_family_to_fib_proto (ct->ct_vip.ce_ip.version);
  dproto = fib_proto_to_dpo (fproto);

  lbi = load_balance_create (vec_len (ct->ct_paths),
			     fib_proto_to_dpo (fproto), IP_FLOW_HASH_DEFAULT);

  vec_foreach (trk, ct->ct_paths)
    load_balance_set_bucket (lbi, trk - ct->ct_paths, &trk->ct_dpo);

  dpo_set (&ct->ct_lb, DPO_LOAD_BALANCE, dproto, lbi);
  dpo_stack (calico_tx_dpo, dproto, &ct->ct_lb, &ct->ct_lb);
}

int
calico_translate_delete (u32 id)
{
  calico_translation_t *ct;
  calico_vip_tx_t *cvip;
  calico_ep_trk_t *trk;

  if (pool_is_free_index (calico_translation_pool, id))
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  ct = pool_elt_at_index (calico_translation_pool, id);
  cvip = pool_elt_at_index (calico_vip_pool, ct->ct_vipi);

  dpo_reset (&ct->ct_lb);

  vec_foreach (trk, ct->ct_paths) calico_tracker_release (trk);

  pool_put (calico_translation_pool, ct);

  cvip->cvip_locks--;

  calico_vip_remove_translation (cvip, ct->ct_vip.ce_port, ct->ct_proto);

  if (0 == cvip->cvip_locks)
    {
      fib_table_entry_delete_index (cvip->cvip_fei, calico_fib_source);
      dpo_reset (&cvip->cvip_dpo);

      hash_free (cvip->cvip_translations);
      pool_put (calico_vip_pool, cvip);
    }

  return (0);
}

u32
calico_translate_update (const calico_endpoint_t * vip,
			 ip_protocol_t proto, const calico_endpoint_t * paths)
{
  const calico_endpoint_t *path;
  calico_translation_t *ct;
  calico_vip_tx_t *cvip;
  calico_ep_trk_t *trk;
  index_t cti, cvipi;
  fib_prefix_t pfx;

  /* do we know of this ep's vip */
  cvip = calico_vip_find (&vip->ce_ip);

  if (NULL == cvip)
    {
      pool_get_zero (calico_vip_pool, cvip);
      cvipi = cvip - calico_vip_pool;

      ip_address_copy (&cvip->cvip_ip, &vip->ce_ip);

      calico_vip_add (&vip->ce_ip, cvipi);

      ip_address_to_fib_prefix (&vip->ce_ip, &pfx);
      dpo_set (&cvip->cvip_dpo, calico_tx_dpo,
	       fib_proto_to_dpo (pfx.fp_proto), cvipi);

      cvip->cvip_fei = fib_table_entry_special_dpo_add
	(CALICO_FIB_TABLE,
	 &pfx,
	 calico_fib_source,
	 (FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT |
	  FIB_ENTRY_FLAG_EXCLUSIVE), &cvip->cvip_dpo);
    }

  cvip->cvip_locks++;
  cvipi = cvip - calico_vip_pool;

  ct = calico_vip_find_translation (cvip, vip->ce_port, proto);

  if (NULL == ct)
    {
      pool_get_zero (calico_translation_pool, ct);

      cti = ct - calico_translation_pool;
      clib_memcpy (&ct->ct_vip, vip, sizeof (*vip));
      ct->ct_proto = proto;
      ct->ct_vipi = cvipi;

      calico_vip_add_translation (cvip, ct->ct_vip.ce_port, ct->ct_proto,
				  cti);

      vlib_validate_combined_counter (&calico_translation_counters, cti);
      vlib_zero_combined_counter (&calico_translation_counters, cti);
    }

  cti = ct - calico_translation_pool;

  vec_foreach (trk, ct->ct_paths)
  {
    calico_tracker_release (trk);
  }

  vec_reset_length (ct->ct_paths);

  vec_foreach (path, paths)
  {
    vec_add2 (ct->ct_paths, trk, 1);

    calico_tracker_track (cti, path, trk);
  }

  calico_translation_stack (ct);

  return (cti);
}

static void
calico_client_db_remove (calico_client_rx_t * cc)
{
  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    hash_unset (calico_rx_db.crd_cip4, ip_addr_v4 (&cc->cc_ip).as_u32);
  else
    hash_unset_mem_free (&calico_rx_db.crd_cip6, &ip_addr_v6 (&cc->cc_ip));
}

static void
calico_client_destroy (index_t cci)
{
  calico_client_rx_t *cc;

  cc = calico_client_rx_get (cci);

  ASSERT (FIB_NODE_INDEX_INVALID != cc->cc_fei);
  ASSERT (fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
  fib_table_entry_delete_index (cc->cc_fei, calico_fib_source);
  ASSERT (!fib_entry_is_sourced (cc->cc_fei, calico_fib_source));
  calico_client_db_remove (cc);
  dpo_reset (&cc->cc_parent);
  pool_put (calico_client_pool, cc);
}

static void
calico_client_db_add (calico_client_rx_t * cc)
{
  index_t cci;

  cci = cc - calico_client_pool;

  if (ip_addr_version (&cc->cc_ip) == AF_IP4)
    hash_set (calico_rx_db.crd_cip4, ip_addr_v4 (&cc->cc_ip).as_u32, cci);
  else
    hash_set_mem_alloc (&calico_rx_db.crd_cip6,
			&ip_addr_v6 (&cc->cc_ip), cci);
}

void
calico_client_learn (const calico_client_learn_t * l)
{
  calico_client_rx_t *cc;

  /* check again if we need this */
  cc = (AF_IP4 == l->cl_af ?
	calico_client_ip4_find (&l->cl_ip.ip4) :
	calico_client_ip6_find (&l->cl_ip.ip6));

  if (NULL == cc)
    {
      dpo_id_t tmp = DPO_INVALID;
      fib_node_index_t fei;
      dpo_proto_t dproto;
      fib_prefix_t pfx;
      index_t cci;

      pool_get (calico_client_pool, cc);
      cc->cc_locks = 1;
      cci = cc - calico_client_pool;
      ip_addr_version (&cc->cc_ip) = l->cl_af;
      ip46_address_copy (&ip_addr_46 (&cc->cc_ip), &l->cl_ip);
      calico_client_db_add (cc);

      ip_address_to_fib_prefix (&cc->cc_ip, &pfx);

      dproto = fib_proto_to_dpo (pfx.fp_proto);
      dpo_set (&tmp, calico_rx_dpo, dproto, cci);
      dpo_stack (calico_rx_dpo, dproto, &cc->cc_parent,
		 drop_dpo_get (dproto));

      fei = fib_table_entry_special_dpo_add
	(CALICO_FIB_TABLE,
	 &pfx,
	 calico_fib_source,
	 (FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT | FIB_ENTRY_FLAG_INTERPOSE), &tmp);

      cc = pool_elt_at_index (calico_client_pool, cci);
      cc->cc_fei = fei;
    }
}

/**
 * Interpose a policy DPO
 */
static void
calico_client_rx_dpo_interpose (const dpo_id_t * original,
				const dpo_id_t * parent, dpo_id_t * clone)
{
  calico_client_rx_t *cc, *cc_clone;

  pool_get_zero (calico_client_pool, cc_clone);
  cc = calico_client_rx_get (original->dpoi_index);

  cc_clone->cc_fei = FIB_NODE_INDEX_INVALID;
  ip_address_copy (&cc_clone->cc_ip, &cc->cc_ip);

  /* stack the clone on the FIB provided parent */
  dpo_stack (calico_rx_dpo, original->dpoi_proto, &cc_clone->cc_parent,
	     parent);

  /* return the clone */
  dpo_set (clone,
	   calico_rx_dpo,
	   original->dpoi_proto, cc_clone - calico_client_pool);
}

void
calico_translate_walk (calico_translate_walk_cb_t cb, void *ctx)
{
  u32 api;

  /* *INDENT-OFF* */
  pool_foreach_index(api, calico_translation_pool,
  ({
    if (!cb(api, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

typedef struct calico_session_purge_walk_t_
{
  clib_bihash_kv_40_32_t *keys;
} calico_session_purge_walk_ctx_t;

static int
calico_session_purge_walk (BVT (clib_bihash_kv) * key, void *arg)
{
  calico_session_purge_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->keys, *key);

  return (BIHASH_WALK_CONTINUE);
}

int
calico_session_purge (void)
{
  /* flush all the session from the DB */
  calico_session_purge_walk_ctx_t ctx = { };
  clib_bihash_kv_40_32_t *key;

  BV (clib_bihash_foreach_key_value_pair) (&calico_session_db,
					   calico_session_purge_walk, &ctx);

  vec_foreach (key, ctx.keys)
    BV (clib_bihash_add_del) (&calico_session_db, key, 0);

  vec_free (ctx.keys);

  /* purge all the clients */
  void *ckey;
  index_t cci, *ccip, *ccis = NULL;

  /* *INDENT-OFF* */
  hash_foreach (ckey, cci, calico_rx_db.crd_cip4,
  ({
    vec_add1(ccis, cci);
  }));
  hash_foreach_mem (ckey, cci, calico_rx_db.crd_cip6,
  ({
    vec_add1(ccis, cci);
  }));
  /* *INDENT-ON* */

  vec_foreach (ccip, ccis) calico_client_destroy (*ccip);

  ASSERT (0 == hash_elts (calico_rx_db.crd_cip6));
  ASSERT (0 == hash_elts (calico_rx_db.crd_cip4));
  ASSERT (0 == pool_elts (calico_client_pool));

  vec_free (ccis);

  return (0);
}

static u8 *
format_calico_vip (u8 * s, va_list * args)
{
  index_t cvipi = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  calico_vip_tx_t *cvip = pool_elt_at_index (calico_vip_pool, cvipi);

  s = format (s, "[%d] calico-vip:[%U]", cvipi,
	      format_ip_address, &cvip->cvip_ip);

  return (s);
}

static u8 *
format_calico_client (u8 * s, va_list * args)
{
  index_t cci = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  calico_client_rx_t *cc = pool_elt_at_index (calico_client_pool, cci);

  s = format (s, "[%d] calico-client:[%U]", cci,
	      format_ip_address, &cc->cc_ip);
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_dpo_id, &cc->cc_parent, indent + 4);

  return (s);
}

static u8 *
format_calico_endpoint (u8 * s, va_list * args)
{
  calico_endpoint_t *cep = va_arg (*args, calico_endpoint_t *);

  s = format (s, "%U;%d", format_ip_address, &cep->ce_ip, cep->ce_port);

  return (s);
}

static u8 *
format_calico_ep_trk (u8 * s, va_list * args)
{
  calico_ep_trk_t *ck = va_arg (*args, calico_ep_trk_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%U", format_calico_endpoint, &ck->ct_ep);
  s = format (s, "\n%Ufib-entry:%d", format_white_space, indent, ck->ct_fei);
  s = format (s, "\n%U%U",
	      format_white_space, indent, format_dpo_id, &ck->ct_dpo, 6);

  return (s);
}

static u8 *
format_calico_translation (u8 * s, va_list * args)
{
  index_t cti = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  calico_translation_t *ct;
  calico_ep_trk_t *ck;

  ct = pool_elt_at_index (calico_translation_pool, cti);

  s = format (s, "[%d] ", cti);
  s = format (s, "%U %U", format_calico_endpoint, &ct->ct_vip,
	      format_ip_protocol, ct->ct_proto);

  vec_foreach (ck, ct->ct_paths)
    s = format (s, "\n%U%U",
		format_white_space, indent, format_calico_ep_trk, ck,
		indent + 2);

  s = format (s, "\n%U via:", format_white_space, indent);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &ct->ct_lb, indent + 2);

  return (s);
}

static u8 *
format_calico_vip_verbose (u8 * s, va_list * args)
{
  index_t cvipi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  index_t cti;
  u32 key;

  calico_vip_tx_t *cvip = pool_elt_at_index (calico_vip_pool, cvipi);

  s = format (s, "[%d] calico-vip:[%U]", cvipi,
	      format_ip_address, &cvip->cvip_ip);

  /* *INDENT-OFF* */
  hash_foreach(key, cti, cvip->cvip_translations,
  ({
    s = format (s, "\n%U%U", format_white_space, indent + 2,
                format_calico_translation, cti, indent + 4);
  }));
  /* *INDENT-ON* */

  return (s);
}

u8 *
format_calico_session (u8 * s, va_list * args)
{
  calico_session_t *sess = va_arg (*args, calico_session_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "session:[%U;%d -> %U;%d, %U, %U] => %U;%d lb:%d age:%f",
	      format_ip46_address, &sess->key.cs_ip[VLIB_RX], IP46_TYPE_ANY,
	      clib_host_to_net_u16 (sess->key.cs_port[VLIB_RX]),
	      format_ip46_address, &sess->key.cs_ip[VLIB_TX], IP46_TYPE_ANY,
	      clib_host_to_net_u16 (sess->key.cs_port[VLIB_TX]),
	      format_ip_protocol, sess->key.cs_proto,
	      format_vlib_rx_tx, sess->key.cs_dir,
	      format_ip46_address, &sess->value.cs_ip, IP46_TYPE_ANY,
	      clib_host_to_net_u16 (sess->value.cs_port),
	      sess->value.cs_lbi, sess->value.cs_timestamp);

  return (s);
}

static clib_error_t *
calico_vip_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cvi;

  cvi = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &cvi))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == cvi)
    {
      ip_address_t *ip;

      /* *INDENT-OFF* */
      hash_foreach(ip, cvi, calico_tx_db.ctd_vip,
      ({
        vlib_cli_output(vm, "%U", format_calico_vip_verbose, cvi, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cvi);
    }

  return (NULL);
}

static clib_error_t *
calico_client_show (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cci;

  cci = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &cci))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == cci)
    {
      ip4_address_t *ip4;
      ip6_address_t *ip6;

      /* *INDENT-OFF* */
      hash_foreach(ip4, cci, calico_rx_db.crd_cip4,
      ({
        vlib_cli_output(vm, "%U", format_calico_client, cci, 0);
      }));
      hash_foreach_mem (ip6, cci, calico_rx_db.crd_cip6,
      ({
        vlib_cli_output(vm, "%U", format_calico_client, cci, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cci);
    }

  return (NULL);
}

static clib_error_t *
calico_translation_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cti;

  cti = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &cti))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == cti)
    {
      /* *INDENT-OFF* */
      pool_foreach_index(cti, calico_translation_pool,
      ({
        vlib_cli_output(vm, "%U", format_calico_translation, cti, 1);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cti);
    }

  return (NULL);
}

static clib_error_t *
calico_session_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Calico Sessions: now:%f\n%U\n",
		   vlib_time_now (vm),
		   BV (format_bihash), &calico_session_db, 1);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_vip_show_cmd_node, static) = {
  .path = "show calico vip",
  .function = calico_vip_show,
  .short_help = "show calico vip <VIP>",
  .is_mp_safe = 1,
};
VLIB_CLI_COMMAND (calico_client_show_cmd_node, static) = {
  .path = "show calico client",
  .function = calico_client_show,
  .short_help = "show calico client",
  .is_mp_safe = 1,
};
VLIB_CLI_COMMAND (calico_translation_show_cmd_node, static) = {
  .path = "show calico translation",
  .function = calico_translation_show,
  .short_help = "show calico translation <VIP>",
  .is_mp_safe = 1,
};
VLIB_CLI_COMMAND (calico_session_show_cmd_node, static) = {
  .path = "show calico session",
  .function = calico_session_show,
  .short_help = "show calico session",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static fib_node_t *
calico_translation_get_node (fib_node_index_t index)
{
  calico_translation_t *ct = calico_translation_get (index);
  return (&(ct->ct_node));
}

static calico_translation_t *
calico_translation_get_from_node (fib_node_t * node)
{
  return ((calico_translation_t *) (((char *) node) -
				    STRUCT_OFFSET_OF (calico_translation_t,
						      ct_node)));
}

static void
calico_translation_last_lock_gone (fib_node_t * node)
{
  // calico_translation_destroy (calico_translation_get_from_node (node));
}

/*
 * A back walk has reached this ABF policy
 */
static fib_node_back_walk_rc_t
calico_translation_back_walk_notify (fib_node_t * node,
				     fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  calico_translation_t *ct = calico_translation_get_from_node (node);

  calico_translation_stack (ct);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The translation's graph node virtual function table
 */
static const fib_node_vft_t calico_translation_vft = {
  .fnv_get = calico_translation_get_node,
  .fnv_last_lock = calico_translation_last_lock_gone,
  .fnv_back_walk = calico_translation_back_walk_notify,
};

const static char *const calico_tx_dpo_ip4_nodes[] = {
  "ip4-calico-tx",
  NULL,
};

const static char *const calico_tx_dpo_ip6_nodes[] = {
  "ip6-calico-tx",
  NULL,
};

const static char *const *const calico_tx_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = calico_tx_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = calico_tx_dpo_ip6_nodes,
};

const static char *const calico_rx_dpo_ip4_nodes[] = {
  "ip4-calico-rx",
  NULL,
};

const static char *const calico_rx_dpo_ip6_nodes[] = {
  "ip6-calico-rx",
  NULL,
};

const static char *const *const calico_rx_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = calico_rx_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = calico_rx_dpo_ip6_nodes,
};

static void
calico_tx_dpo_lock (dpo_id_t * dpo)
{
}

static void
calico_tx_dpo_unlock (dpo_id_t * dpo)
{
}

u8 *
format_calico_tx_fib_dpo (u8 * s, va_list * ap)
{
  index_t cti = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "%U", format_calico_vip, cti, indent);

  return (s);
}

const static dpo_vft_t calico_tx_dpo_vft = {
  .dv_lock = calico_tx_dpo_lock,
  .dv_unlock = calico_tx_dpo_unlock,
  .dv_format = format_calico_tx_fib_dpo,
};

static void
calico_rx_dpo_lock (dpo_id_t * dpo)
{
  calico_client_rx_t *cc;

  cc = calico_client_rx_get (dpo->dpoi_index);

  cc->cc_locks++;
}

static void
calico_rx_dpo_unlock (dpo_id_t * dpo)
{
  calico_client_rx_t *cc;

  cc = calico_client_rx_get (dpo->dpoi_index);

  cc->cc_locks--;

  if (0 == cc->cc_locks)
    {
      ASSERT (cc->cc_fei == FIB_NODE_INDEX_INVALID);
      pool_put (calico_client_pool, cc);
    }
}

u8 *
format_calico_rx_fib_dpo (u8 * s, va_list * ap)
{
  index_t cci = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "%U", format_calico_client, cci, indent);

  return (s);
}

const static dpo_vft_t calico_rx_dpo_vft = {
  .dv_lock = calico_rx_dpo_lock,
  .dv_unlock = calico_rx_dpo_unlock,
  .dv_format = format_calico_rx_fib_dpo,
  .dv_mk_interpose = calico_client_rx_dpo_interpose,
};

static clib_error_t *
calico_translation_init (vlib_main_t * vm)
{
  calico_translation_fib_node_type =
    fib_node_register_new_type (&calico_translation_vft);

  calico_tx_dpo = dpo_register_new_type (&calico_tx_dpo_vft,
					 calico_tx_dpo_nodes);
  calico_rx_dpo = dpo_register_new_type (&calico_rx_dpo_vft,
					 calico_rx_dpo_nodes);

  calico_fib_source = fib_source_allocate ("calico",
					   FIB_SOURCE_PRIORITY_HI,
					   FIB_SOURCE_BH_SIMPLE);

  calico_tx_db.ctd_vip = hash_create_mem (0,
					  sizeof (ip_address_t),
					  sizeof (uword));
  calico_rx_db.crd_cip6 = hash_create_mem (0,
					   sizeof (ip6_address_t),
					   sizeof (uword));

  BV (clib_bihash_init) (&calico_session_db,
			 "Calico Session DB", 1000, 0xffff);
  BV (clib_bihash_set_kvp_format_fn) (&calico_session_db,
				      format_calico_session);

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_translation_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
