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

#include <cnat/cnat_translation.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>

cnat_translation_t *cnat_translation_pool;
clib_bihash_8_8_t cnat_translation_db;

static fib_node_type_t cnat_translation_fib_node_type;

vlib_combined_counter_main_t cnat_translation_counters = {
  .name = "cnat-translation",
  .stat_segment_name = "/net/cnat-translation",
};

static void
cnat_tracker_release (cnat_ep_trk_t * trk)
{
  fib_entry_untrack (trk->ct_fei, trk->ct_sibling);
}

static void
cnat_tracker_track (index_t cti,
		    const cnat_endpoint_tuple_t * path, cnat_ep_trk_t * trk)
{
  fib_prefix_t pfx;

  ip_address_to_fib_prefix (&path->dst_ep.ce_ip, &pfx);

  clib_memcpy (&trk->ct_ep[VLIB_TX], &path->dst_ep,
	       sizeof (trk->ct_ep[VLIB_TX]));
  clib_memcpy (&trk->ct_ep[VLIB_RX], &path->src_ep,
	       sizeof (trk->ct_ep[VLIB_RX]));

  trk->ct_fei = fib_entry_track (CNAT_FIB_TABLE,
				 &pfx,
				 cnat_translation_fib_node_type,
				 cti, &trk->ct_sibling);

  fib_entry_contribute_forwarding (trk->ct_fei,
				   fib_forw_chain_type_from_fib_proto
				   (pfx.fp_proto), &trk->ct_dpo);
}

void
cnat_add_translation_to_db (index_t cci, u16 port, ip_protocol_t proto,
			    index_t cti)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;

  key = (proto << 16) | port;
  key = key << 32 | (u32) cci;

  bkey.key = key;
  bkey.value = cti;

  clib_bihash_add_del_8_8 (&cnat_translation_db, &bkey, 1);
}

void
cnat_remove_translation_from_db (index_t cci, u16 port, ip_protocol_t proto)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;

  key = (proto << 16) | port;
  key = key << 32 | (u32) cci;

  bkey.key = key;

  clib_bihash_add_del_8_8 (&cnat_translation_db, &bkey, 0);
}

static void
cnat_translation_stack (cnat_translation_t * ct)
{
  fib_protocol_t fproto;
  cnat_ep_trk_t *trk;
  dpo_proto_t dproto;
  index_t lbi;

  fproto = ip_address_family_to_fib_proto (ct->ct_vip.ce_ip.version);
  dproto = fib_proto_to_dpo (fproto);

  lbi = load_balance_create (vec_len (ct->ct_paths),
			     fib_proto_to_dpo (fproto), IP_FLOW_HASH_DEFAULT);

  vec_foreach (trk, ct->ct_paths)
    load_balance_set_bucket (lbi, trk - ct->ct_paths, &trk->ct_dpo);

  dpo_set (&ct->ct_lb, DPO_LOAD_BALANCE, dproto, lbi);
  dpo_stack (cnat_client_dpo, dproto, &ct->ct_lb, &ct->ct_lb);
}

int
cnat_translation_delete (u32 id)
{
  cnat_translation_t *ct;
  cnat_ep_trk_t *trk;

  if (pool_is_free_index (cnat_translation_pool, id))
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  ct = pool_elt_at_index (cnat_translation_pool, id);

  dpo_reset (&ct->ct_lb);

  vec_foreach (trk, ct->ct_paths) cnat_tracker_release (trk);

  cnat_remove_translation_from_db (ct->ct_cci, ct->ct_vip.ce_port,
				   ct->ct_proto);
  cnat_client_translation_deleted (ct->ct_cci);
  pool_put (cnat_translation_pool, ct);

  return (0);
}

u32
cnat_translation_update (const cnat_endpoint_t * vip,
			 ip_protocol_t proto,
			 const cnat_endpoint_tuple_t * paths, u8 flags)
{
  const cnat_endpoint_tuple_t *path;
  const cnat_client_t *cc;
  cnat_translation_t *ct;
  cnat_ep_trk_t *trk;
  index_t cci;

  cnat_lazy_init ();

  /* do we know of this ep's vip */
  cci = cnat_client_add (&vip->ce_ip, flags);
  cc = cnat_client_get (cci);

  ct = cnat_find_translation (cc->parent_cci, vip->ce_port, proto);

  if (NULL == ct)
    {
      pool_get_zero (cnat_translation_pool, ct);

      clib_memcpy (&ct->ct_vip, vip, sizeof (*vip));
      ct->ct_proto = proto;
      ct->ct_cci = cci;
      ct->index = ct - cnat_translation_pool;

      cnat_add_translation_to_db (cci, ct->ct_vip.ce_port, ct->ct_proto,
				  ct->index);
      cnat_client_translation_added (cci);

      vlib_validate_combined_counter (&cnat_translation_counters, ct->index);
      vlib_zero_combined_counter (&cnat_translation_counters, ct->index);
    }
  ct->flags = flags;

  vec_foreach (trk, ct->ct_paths)
  {
    cnat_tracker_release (trk);
  }

  vec_reset_length (ct->ct_paths);

  vec_foreach (path, paths)
  {
    vec_add2 (ct->ct_paths, trk, 1);

    cnat_tracker_track (ct->index, path, trk);
  }

  cnat_translation_stack (ct);

  return (ct->index);
}

void
cnat_translation_walk (cnat_translation_walk_cb_t cb, void *ctx)
{
  u32 api;

  /* *INDENT-OFF* */
  pool_foreach_index(api, cnat_translation_pool,
  ({
    if (!cb(api, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static u8 *
format_cnat_ep_trk (u8 * s, va_list * args)
{
  cnat_ep_trk_t *ck = va_arg (*args, cnat_ep_trk_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%U->%U", format_cnat_endpoint, &ck->ct_ep[VLIB_RX],
	      format_cnat_endpoint, &ck->ct_ep[VLIB_TX]);
  s = format (s, "\n%Ufib-entry:%d", format_white_space, indent, ck->ct_fei);
  s = format (s, "\n%U%U",
	      format_white_space, indent, format_dpo_id, &ck->ct_dpo, 6);

  return (s);
}

u8 *
format_cnat_translation (u8 * s, va_list * args)
{
  cnat_translation_t *ct = va_arg (*args, cnat_translation_t *);
  cnat_ep_trk_t *ck;

  s = format (s, "[%d] ", ct->index);
  s = format (s, "%U %U", format_cnat_endpoint, &ct->ct_vip,
	      format_ip_protocol, ct->ct_proto);

  vec_foreach (ck, ct->ct_paths)
    s = format (s, "\n%U", format_cnat_ep_trk, ck, 2);

  /* If printing a trace, the LB object might be deleted */
  if (!pool_is_free_index (load_balance_pool, ct->ct_lb.dpoi_index))
    {
      s = format (s, "\n via:");
      s = format (s, "\n%U%U",
		  format_white_space, 2, format_dpo_id, &ct->ct_lb, 2);
    }

  return (s);
}

static clib_error_t *
cnat_translation_show (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cti;
  cnat_translation_t *ct;

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
      pool_foreach_index(cti, cnat_translation_pool,
      ({
	ct = pool_elt_at_index (cnat_translation_pool, cti);
        vlib_cli_output(vm, "%U", format_cnat_translation, ct);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cti);
    }

  return (NULL);
}

int
cnat_translation_purge (void)
{
  /* purge all the translations */
  index_t tri, *trp, *trs = NULL;

  /* *INDENT-OFF* */
  pool_foreach_index(tri, cnat_translation_pool,
  ({
    vec_add1(trs, tri);
  }));
  /* *INDENT-ON* */

  vec_foreach (trp, trs) cnat_translation_delete (*trp);

  ASSERT (0 == pool_elts (cnat_translation_pool));

  vec_free (trs);

  return (0);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cnat_translation_show_cmd_node, static) = {
  .path = "show cnat translation",
  .function = cnat_translation_show,
  .short_help = "show cnat translation <VIP>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static fib_node_t *
cnat_translation_get_node (fib_node_index_t index)
{
  cnat_translation_t *ct = cnat_translation_get (index);
  return (&(ct->ct_node));
}

static cnat_translation_t *
cnat_translation_get_from_node (fib_node_t * node)
{
  return ((cnat_translation_t *) (((char *) node) -
				  STRUCT_OFFSET_OF (cnat_translation_t,
						    ct_node)));
}

static void
cnat_translation_last_lock_gone (fib_node_t * node)
{
 /**/}

/*
 * A back walk has reached this ABF policy
 */
static fib_node_back_walk_rc_t
cnat_translation_back_walk_notify (fib_node_t * node,
				   fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  cnat_translation_t *ct = cnat_translation_get_from_node (node);

  cnat_translation_stack (ct);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The translation's graph node virtual function table
 */
static const fib_node_vft_t cnat_translation_vft = {
  .fnv_get = cnat_translation_get_node,
  .fnv_last_lock = cnat_translation_last_lock_gone,
  .fnv_back_walk = cnat_translation_back_walk_notify,
};

static clib_error_t *
cnat_translation_cli_add_del (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  u32 del_index = INDEX_INVALID;
  ip_protocol_t proto = IP_PROTOCOL_TCP;
  cnat_endpoint_t vip;
  u8 flags = CNAT_FLAG_EXCLUSIVE;
  cnat_endpoint_tuple_t tmp, *paths = NULL, *path;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	del_index = INDEX_INVALID;
      else if (unformat (input, "del %d", &del_index))
	;
      else if (unformat (input, "proto %U", unformat_ip_protocol, &proto))
	;
      else if (unformat (input, "vip %U", unformat_cnat_ep, &vip))
	flags = CNAT_FLAG_EXCLUSIVE;
      else if (unformat (input, "real %U", unformat_cnat_ep, &vip))
	flags = 0;
      else if (unformat (input, "to %U", unformat_cnat_ep_tuple, &tmp))
	{
	  pool_get (paths, path);
	  clib_memcpy (path, &tmp, sizeof (cnat_endpoint_tuple_t));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == del_index)
    cnat_translation_update (&vip, proto, paths, flags);
  else
    cnat_translation_delete (del_index);

  pool_free (paths);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cnat_translation_cli_add_del_command, static) =
{
  .path = "cnat translation",
  .short_help = "cnat translation [add|del] proto [TCP|UDP] [vip|real] [ip] [port] [to [ip] [port]->[ip] [port]]",
  .function = cnat_translation_cli_add_del,
};
/* *INDENT-ON* */

static clib_error_t *
cnat_translation_init (vlib_main_t * vm)
{
  cnat_main_t *cm = &cnat_main;
  cnat_translation_fib_node_type =
    fib_node_register_new_type (&cnat_translation_vft);

  clib_bihash_init_8_8 (&cnat_translation_db, "CNat translation DB",
			cm->translation_hash_buckets,
			cm->translation_hash_memory);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_translation_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
