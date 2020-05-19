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

#include <calico/calico_translation.h>
#include <calico/calico_session.h>
#include <calico/calico_client.h>

calico_translation_t *calico_translation_pool;
clib_bihash_8_8_t calico_translation_db;

static fib_node_type_t calico_translation_fib_node_type;

vlib_combined_counter_main_t calico_translation_counters = {
  .name = "calico-translation",
  .stat_segment_name = "/net/calico-translation",
};

static void
calico_tracker_release (calico_ep_trk_t * trk)
{
  fib_entry_untrack (trk->ct_fei, trk->ct_sibling);
}

static void
calico_tracker_track (index_t cti,
		      const calico_endpoint_tuple_t * path,
		      calico_ep_trk_t * trk)
{
  fib_prefix_t pfx;

  ip_address_to_fib_prefix (&path->dst_ep.ce_ip, &pfx);

  clib_memcpy (&trk->ct_ep[VLIB_TX], &path->dst_ep,
	       sizeof (trk->ct_ep[VLIB_TX]));
  clib_memcpy (&trk->ct_ep[VLIB_RX], &path->src_ep,
	       sizeof (trk->ct_ep[VLIB_RX]));

  trk->ct_fei = fib_entry_track (CALICO_FIB_TABLE,
				 &pfx,
				 calico_translation_fib_node_type,
				 cti, &trk->ct_sibling);

  fib_entry_contribute_forwarding (trk->ct_fei,
				   fib_forw_chain_type_from_fib_proto
				   (pfx.fp_proto), &trk->ct_dpo);
}

void
calico_add_translation (index_t cci, u16 port, ip_protocol_t proto,
			index_t cti)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;

  key = (proto << 16) | port;
  key = key << 32 | (u32) cci;

  bkey.key = key;
  bkey.value = cti;

  clib_bihash_add_del_8_8 (&calico_translation_db, &bkey, 1);
}

void
calico_remove_translation (index_t cci, u16 port, ip_protocol_t proto)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;

  key = (proto << 16) | port;
  key = key << 32 | (u32) cci;

  bkey.key = key;

  clib_bihash_add_del_8_8 (&calico_translation_db, &bkey, 0);
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
  dpo_stack (calico_client_dpo, dproto, &ct->ct_lb, &ct->ct_lb);
}

int
calico_translation_delete (u32 id)
{
  calico_translation_t *ct;
  calico_ep_trk_t *trk;

  if (pool_is_free_index (calico_translation_pool, id))
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  ct = pool_elt_at_index (calico_translation_pool, id);

  dpo_reset (&ct->ct_lb);

  vec_foreach (trk, ct->ct_paths) calico_tracker_release (trk);

  pool_put (calico_translation_pool, ct);


  calico_client_remove_translation (ct->ct_cci, ct->ct_vip.ce_port,
				    ct->ct_proto);

  return (0);
}

u32
calico_translation_update (const calico_endpoint_t * vip,
			   ip_protocol_t proto,
			   const calico_endpoint_tuple_t * paths, u8 flags)
{
  const calico_endpoint_tuple_t *path;
  const calico_client_t *cc;
  calico_translation_t *ct;
  calico_ep_trk_t *trk;
  index_t cti, cci;

  /* do we know of this ep's vip */
  cci = calico_client_add (&vip->ce_ip, flags);
  cc = calico_client_get (cci);

  ct = calico_find_translation (cc->parent_cci, vip->ce_port, proto);

  if (NULL == ct)
    {
      pool_get_zero (calico_translation_pool, ct);

      cti = ct - calico_translation_pool;
      clib_memcpy (&ct->ct_vip, vip, sizeof (*vip));
      ct->ct_proto = proto;
      ct->ct_cci = cci;

      calico_client_add_translation (cci, ct->ct_vip.ce_port, ct->ct_proto,
				     cti);

      vlib_validate_combined_counter (&calico_translation_counters, cti);
      vlib_zero_combined_counter (&calico_translation_counters, cti);
    }
  ct->flags = flags;
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

void
calico_translation_walk (calico_translation_walk_cb_t cb, void *ctx)
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

static u8 *
format_calico_ep_trk (u8 * s, va_list * args)
{
  calico_ep_trk_t *ck = va_arg (*args, calico_ep_trk_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%U->%U", format_calico_endpoint, &ck->ct_ep[VLIB_RX],
	      format_calico_endpoint, &ck->ct_ep[VLIB_TX]);
  s = format (s, "\n%Ufib-entry:%d", format_white_space, indent, ck->ct_fei);
  s = format (s, "\n%U%U",
	      format_white_space, indent, format_dpo_id, &ck->ct_dpo, 6);

  return (s);
}

u8 *
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


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_translation_show_cmd_node, static) = {
  .path = "show calico translation",
  .function = calico_translation_show,
  .short_help = "show calico translation <VIP>",
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
 /**/}

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

static clib_error_t *
calico_translation_cli_add_del (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  u32 del_index = INDEX_INVALID;
  ip_protocol_t proto = IP_PROTOCOL_TCP;
  calico_endpoint_t vip;
  u8 flags = CALICO_FLAG_EXCLUSIVE;
  calico_endpoint_tuple_t tmp, *paths = NULL, *path;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	del_index = INDEX_INVALID;
      else if (unformat (input, "del %d", &del_index))
	;
      else if (unformat (input, "proto %U", unformat_ip_protocol, &proto))
	;
      else if (unformat (input, "vip %U", unformat_calico_ep, &vip))
	flags = CALICO_FLAG_EXCLUSIVE;
      else if (unformat (input, "real %U", unformat_calico_ep, &vip))
	flags = 0;
      else if (unformat (input, "to %U", unformat_calico_ep_tuple, &tmp))
	{
	  pool_get (paths, path);
	  clib_memcpy (path, &tmp, sizeof (calico_endpoint_tuple_t));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == del_index)
    calico_translation_update (&vip, proto, paths, flags);
  else
    calico_translation_delete (del_index);

  pool_free (paths);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_translation_cli_add_del_command, static) =
{
  .path = "calico translation",
  .short_help = "calico translation [add|del] proto [TCP|UDP] [vip|real] [ip] [port] [to [ip] [port]->[ip] [port]]",
  .function = calico_translation_cli_add_del,
};
/* *INDENT-ON* */

static clib_error_t *
calico_translation_init (vlib_main_t * vm)
{
  calico_main_t *cm = &calico_main;
  calico_translation_fib_node_type =
    fib_node_register_new_type (&calico_translation_vft);

  clib_bihash_init_8_8 (&calico_translation_db, "Calico translation DB",
			cm->translation_hash_buckets,
			cm->translation_hash_memory);

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
