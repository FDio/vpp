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
#include <cnat/cnat_maglev.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>

cnat_translation_t *cnat_translation_pool;
clib_bihash_8_8_t cnat_translation_db;
addr_resolution_t *tr_resolutions;
cnat_if_addr_add_cb_t *cnat_if_addr_add_cbs;

static fib_node_type_t cnat_translation_fib_node_type;

vlib_combined_counter_main_t cnat_translation_counters = {
  .name = "cnat-translation",
  .stat_segment_name = "/net/cnat-translation",
};

void
cnat_translation_watch_addr (index_t cti, u64 opaque, cnat_endpoint_t * ep,
			     cnat_addr_resol_type_t type)
{
  addr_resolution_t *ar;

  if (INDEX_INVALID == ep->ce_sw_if_index)
    return;

  pool_get (tr_resolutions, ar);
  ar->af = ep->ce_ip.version;
  ar->sw_if_index = ep->ce_sw_if_index;
  ar->type = type;
  ar->opaque = opaque;
  ar->cti = cti;
}

static void
cnat_resolve_ep_tuple (cnat_endpoint_tuple_t * path)
{
  cnat_resolve_ep (&path->src_ep);
  cnat_resolve_ep (&path->dst_ep);
}

void
cnat_translation_unwatch_addr (u32 cti, cnat_addr_resol_type_t type)
{
  /* Delete tr resolution entries matching translation index */
  addr_resolution_t *ar;
  index_t *indexes = 0, *ari;
  pool_foreach (ar, tr_resolutions)
    {
      if ((cti == INDEX_INVALID || ar->cti == cti) &&
	  (ar->type == type || CNAT_RESOLV_ADDR_ANY == type))
	vec_add1 (indexes, ar - tr_resolutions);
    }
  vec_foreach (ari, indexes) pool_put_index (tr_resolutions, *ari);

  vec_free (indexes);
}

static void
cnat_tracker_release (cnat_ep_trk_t * trk)
{
  /* We only track fully resolved endpoints */
  if (!(trk->ct_flags & CNAT_TRK_ACTIVE))
    return;
  fib_entry_untrack (trk->ct_fei, trk->ct_sibling);
}

static void
cnat_tracker_track (index_t cti, cnat_ep_trk_t * trk)
{
  fib_prefix_t pfx;
  /* We only track fully resolved endpoints */
  if (trk->ct_ep[VLIB_TX].ce_flags & CNAT_EP_FLAG_RESOLVED &&
      trk->ct_ep[VLIB_RX].ce_flags & CNAT_EP_FLAG_RESOLVED)
    trk->ct_flags |= CNAT_TRK_ACTIVE;
  else
    {
      trk->ct_flags &= ~CNAT_TRK_ACTIVE;
      return;
    }

  ip_address_to_fib_prefix (&trk->ct_ep[VLIB_TX].ce_ip, &pfx);
  trk->ct_fei = fib_entry_track (CNAT_FIB_TABLE,
				 &pfx,
				 cnat_translation_fib_node_type,
				 cti, &trk->ct_sibling);

  fib_entry_contribute_forwarding (trk->ct_fei,
				   fib_forw_chain_type_from_fib_proto
				   (pfx.fp_proto), &trk->ct_dpo);
}

u8 *
format_cnat_lb_type (u8 *s, va_list *args)
{
  cnat_lb_type_t lb_type = va_arg (*args, int);
  if (CNAT_LB_DEFAULT == lb_type)
    s = format (s, "default");
  else if (CNAT_LB_MAGLEV == lb_type)
    s = format (s, "maglev");
  else
    s = format (s, "unknown");
  return (s);
}

uword
unformat_cnat_lb_type (unformat_input_t *input, va_list *args)
{
  cnat_lb_type_t *a = va_arg (*args, cnat_lb_type_t *);
  if (unformat (input, "default"))
    *a = CNAT_LB_DEFAULT;
  else if (unformat (input, "maglev"))
    *a = CNAT_LB_MAGLEV;
  else
    return 0;
  return 1;
}

/**
 * Add a translation to the bihash
 *
 * @param cci the ID of the parent client (invalid if vip not resolved)
 * @param vip the translation endpoint
 * @param proto the translation proto
 * @param cti the translation index to be used as value
 */
static void
cnat_add_translation_to_db (index_t cci, cnat_endpoint_t * vip,
			    ip_protocol_t proto, index_t cti)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;
  if (INDEX_INVALID == cci)
    {
      key = proto << 8 | 0x80 | vip->ce_ip.version;
      key = key << 16 | vip->ce_port;
      key = key << 32 | (u32) vip->ce_sw_if_index;
    }
  else
    {
      key = proto << 8;
      key = key << 16 | vip->ce_port;
      key = key << 32 | (u32) cci;
    }

  bkey.key = key;
  bkey.value = cti;

  clib_bihash_add_del_8_8 (&cnat_translation_db, &bkey, 1);
}

/**
 * Remove a translation from the bihash
 *
 * @param cci the ID of the parent client
 * @param vip the translation endpoint
 * @param proto the translation proto
 */
static void
cnat_remove_translation_from_db (index_t cci, cnat_endpoint_t * vip,
				 ip_protocol_t proto)
{
  clib_bihash_kv_8_8_t bkey;
  u64 key;
  if (INDEX_INVALID == cci)
    {
      key = proto << 8 | 0x80 | vip->ce_ip.version;
      key = key << 16 | vip->ce_port;
      key = key << 32 | (u32) vip->ce_sw_if_index;
    }
  else
    {
      key = proto << 8;
      key = key << 16 | vip->ce_port;
      key = key << 32 | (u32) cci;
    }

  bkey.key = key;

  clib_bihash_add_del_8_8 (&cnat_translation_db, &bkey, 0);
}



static void
cnat_translation_stack (cnat_translation_t * ct)
{
  fib_protocol_t fproto;
  cnat_ep_trk_t *trk;
  dpo_proto_t dproto;
  u32 ep_idx = 0;
  index_t lbi;

  fproto = ip_address_family_to_fib_proto (ct->ct_vip.ce_ip.version);
  dproto = fib_proto_to_dpo (fproto);

  vec_reset_length (ct->ct_active_paths);

  vec_foreach (trk, ct->ct_paths)
    if (trk->ct_flags & CNAT_TRK_ACTIVE)
      vec_add1 (ct->ct_active_paths, *trk);

  lbi = load_balance_create (vec_len (ct->ct_active_paths),
			     fib_proto_to_dpo (fproto), IP_FLOW_HASH_DEFAULT);

  ep_idx = 0;
  vec_foreach (trk, ct->ct_active_paths)
    load_balance_set_bucket (lbi, ep_idx++, &trk->ct_dpo);

  if (ep_idx > 0 && CNAT_LB_MAGLEV == ct->lb_type)
    cnat_translation_init_maglev (ct);

  dpo_set (&ct->ct_lb, DPO_LOAD_BALANCE, dproto, lbi);
  dpo_stack (cnat_client_dpo, dproto, &ct->ct_lb, &ct->ct_lb);
  ct->flags |= CNAT_TRANSLATION_STACKED;
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

  vec_foreach (trk, ct->ct_active_paths)
    cnat_tracker_release (trk);

  cnat_remove_translation_from_db (ct->ct_cci, &ct->ct_vip, ct->ct_proto);
  cnat_client_translation_deleted (ct->ct_cci);
  cnat_translation_unwatch_addr (id, CNAT_RESOLV_ADDR_ANY);
  pool_put (cnat_translation_pool, ct);

  return (0);
}

u32
cnat_translation_update (cnat_endpoint_t *vip, ip_protocol_t proto,
			 cnat_endpoint_tuple_t *paths, u8 flags,
			 cnat_lb_type_t lb_type)
{
  cnat_endpoint_tuple_t *path;
  const cnat_client_t *cc;
  cnat_translation_t *ct;
  cnat_ep_trk_t *trk;
  index_t cci;

  cnat_lazy_init ();
  if (cnat_resolve_ep (vip))
    {
      /* vip only contains a sw_if_index for now */
      ct = cnat_find_translation (vip->ce_sw_if_index, vip->ce_port, proto);
      cci = INDEX_INVALID;
    }
  else
    {
      /* do we know of this ep's vip */
      cci = cnat_client_add (&vip->ce_ip, flags);
      cc = cnat_client_get (cci);

      ct = cnat_find_translation (cc->parent_cci, vip->ce_port, proto);
    }

  if (NULL == ct)
    {
      pool_get_zero (cnat_translation_pool, ct);

      clib_memcpy (&ct->ct_vip, vip, sizeof (*vip));
      ct->ct_proto = proto;
      ct->ct_cci = cci;
      ct->index = ct - cnat_translation_pool;
      ct->lb_type = lb_type;

      cnat_add_translation_to_db (cci, vip, proto, ct->index);
      cnat_client_translation_added (cci);

      vlib_validate_combined_counter (&cnat_translation_counters, ct->index);
      vlib_zero_combined_counter (&cnat_translation_counters, ct->index);
    }
  ct->flags = flags;

  cnat_translation_unwatch_addr (ct->index, CNAT_RESOLV_ADDR_ANY);
  cnat_translation_watch_addr (ct->index, 0, vip,
			       CNAT_RESOLV_ADDR_TRANSLATION);

  vec_foreach (trk, ct->ct_paths)
  {
    cnat_tracker_release (trk);
  }

  vec_reset_length (ct->ct_paths);
  ct->flags &= ~CNAT_TRANSLATION_STACKED;

  u64 path_idx = 0;
  vec_foreach (path, paths)
  {
    cnat_resolve_ep_tuple (path);
    cnat_translation_watch_addr (ct->index,
				 path_idx << 32 | VLIB_RX, &path->src_ep,
				 CNAT_RESOLV_ADDR_BACKEND);
    cnat_translation_watch_addr (ct->index,
				 path_idx << 32 | VLIB_TX, &path->dst_ep,
				 CNAT_RESOLV_ADDR_BACKEND);
    path_idx++;

    vec_add2 (ct->ct_paths, trk, 1);

    clib_memcpy (&trk->ct_ep[VLIB_TX], &path->dst_ep,
		 sizeof (trk->ct_ep[VLIB_TX]));
    clib_memcpy (&trk->ct_ep[VLIB_RX], &path->src_ep,
		 sizeof (trk->ct_ep[VLIB_RX]));
    trk->ct_flags = path->ep_flags;

    cnat_tracker_track (ct->index, trk);
  }

  cnat_translation_stack (ct);

  return (ct->index);
}

void
cnat_translation_walk (cnat_translation_walk_cb_t cb, void *ctx)
{
  u32 api;

  pool_foreach_index (api, cnat_translation_pool)
   {
    if (!cb(api, ctx))
      break;
  }
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
  cnat_main_t *cm = &cnat_main;
  cnat_ep_trk_t *ck;

  s = format (s, "[%d] ", ct->index);
  s = format (s, "%U %U ", format_cnat_endpoint, &ct->ct_vip,
	      format_ip_protocol, ct->ct_proto);
  s = format (s, "lb:%U ", format_cnat_lb_type, ct->lb_type);

  vec_foreach (ck, ct->ct_paths)
    s = format (s, "\n%U", format_cnat_ep_trk, ck, 2);

  /* If printing a trace, the LB object might be deleted */
  if (!pool_is_free_index (load_balance_pool, ct->ct_lb.dpoi_index))
    {
      s = format (s, "\n via:");
      s = format (s, "\n%U%U",
		  format_white_space, 2, format_dpo_id, &ct->ct_lb, 2);
    }

  u32 bid = 0;
  if (CNAT_LB_MAGLEV == ct->lb_type)
    {
      s = format (s, "\nmaglev backends map");
      uword *bitmap = NULL;
      clib_bitmap_alloc (bitmap, cm->maglev_len);
      vec_foreach (ck, ct->ct_paths)
	{
	  clib_bitmap_zero (bitmap);
	  for (u32 i = 0; i < vec_len (ct->lb_maglev); i++)
	    if (ct->lb_maglev[i] == bid)
	      clib_bitmap_set (bitmap, i, 1);
	  s = format (s, "\n  backend#%d: %U", bid, format_bitmap_hex, bitmap);

	  bid++;
	}
      clib_bitmap_free (bitmap);
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
      pool_foreach_index (cti, cnat_translation_pool)
       {
	ct = pool_elt_at_index (cnat_translation_pool, cti);
        vlib_cli_output(vm, "%U", format_cnat_translation, ct);
      }
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

  pool_foreach_index (tri, cnat_translation_pool)
   {
    vec_add1(trs, tri);
  }

  vec_foreach (trp, trs) cnat_translation_delete (*trp);

  ASSERT (0 == pool_elts (cnat_translation_pool));

  vec_free (trs);

  return (0);
}

VLIB_CLI_COMMAND (cnat_translation_show_cmd_node, static) = {
  .path = "show cnat translation",
  .function = cnat_translation_show,
  .short_help = "show cnat translation <VIP>",
  .is_mp_safe = 1,
};

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

  /* If we have more than FIB_PATH_LIST_POPULAR paths
   * we might get called during path tracking
   * (cnat_tracker_track) */
  if (!(ct->flags & CNAT_TRANSLATION_STACKED))
    return (FIB_NODE_BACK_WALK_CONTINUE);

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
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *e = 0;
  cnat_lb_type_t lb_type;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	del_index = INDEX_INVALID;
      else if (unformat (line_input, "del %d", &del_index))
	;
      else
	if (unformat (line_input, "proto %U", unformat_ip_protocol, &proto))
	;
      else if (unformat (line_input, "vip %U", unformat_cnat_ep, &vip))
	flags = CNAT_FLAG_EXCLUSIVE;
      else if (unformat (line_input, "real %U", unformat_cnat_ep, &vip))
	flags = 0;
      else if (unformat (line_input, "to %U", unformat_cnat_ep_tuple, &tmp))
	{
	  vec_add2 (paths, path, 1);
	  clib_memcpy (path, &tmp, sizeof (cnat_endpoint_tuple_t));
	}
      else if (unformat (line_input, "%U", unformat_cnat_lb_type, &lb_type))
	;
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	  goto done;
	}
    }

  if (INDEX_INVALID == del_index)
    cnat_translation_update (&vip, proto, paths, flags, lb_type);
  else
    cnat_translation_delete (del_index);

done:
  vec_free (paths);
  unformat_free (line_input);
  return (e);
}

VLIB_CLI_COMMAND (cnat_translation_cli_add_del_command, static) =
{
  .path = "cnat translation",
  .short_help = "cnat translation [add|del] proto [TCP|UDP] [vip|real] [ip|sw_if_index [v6]] [port] [to [ip|sw_if_index [v6]] [port]->[ip|sw_if_index [v6]] [port]]",
  .function = cnat_translation_cli_add_del,
};

static void
cnat_if_addr_add_del_translation_cb (addr_resolution_t * ar,
				     ip_address_t * address, u8 is_del)
{
  cnat_translation_t *ct;
  ct = cnat_translation_get (ar->cti);
  if (!is_del && ct->ct_vip.ce_flags & CNAT_EP_FLAG_RESOLVED)
    return;

  cnat_remove_translation_from_db (ct->ct_cci, &ct->ct_vip, ct->ct_proto);

  if (is_del)
    {
      ct->ct_vip.ce_flags &= ~CNAT_EP_FLAG_RESOLVED;
      ct->ct_cci = INDEX_INVALID;
      cnat_client_translation_deleted (ct->ct_cci);
      /* Are there remaining addresses ? */
      if (0 == cnat_resolve_addr (ar->sw_if_index, ar->af, address))
	is_del = 0;
    }

  if (!is_del)
    {
      ct->ct_cci = cnat_client_add (address, ct->flags);
      cnat_client_translation_added (ct->ct_cci);
      ip_address_copy (&ct->ct_vip.ce_ip, address);
      ct->ct_vip.ce_flags |= CNAT_EP_FLAG_RESOLVED;
    }

  cnat_add_translation_to_db (ct->ct_cci, &ct->ct_vip, ct->ct_proto,
			      ct->index);
}

static void
cnat_if_addr_add_del_backend_cb (addr_resolution_t * ar,
				 ip_address_t * address, u8 is_del)
{
  cnat_translation_t *ct;
  cnat_ep_trk_t *trk;
  cnat_endpoint_t *ep;

  u8 direction = ar->opaque & 0xf;
  u32 path_idx = ar->opaque >> 32;

  ct = cnat_translation_get (ar->cti);

  trk = &ct->ct_paths[path_idx];
  ep = &trk->ct_ep[direction];

  if (!is_del && ep->ce_flags & CNAT_EP_FLAG_RESOLVED)
    return;

  ASSERT (ep->ce_sw_if_index == ar->sw_if_index);

  if (is_del)
    {
      ep->ce_flags &= ~CNAT_EP_FLAG_RESOLVED;
      /* Are there remaining addresses ? */
      if (0 == cnat_resolve_addr (ar->sw_if_index, ar->af, address))
	is_del = 0;
    }

  if (!is_del)
    {
      ip_address_copy (&ep->ce_ip, address);
      ep->ce_flags |= CNAT_EP_FLAG_RESOLVED;
    }

  ct->flags &= ~CNAT_TRANSLATION_STACKED;
  cnat_tracker_track (ar->cti, trk);

  cnat_translation_stack (ct);
  ct->flags |= CNAT_TRANSLATION_STACKED;
}

static void
cnat_if_addr_add_del_callback (u32 sw_if_index, ip_address_t * address,
			       u8 is_del)
{
  addr_resolution_t *ar;
  pool_foreach (ar, tr_resolutions)
    {
      if (ar->sw_if_index != sw_if_index)
	continue;
      if (ar->af != ip_addr_version (address))
	continue;
      cnat_if_addr_add_cbs[ar->type](ar, address, is_del);
    }
}

static void
cnat_ip6_if_addr_add_del_callback (struct ip6_main_t *im,
				   uword opaque, u32 sw_if_index,
				   ip6_address_t * address,
				   u32 address_length, u32 if_address_index,
				   u32 is_del)
{
  ip_address_t addr;
  ip_address_set (&addr, address, AF_IP6);
  cnat_if_addr_add_del_callback (sw_if_index, &addr, is_del);
}

static void
cnat_ip4_if_addr_add_del_callback (struct ip4_main_t *im,
				   uword opaque, u32 sw_if_index,
				   ip4_address_t * address,
				   u32 address_length, u32 if_address_index,
				   u32 is_del)
{
  ip_address_t addr;
  ip_address_set (&addr, address, AF_IP4);
  cnat_if_addr_add_del_callback (sw_if_index, &addr, is_del);
}

void
cnat_translation_register_addr_add_cb (cnat_addr_resol_type_t typ,
				       cnat_if_addr_add_cb_t fn)
{
  vec_validate (cnat_if_addr_add_cbs, CNAT_ADDR_N_RESOLUTIONS);
  cnat_if_addr_add_cbs[typ] = fn;
}

static clib_error_t *
cnat_translation_init (vlib_main_t * vm)
{
  ip4_main_t *i4m = &ip4_main;
  ip6_main_t *i6m = &ip6_main;
  cnat_main_t *cm = &cnat_main;
  cnat_translation_fib_node_type =
    fib_node_register_new_type ("cnat-translation", &cnat_translation_vft);

  clib_bihash_init_8_8 (&cnat_translation_db, "CNat translation DB",
			cm->translation_hash_buckets,
			cm->translation_hash_memory);

  ip4_add_del_interface_address_callback_t cb4 = { 0 };
  cb4.function = cnat_ip4_if_addr_add_del_callback;
  vec_add1 (i4m->add_del_interface_address_callbacks, cb4);

  ip6_add_del_interface_address_callback_t cb6 = { 0 };
  cb6.function = cnat_ip6_if_addr_add_del_callback;
  vec_add1 (i6m->add_del_interface_address_callbacks, cb6);

  cnat_translation_register_addr_add_cb (CNAT_RESOLV_ADDR_BACKEND,
					 cnat_if_addr_add_del_backend_cb);
  cnat_translation_register_addr_add_cb (CNAT_RESOLV_ADDR_TRANSLATION,
					 cnat_if_addr_add_del_translation_cb);

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
