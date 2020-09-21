/*
 *------------------------------------------------------------------
 * lisp_gpe_api.c - lisp_gpe api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <lisp/lisp-gpe/lisp_gpe.h>
#include <lisp/lisp-gpe/lisp_gpe_adjacency.h>
#include <lisp/lisp-gpe/lisp_gpe_tunnel.h>
#include <lisp/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <lisp/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <lisp/lisp-gpe/lisp_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <lisp/lisp-gpe/lisp_gpe.api_enum.h>
#include <lisp/lisp-gpe/lisp_gpe.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 gpe_base_msg_id;
#define REPLY_MSG_ID_BASE gpe_base_msg_id

#include <vlibapi/api_helper_macros.h>

static locator_pair_t *
unformat_gpe_loc_pairs (void *locs, u32 rloc_num)
{
  u32 i;
  locator_pair_t *pairs = 0, pair, *p;
  vl_api_gpe_locator_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* local locator */
      r = &((vl_api_gpe_locator_t *) locs)[i];
      clib_memset (&pair, 0, sizeof (pair));
      ip_address_decode2 (&r->addr, &pair.lcl_loc);

      pair.weight = r->weight;
      vec_add1 (pairs, pair);
    }

  for (i = rloc_num; i < rloc_num * 2; i++)
    {
      /* remote locators */
      r = &((vl_api_gpe_locator_t *) locs)[i];
      p = &pairs[i - rloc_num];
      ip_address_decode2 (&r->addr, &p->rmt_loc);
    }
  return pairs;
}

static void
  gpe_fwd_entry_path_dump_t_net_to_host
  (vl_api_gpe_fwd_entry_path_dump_t * mp)
{
  mp->fwd_entry_index = clib_net_to_host_u32 (mp->fwd_entry_index);
}

static void
lisp_api_set_locator (vl_api_gpe_locator_t * loc,
		      const ip_address_t * addr, u8 weight)
{
  loc->weight = weight;
  ip_address_encode2 (addr, &loc->addr);
}

static void
  vl_api_gpe_fwd_entry_path_dump_t_handler
  (vl_api_gpe_fwd_entry_path_dump_t * mp)
{
  lisp_fwd_path_t *path;
  vl_api_gpe_fwd_entry_path_details_t *rmp = NULL;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  vl_api_registration_t *reg;
  lisp_gpe_fwd_entry_t *lfe;

  gpe_fwd_entry_path_dump_t_net_to_host (mp);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (pool_is_free_index (lgm->lisp_fwd_entry_pool, mp->fwd_entry_index))
    return;

  lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, mp->fwd_entry_index);

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
    return;

  vec_foreach (path, lfe->paths)
  {
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    clib_memset (rmp, 0, sizeof (*rmp));
    const lisp_gpe_tunnel_t *lgt;

    rmp->_vl_msg_id =
      clib_host_to_net_u16 (VL_API_GPE_FWD_ENTRY_PATH_DETAILS);

    const lisp_gpe_adjacency_t *ladj =
      lisp_gpe_adjacency_get (path->lisp_adj);
    lisp_api_set_locator (&rmp->rmt_loc, &ladj->remote_rloc, path->weight);
    lgt = lisp_gpe_tunnel_get (ladj->tunnel_index);
    lisp_api_set_locator (&rmp->lcl_loc, &lgt->key->lcl, path->weight);

    rmp->context = mp->context;
    vl_api_send_msg (reg, (u8 *) rmp);
  }
}

static void
gpe_fwd_entries_copy (vl_api_gpe_fwd_entry_t * dst,
		      lisp_api_gpe_fwd_entry_t * src)
{
  lisp_api_gpe_fwd_entry_t *e;
  u32 i = 0;

  vec_foreach (e, src)
  {
    clib_memset (&dst[i], 0, sizeof (*dst));
    dst[i].dp_table = e->dp_table;
    dst[i].fwd_entry_index = e->fwd_entry_index;
    dst[i].vni = e->vni;
    dst[i].action = e->action;
    switch (fid_addr_type (&e->leid))
      {
      case FID_ADDR_IP_PREF:
	dst[i].leid.type = EID_TYPE_API_PREFIX;
	dst[i].reid.type = EID_TYPE_API_PREFIX;
	ip_prefix_encode2 (&fid_addr_ippref (&e->leid),
			   &dst[i].leid.address.prefix);
	ip_prefix_encode2 (&fid_addr_ippref (&e->reid),
			   &dst[i].reid.address.prefix);
	break;
      case FID_ADDR_MAC:
	mac_address_encode ((mac_address_t *) fid_addr_mac (&e->leid),
			    dst[i].leid.address.mac);
	mac_address_encode ((mac_address_t *) fid_addr_mac (&e->reid),
			    dst[i].reid.address.mac);
	dst[i].leid.type = EID_TYPE_API_MAC;
	dst[i].reid.type = EID_TYPE_API_MAC;
	break;
      default:
	clib_warning ("unknown fid type %d!", fid_addr_type (&e->leid));
	break;
      }
    i++;
  }
}

static void
gpe_fwd_entries_get_t_net_to_host (vl_api_gpe_fwd_entries_get_t * mp)
{
  mp->vni = clib_net_to_host_u32 (mp->vni);
}

static void
gpe_entry_t_host_to_net (vl_api_gpe_fwd_entry_t * e)
{
  e->fwd_entry_index = clib_host_to_net_u32 (e->fwd_entry_index);
  e->dp_table = clib_host_to_net_u32 (e->dp_table);
  e->vni = clib_host_to_net_u32 (e->vni);
}

static void
  gpe_fwd_entries_get_reply_t_host_to_net
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  u32 i;
  vl_api_gpe_fwd_entry_t *e;

  for (i = 0; i < mp->count; i++)
    {
      e = &mp->entries[i];
      gpe_entry_t_host_to_net (e);
    }
  mp->count = clib_host_to_net_u32 (mp->count);
}

static void
vl_api_gpe_fwd_entry_vnis_get_t_handler (vl_api_gpe_fwd_entry_vnis_get_t * mp)
{
  vl_api_gpe_fwd_entry_vnis_get_reply_t *rmp = 0;
  hash_pair_t *p;
  u32 i = 0;
  int rv = 0;

  u32 *vnis = vnet_lisp_gpe_get_fwd_entry_vnis ();
  u32 size = hash_elts (vnis) * sizeof (u32);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (hash_elts (vnis));
    hash_foreach_pair (p, vnis,
    ({
      rmp->vnis[i++] = clib_host_to_net_u32 (p->key);
    }));
  });
  /* *INDENT-ON* */

  hash_free (vnis);
}

static void
vl_api_gpe_fwd_entries_get_t_handler (vl_api_gpe_fwd_entries_get_t * mp)
{
  lisp_api_gpe_fwd_entry_t *e;
  vl_api_gpe_fwd_entries_get_reply_t *rmp = 0;
  u32 size = 0;
  int rv = 0;

  gpe_fwd_entries_get_t_net_to_host (mp);

  e = vnet_lisp_gpe_fwd_entries_get_by_vni (mp->vni);
  size = vec_len (e) * sizeof (vl_api_gpe_fwd_entry_t);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_GPE_FWD_ENTRIES_GET_REPLY, size,
  {
    rmp->count = vec_len (e);
    gpe_fwd_entries_copy (rmp->entries, e);
    gpe_fwd_entries_get_reply_t_host_to_net (rmp);
  });
  /* *INDENT-ON* */

  vec_free (e);
}

static void
gpe_add_del_fwd_entry_t_net_to_host (vl_api_gpe_add_del_fwd_entry_t * mp)
{
  mp->vni = clib_net_to_host_u32 (mp->vni);
  mp->dp_table = clib_net_to_host_u32 (mp->dp_table);
  mp->loc_num = clib_net_to_host_u32 (mp->loc_num);
}

static void
vl_api_gpe_add_del_fwd_entry_t_handler (vl_api_gpe_add_del_fwd_entry_t * mp)
{
  vl_api_gpe_add_del_fwd_entry_reply_t *rmp;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  locator_pair_t *pairs = 0;
  int rv = 0;

  gpe_add_del_fwd_entry_t_net_to_host (mp);
  clib_memset (a, 0, sizeof (a[0]));

  rv = unformat_lisp_eid_api (&a->rmt_eid, mp->vni, &mp->rmt_eid);
  rv |= unformat_lisp_eid_api (&a->lcl_eid, mp->vni, &mp->lcl_eid);

  if (mp->loc_num % 2 != 0)
    {
      rv = -1;
      goto send_reply;
    }
  pairs = unformat_gpe_loc_pairs (mp->locs, mp->loc_num / 2);

  if (rv)
    goto send_reply;

  a->is_add = mp->is_add;
  a->locator_pairs = pairs;
  a->dp_table = mp->dp_table;
  a->vni = mp->vni;
  a->action = mp->action;
  if (mp->loc_num == 0)
    a->is_negative = 1;

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, 0);
  vec_free (pairs);
send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY,
  {
    rmp->fwd_entry_index = clib_host_to_net_u32 (a->fwd_entry_index);
  });
  /* *INDENT-ON* */
}

static void
vl_api_gpe_enable_disable_t_handler (vl_api_gpe_enable_disable_t * mp)
{
  vl_api_gpe_enable_disable_reply_t *rmp;
  int rv = 0;
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;

  a->is_en = mp->is_enable;
  vnet_lisp_gpe_enable_disable (a);

  REPLY_MACRO (VL_API_GPE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_gpe_add_del_iface_t_handler (vl_api_gpe_add_del_iface_t * mp)
{
  vl_api_gpe_add_del_iface_reply_t *rmp;
  int rv = 0;
  u32 vni, dp_table;

  vni = clib_net_to_host_u32 (mp->vni);
  dp_table = clib_net_to_host_u32 (mp->dp_table);

  if (mp->is_l2)
    {
      if (mp->is_add)
	{
	  if (~0 == lisp_gpe_tenant_l2_iface_add_or_lock (vni, dp_table))
	    rv = 1;
	}
      else
	lisp_gpe_tenant_l2_iface_unlock (vni);
    }
  else
    {
      if (mp->is_add)
	{
	  if (~0 == lisp_gpe_tenant_l3_iface_add_or_lock (vni, dp_table, 1))
	    rv = 1;
	}
      else
	lisp_gpe_tenant_l3_iface_unlock (vni);
    }

  REPLY_MACRO (VL_API_GPE_ADD_DEL_IFACE_REPLY);
}

static void
vl_api_gpe_set_encap_mode_t_handler (vl_api_gpe_set_encap_mode_t * mp)
{
  vl_api_gpe_set_encap_mode_reply_t *rmp;
  int rv = 0;

  rv = vnet_gpe_set_encap_mode (mp->is_vxlan);
  REPLY_MACRO (VL_API_GPE_SET_ENCAP_MODE_REPLY);
}

static void
vl_api_gpe_get_encap_mode_t_handler (vl_api_gpe_get_encap_mode_t * mp)
{
  vl_api_gpe_get_encap_mode_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_GPE_GET_ENCAP_MODE_REPLY,
  ({
    rmp->encap_mode = vnet_gpe_get_encap_mode ();
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_gpe_add_del_native_fwd_rpath_t_handler
  (vl_api_gpe_add_del_native_fwd_rpath_t * mp)
{
  vl_api_gpe_add_del_native_fwd_rpath_reply_t *rmp;
  vnet_gpe_native_fwd_rpath_args_t _a, *a = &_a;
  int rv = 0;

  clib_memset (a, 0, sizeof (a[0]));

  if (mp->nh_addr.af)
    clib_memcpy (&a->rpath.frp_addr.ip6, mp->nh_addr.un.ip6,
		 sizeof (ip6_address_t));
  else
    clib_memcpy (&a->rpath.frp_addr.ip4, mp->nh_addr.un.ip4,
		 sizeof (ip4_address_t));

  a->is_add = mp->is_add;
  a->rpath.frp_proto = mp->nh_addr.af ? DPO_PROTO_IP6 : DPO_PROTO_IP4;
  a->rpath.frp_fib_index =
    fib_table_find (dpo_proto_to_fib (a->rpath.frp_proto),
		    clib_net_to_host_u32 (mp->table_id));
  if (~0 == a->rpath.frp_fib_index)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  a->rpath.frp_sw_if_index = clib_net_to_host_u32 (mp->nh_sw_if_index);
  a->rpath.frp_weight = 1;

  rv = vnet_gpe_add_del_native_fwd_rpath (a);
done:
  REPLY_MACRO (VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY);
}

static void
gpe_native_fwd_rpaths_copy (vl_api_gpe_native_fwd_rpath_t * dst,
			    fib_route_path_t * src)
{
  fib_route_path_t *e;
  fib_table_t *table;
  u32 i = 0;

  vec_foreach (e, src)
  {
    clib_memset (&dst[i], 0, sizeof (*dst));
    table = fib_table_get (e->frp_fib_index, dpo_proto_to_fib (e->frp_proto));
    dst[i].fib_index = table->ft_table_id;
    dst[i].nh_sw_if_index = e->frp_sw_if_index;
    ip_address_encode (&e->frp_addr, IP46_TYPE_ANY, &dst[i].nh_addr);
    i++;
  }
}

static void
gpe_native_fwd_rpath_t_host_to_net (vl_api_gpe_native_fwd_rpath_t * e)
{
  e->fib_index = clib_host_to_net_u32 (e->fib_index);
  e->nh_sw_if_index = clib_host_to_net_u32 (e->nh_sw_if_index);
}

static void
  gpe_native_fwd_rpaths_get_reply_t_host_to_net
  (vl_api_gpe_native_fwd_rpaths_get_reply_t * mp)
{
  u32 i;
  vl_api_gpe_native_fwd_rpath_t *e;

  for (i = 0; i < mp->count; i++)
    {
      e = &mp->entries[i];
      gpe_native_fwd_rpath_t_host_to_net (e);
    }
  mp->count = clib_host_to_net_u32 (mp->count);
}

static void
vl_api_gpe_native_fwd_rpaths_get_t_handler (vl_api_gpe_native_fwd_rpaths_get_t
					    * mp)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  vl_api_gpe_native_fwd_rpaths_get_reply_t *rmp;
  u32 size = 0;
  int rv = 0;

  u8 rpath_index = mp->is_ip4 ? 1 : 0;

  size = vec_len (lgm->native_fwd_rpath[rpath_index])
    * sizeof (vl_api_gpe_native_fwd_rpath_t);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY, size,
  {
    rmp->count = vec_len (lgm->native_fwd_rpath[rpath_index]);
    gpe_native_fwd_rpaths_copy (rmp->entries,
				lgm->native_fwd_rpath[rpath_index]);
    gpe_native_fwd_rpaths_get_reply_t_host_to_net (rmp);
  });
  /* *INDENT-ON* */
}

/*
 * lisp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#include <lisp/lisp-gpe/lisp_gpe.api.c>

static clib_error_t *
gpe_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  gpe_base_msg_id = setup_message_id_table ();

  return NULL;
}

VLIB_API_INIT_FUNCTION (gpe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
