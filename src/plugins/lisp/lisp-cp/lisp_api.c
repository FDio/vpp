/*
 *------------------------------------------------------------------
 * lisp_api.c - lisp api
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
#include <lisp/lisp-cp/control.h>
#include <lisp/lisp-gpe/lisp_gpe.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <lisp/lisp-cp/lisp_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <lisp/lisp-cp/lisp.api_enum.h>
#include <lisp/lisp-cp/lisp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 lisp_base_msg_id;
#define REPLY_MSG_ID_BASE lisp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static locator_t *
unformat_lisp_locs (vl_api_remote_locator_t * rmt_locs, u32 rloc_num)
{
  u32 i;
  locator_t *locs = 0, loc;
  vl_api_remote_locator_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* remote locators */
      r = &rmt_locs[i];
      clib_memset (&loc, 0, sizeof (loc));
      ip_address_decode2 (&r->ip_address, &loc.address.ippref.addr);
      loc.address.ippref.len =
	ip_address_max_len (loc.address.ippref.addr.version);

      loc.priority = r->priority;
      loc.weight = r->weight;

      vec_add1 (locs, loc);
    }
  return locs;
}

static void
vl_api_lisp_add_del_locator_set_t_handler (vl_api_lisp_add_del_locator_set_t *
					   mp)
{
  vl_api_lisp_add_del_locator_set_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  locator_t locator;
  vl_api_local_locator_t *ls_loc;
  u32 ls_index = ~0, locator_num;
  u8 *locator_name = NULL;
  int i;

  clib_memset (a, 0, sizeof (a[0]));

  mp->locator_set_name[sizeof (mp->locator_set_name) - 1] = 0;
  locator_name = format (0, "%s", mp->locator_set_name);
  vec_terminate_c_string (locator_name);

  a->name = locator_name;
  a->is_add = mp->is_add;
  a->local = 1;
  locator_num = clib_net_to_host_u32 (mp->locator_num);

  clib_memset (&locator, 0, sizeof (locator));
  for (i = 0; i < locator_num; i++)
    {
      ls_loc = &mp->locators[i];
      VALIDATE_SW_IF_INDEX (ls_loc);

      locator.sw_if_index = htonl (ls_loc->sw_if_index);
      locator.priority = ls_loc->priority;
      locator.weight = ls_loc->weight;
      locator.local = 1;
      vec_add1 (a->locators, locator);
    }

  rv = vnet_lisp_add_del_locator_set (a, &ls_index);

  BAD_SW_IF_INDEX_LABEL;

  vec_free (locator_name);
  vec_free (a->locators);

  REPLY_MACRO2 (VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY,
  ({
    rmp->ls_index = clib_host_to_net_u32 (ls_index);
  }));
}

static void
vl_api_lisp_add_del_locator_t_handler (vl_api_lisp_add_del_locator_t * mp)
{
  vl_api_lisp_add_del_locator_reply_t *rmp;
  int rv = 0;
  locator_t locator, *locators = NULL;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  u32 ls_index = ~0;
  u8 *locator_name = NULL;

  clib_memset (&locator, 0, sizeof (locator));
  clib_memset (a, 0, sizeof (a[0]));

  locator.sw_if_index = ntohl (mp->sw_if_index);
  locator.priority = mp->priority;
  locator.weight = mp->weight;
  locator.local = 1;
  vec_add1 (locators, locator);

  mp->locator_set_name[sizeof (mp->locator_set_name) - 1] = 0;
  locator_name = format (0, "%s", mp->locator_set_name);
  vec_terminate_c_string (locator_name);

  a->name = locator_name;
  a->locators = locators;
  a->is_add = mp->is_add;
  a->local = 1;

  rv = vnet_lisp_add_del_locator (a, NULL, &ls_index);

  vec_free (locators);
  vec_free (locator_name);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_LOCATOR_REPLY);
}

static void
vl_api_lisp_add_del_local_eid_t_handler (vl_api_lisp_add_del_local_eid_t * mp)
{
  vl_api_lisp_add_del_local_eid_reply_t *rmp;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  int rv = 0;
  gid_address_t _gid, *gid = &_gid;
  uword *p = NULL;
  u32 locator_set_index = ~0, map_index = ~0;
  vnet_lisp_add_del_mapping_args_t _a, *a = &_a;
  u8 *name = NULL, *key = NULL;
  clib_memset (a, 0, sizeof (a[0]));
  clib_memset (gid, 0, sizeof (gid[0]));

  rv = unformat_lisp_eid_api (gid, mp->vni, &mp->eid);
  if (rv)
    goto out;

  mp->locator_set_name[sizeof (mp->locator_set_name) - 1] = 0;
  name = format (0, "%s", mp->locator_set_name);
  vec_terminate_c_string (name);
  p = hash_get_mem (lcm->locator_set_index_by_name, name);
  if (!p)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }
  locator_set_index = p[0];

  if (mp->key.id)
    key = format (0, "%s", mp->key.key);

  /* XXX treat batch configuration */
  a->is_add = mp->is_add;
  gid_address_copy (&a->eid, gid);
  a->locator_set_index = locator_set_index;
  a->local = 1;
  a->key = key;
  a->key_id = clib_net_to_host_u16 (mp->key.id);

  rv = vnet_lisp_add_del_local_mapping (a, &map_index);

out:
  vec_free (name);
  vec_free (key);
  gid_address_free (&a->eid);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY);
}

static void
  vl_api_lisp_eid_table_add_del_map_t_handler
  (vl_api_lisp_eid_table_add_del_map_t * mp)
{
  vl_api_lisp_eid_table_add_del_map_reply_t *rmp;
  int rv = 0;
  rv = vnet_lisp_eid_table_map (clib_net_to_host_u32 (mp->vni),
				clib_net_to_host_u32 (mp->dp_table),
				mp->is_l2, mp->is_add);
REPLY_MACRO (VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY)}

static void
vl_api_lisp_add_del_map_server_t_handler (vl_api_lisp_add_del_map_server_t
					  * mp)
{
  vl_api_lisp_add_del_map_server_reply_t *rmp;
  int rv = 0;
  ip_address_t addr;

  clib_memset (&addr, 0, sizeof (addr));

  ip_address_decode2 (&mp->ip_address, &addr);
  rv = vnet_lisp_add_del_map_server (&addr, mp->is_add);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY);
}

static void
vl_api_lisp_add_del_map_resolver_t_handler (vl_api_lisp_add_del_map_resolver_t
					    * mp)
{
  vl_api_lisp_add_del_map_resolver_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_map_resolver_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (a[0]));

  a->is_add = mp->is_add;
  ip_address_decode2 (&mp->ip_address, &a->address);

  rv = vnet_lisp_add_del_map_resolver (a);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY);
}

static void
  vl_api_lisp_map_register_enable_disable_t_handler
  (vl_api_lisp_map_register_enable_disable_t * mp)
{
  vl_api_lisp_map_register_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_map_register_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_lisp_rloc_probe_enable_disable_t_handler
  (vl_api_lisp_rloc_probe_enable_disable_t * mp)
{
  vl_api_lisp_rloc_probe_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_rloc_probe_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
vl_api_lisp_enable_disable_t_handler (vl_api_lisp_enable_disable_t * mp)
{
  vl_api_lisp_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_show_lisp_map_request_mode_t_handler
  (vl_api_show_lisp_map_request_mode_t * mp)
{
  int rv = 0;
  vl_api_show_lisp_map_request_mode_reply_t *rmp;

  REPLY_MACRO2(VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY,
  ({
    rmp->is_src_dst = vnet_lisp_get_map_request_mode ();
  }));
}

static void
vl_api_lisp_map_request_mode_t_handler (vl_api_lisp_map_request_mode_t * mp)
{
  vl_api_lisp_map_request_mode_reply_t *rmp;
  int rv = 0;

  rv = vnet_lisp_set_map_request_mode (mp->is_src_dst);

  REPLY_MACRO (VL_API_LISP_MAP_REQUEST_MODE_REPLY);
}

static void
vl_api_lisp_pitr_set_locator_set_t_handler (vl_api_lisp_pitr_set_locator_set_t
					    * mp)
{
  vl_api_lisp_pitr_set_locator_set_reply_t *rmp;
  int rv = 0;
  u8 *ls_name = 0;

  mp->ls_name[sizeof (mp->ls_name) - 1] = 0;
  ls_name = format (0, "%s", mp->ls_name);
  vec_terminate_c_string (ls_name);
  rv = vnet_lisp_pitr_set_locator_set (ls_name, mp->is_add);
  vec_free (ls_name);

  REPLY_MACRO (VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY);
}

static void
vl_api_lisp_use_petr_t_handler (vl_api_lisp_use_petr_t * mp)
{
  vl_api_lisp_use_petr_reply_t *rmp;
  int rv = 0;
  ip_address_t addr;

  ip_address_decode2 (&mp->ip_address, &addr);
  rv = vnet_lisp_use_petr (&addr, mp->is_add);

  REPLY_MACRO (VL_API_LISP_USE_PETR_REPLY);
}

static void
vl_api_show_lisp_use_petr_t_handler (vl_api_show_lisp_use_petr_t * mp)
{
  vl_api_show_lisp_use_petr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  int rv = 0;
  locator_t *loc = 0;
  u8 status = 0;
  gid_address_t addr;

  clib_memset (&addr, 0, sizeof (addr));
  status = lcm->flags & LISP_FLAG_USE_PETR;
  if (status)
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->petr_map_index);
      if (~0 != m->locator_set_index)
	{
	  ls =
	    pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);
	  loc = pool_elt_at_index (lcm->locator_pool, ls->locator_indices[0]);
	  gid_address_copy (&addr, &loc->address);
	}
    }

  REPLY_MACRO2 (VL_API_SHOW_LISP_USE_PETR_REPLY,
  {
    rmp->is_petr_enable = status;
    ip_address_encode2 (&gid_address_ip (&addr), &rmp->ip_address);
  });
}

static void
  vl_api_lisp_add_del_map_request_itr_rlocs_t_handler
  (vl_api_lisp_add_del_map_request_itr_rlocs_t * mp)
{
  vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *rmp;
  int rv = 0;
  u8 *locator_set_name = NULL;
  vnet_lisp_add_del_mreq_itr_rloc_args_t _a, *a = &_a;

  mp->locator_set_name[sizeof (mp->locator_set_name) - 1] = 0;
  locator_set_name = format (0, "%s", mp->locator_set_name);
  vec_terminate_c_string (locator_set_name);

  a->is_add = mp->is_add;
  a->locator_set_name = locator_set_name;

  rv = vnet_lisp_add_del_mreq_itr_rlocs (a);

  vec_free (locator_set_name);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY);
}

static void
  vl_api_lisp_add_del_remote_mapping_t_handler
  (vl_api_lisp_add_del_remote_mapping_t * mp)
{
  locator_t *rlocs = 0;
  vl_api_lisp_add_del_remote_mapping_reply_t *rmp;
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;
  u32 rloc_num = clib_net_to_host_u32 (mp->rloc_num);

  clib_memset (eid, 0, sizeof (eid[0]));

  rv = unformat_lisp_eid_api (eid, mp->vni, &mp->deid);
  if (rv)
    goto send_reply;

  rlocs = unformat_lisp_locs (mp->rlocs, rloc_num);

  if (!mp->is_add)
    {
      vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
      clib_memset (a, 0, sizeof (*a));
      gid_address_copy (&a->reid, eid);
      a->is_add = 0;
      rv = vnet_lisp_add_del_adjacency (a);
      if (rv)
	{
	  goto out;
	}
    }

  /* NOTE: for now this works as a static remote mapping, i.e.,
   * not authoritative and ttl infinite. */
  if (mp->is_add)
    {
      vnet_lisp_add_del_mapping_args_t _m_args, *m_args = &_m_args;
      clib_memset (m_args, 0, sizeof (m_args[0]));
      gid_address_copy (&m_args->eid, eid);
      m_args->action = mp->action;
      m_args->is_static = 1;
      m_args->ttl = ~0;
      m_args->authoritative = 0;
      rv = vnet_lisp_add_mapping (m_args, rlocs, NULL, NULL);
    }
  else
    {
      rv = vnet_lisp_del_mapping (eid, NULL);
    }

  if (mp->del_all)
    vnet_lisp_clear_all_remote_adjacencies ();

out:
  vec_free (rlocs);
send_reply:
  REPLY_MACRO (VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY);
}

static void
vl_api_lisp_add_del_adjacency_t_handler (vl_api_lisp_add_del_adjacency_t * mp)
{
  vl_api_lisp_add_del_adjacency_reply_t *rmp;
  vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;

  int rv = 0;
  clib_memset (a, 0, sizeof (a[0]));

  rv = unformat_lisp_eid_api (&a->leid, mp->vni, &mp->leid);
  rv = unformat_lisp_eid_api (&a->reid, mp->vni, &mp->reid);

  if (rv)
    goto send_reply;

  a->is_add = mp->is_add;
  rv = vnet_lisp_add_del_adjacency (a);

send_reply:
  REPLY_MACRO (VL_API_LISP_ADD_DEL_ADJACENCY_REPLY);
}

static void
send_lisp_locator_details (lisp_cp_main_t * lcm,
			   locator_t * loc, vl_api_registration_t * reg,
			   u32 context)
{
  vl_api_lisp_locator_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_LOCATOR_DETAILS + REPLY_MSG_ID_BASE);
  rmp->context = context;

  rmp->local = loc->local;
  if (loc->local)
    {
      rmp->sw_if_index = ntohl (loc->sw_if_index);
    }
  else
    {
      ip_address_encode2 (&gid_address_ip (&loc->address), &rmp->ip_address);
    }
  rmp->priority = loc->priority;
  rmp->weight = loc->weight;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_locator_dump_t_handler (vl_api_lisp_locator_dump_t * mp)
{
  u8 *ls_name = 0;
  vl_api_registration_t *reg = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = 0;
  locator_t *loc = 0;
  u32 ls_index = ~0, *locit = 0;
  uword *p = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->is_index_set)
    ls_index = htonl (mp->ls_index);
  else
    {
      /* make sure we get a proper C-string */
      mp->ls_name[sizeof (mp->ls_name) - 1] = 0;
      ls_name = format (0, "%s", mp->ls_name);
      vec_terminate_c_string (ls_name);
      p = hash_get_mem (lcm->locator_set_index_by_name, ls_name);
      if (!p)
	goto out;
      ls_index = p[0];
    }

  if (pool_is_free_index (lcm->locator_set_pool, ls_index))
    return;

  lsit = pool_elt_at_index (lcm->locator_set_pool, ls_index);

  vec_foreach (locit, lsit->locator_indices)
  {
    loc = pool_elt_at_index (lcm->locator_pool, locit[0]);
    send_lisp_locator_details (lcm, loc, reg, mp->context);
  };
out:
  vec_free (ls_name);
}

static void
send_lisp_locator_set_details (lisp_cp_main_t * lcm,
			       locator_set_t * lsit,
			       vl_api_registration_t * reg, u32 context,
			       u32 ls_index)
{
  vl_api_lisp_locator_set_details_t *rmp;
  u8 *str = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LISP_LOCATOR_SET_DETAILS + REPLY_MSG_ID_BASE);
  rmp->context = context;

  rmp->ls_index = htonl (ls_index);
  if (lsit->local)
    {
      ASSERT (lsit->name != NULL);
      uword name_len =
	clib_min (vec_len (lsit->name), ARRAY_LEN (rmp->ls_name) - 1);
      if (name_len)
	clib_memcpy_fast (rmp->ls_name, lsit->name, name_len);
      rmp->ls_name[name_len] = 0;
    }
  else
    {
      str = format (0, "<remote-%d>", ls_index);
      uword name_len = clib_min (vec_len (str), ARRAY_LEN (rmp->ls_name) - 1);
      if (name_len)
	clib_memcpy_fast (rmp->ls_name, str, name_len);
      rmp->ls_name[name_len] = 0;
      vec_free (str);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_locator_set_dump_t_handler (vl_api_lisp_locator_set_dump_t * mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = NULL;
  u8 filter;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter = mp->filter;
  pool_foreach (lsit, lcm->locator_set_pool)
   {
    if (filter && !((1 == filter && lsit->local) ||
                    (2 == filter && !lsit->local)))
      {
        continue;
      }
    send_lisp_locator_set_details (lcm, lsit, reg, mp->context,
                                   lsit - lcm->locator_set_pool);
  }
}

static void
send_lisp_eid_table_details (mapping_t * mapit,
			     vl_api_registration_t * reg, u32 context,
			     u8 filter)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *ls = 0;
  vl_api_lisp_eid_table_details_t *rmp = NULL;
  gid_address_t *gid = NULL;

  switch (filter)
    {
    case 0:			/* all mappings */
      break;

    case 1:			/* local only */
      if (!mapit->local)
	return;
      break;
    case 2:			/* remote only */
      if (mapit->local)
	return;
      break;
    default:
      clib_warning ("Filter error, unknown filter: %d", filter);
      return;
    }

  /* don't send PITR generated mapping */
  if (mapit->pitr_set)
    return;

  gid = &mapit->eid;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_DETAILS + REPLY_MSG_ID_BASE);

  ls = pool_elt_at_index (lcm->locator_set_pool, mapit->locator_set_index);
  if (vec_len (ls->locator_indices) == 0)
    rmp->locator_set_index = ~0;
  else
    rmp->locator_set_index = clib_host_to_net_u32 (mapit->locator_set_index);

  rmp->is_local = mapit->local;
  rmp->ttl = clib_host_to_net_u32 (mapit->ttl);
  rmp->action = mapit->action;
  rmp->authoritative = mapit->authoritative;
  switch (gid_address_type (gid))
    {
    case GID_ADDR_SRC_DST:
      lisp_fid_put_api (&rmp->seid, &gid_address_sd_src (gid));
      lisp_fid_put_api (&rmp->deid, &gid_address_sd_dst (gid));
      rmp->is_src_dst = 1;
      break;
    case GID_ADDR_IP_PREFIX:
      lisp_gid_put_api (&rmp->seid, gid);
      break;
    case GID_ADDR_MAC:
      lisp_gid_put_api (&rmp->seid, gid);
      break;
    default:
      ASSERT (0);
    }
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (gid_address_vni (gid));
  rmp->key.id = clib_host_to_net_u16 (mapit->key_id);
  memcpy (rmp->key.key, mapit->key, vec_len (mapit->key));
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_eid_table_dump_t_handler (vl_api_lisp_eid_table_dump_t * mp)
{
  u32 mi;
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *mapit = NULL;
  gid_address_t _eid, *eid = &_eid;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->eid_set)
    {
      clib_memset (eid, 0, sizeof (*eid));

      unformat_lisp_eid_api (eid, mp->vni, &mp->eid);

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
      if ((u32) ~ 0 == mi)
	return;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      send_lisp_eid_table_details (mapit, reg, mp->context,
				   0 /* ignore filter */ );
    }
  else
    {
      pool_foreach (mapit, lcm->mapping_pool)
       {
        send_lisp_eid_table_details(mapit, reg, mp->context,
                                    mp->filter);
      }
    }
}

static void
send_lisp_map_server_details (ip_address_t * ip, vl_api_registration_t * reg,
			      u32 context)
{
  vl_api_lisp_map_server_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LISP_MAP_SERVER_DETAILS + REPLY_MSG_ID_BASE);

  ip_address_encode2 (ip, &rmp->ip_address);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_map_server_dump_t_handler (vl_api_lisp_map_server_dump_t * mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (mr, lcm->map_servers)
  {
    send_lisp_map_server_details (&mr->address, reg, mp->context);
  }
}

static void
send_lisp_map_resolver_details (ip_address_t * ip,
				vl_api_registration_t * reg, u32 context)
{
  vl_api_lisp_map_resolver_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LISP_MAP_RESOLVER_DETAILS + REPLY_MSG_ID_BASE);

  ip_address_encode2 (ip, &rmp->ip_address);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_map_resolver_dump_t_handler (vl_api_lisp_map_resolver_dump_t * mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (mr, lcm->map_resolvers)
  {
    send_lisp_map_resolver_details (&mr->address, reg, mp->context);
  }
}

static void
send_eid_table_map_pair (hash_pair_t * p, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_lisp_eid_table_map_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LISP_EID_TABLE_MAP_DETAILS + REPLY_MSG_ID_BASE);

  rmp->vni = clib_host_to_net_u32 (p->key);
  rmp->dp_table = clib_host_to_net_u32 (p->value[0]);
  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lisp_eid_table_map_dump_t_handler (vl_api_lisp_eid_table_map_dump_t *
					  mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  hash_pair_t *p;
  uword *vni_table = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->is_l2)
    {
      vni_table = lcm->bd_id_by_vni;
    }
  else
    {
      vni_table = lcm->table_id_by_vni;
    }

  hash_foreach_pair (p, vni_table,
  ({
    send_eid_table_map_pair (p, reg, mp->context);
  }));
}

static void
send_eid_table_vni (u32 vni, vl_api_registration_t * reg, u32 context)
{
  vl_api_lisp_eid_table_vni_details_t *rmp = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LISP_EID_TABLE_VNI_DETAILS + REPLY_MSG_ID_BASE);
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (vni);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
lisp_adjacency_copy (vl_api_lisp_adjacency_t * dst, lisp_adjacency_t * adjs)
{
  lisp_adjacency_t *adj;
  vl_api_lisp_adjacency_t a;
  u32 i, n = vec_len (adjs);

  for (i = 0; i < n; i++)
    {
      adj = vec_elt_at_index (adjs, i);
      clib_memset (&a, 0, sizeof (a));

      lisp_gid_put_api (&a.reid, &adj->reid);
      lisp_gid_put_api (&a.leid, &adj->leid);

      dst[i] = a;
    }
}

static void
  vl_api_show_lisp_rloc_probe_state_t_handler
  (vl_api_show_lisp_rloc_probe_state_t * mp)
{
  vl_api_show_lisp_rloc_probe_state_reply_t *rmp = 0;
  int rv = 0;

  REPLY_MACRO2 (VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_rloc_probe_state_get ();
  });
}

static void
  vl_api_show_lisp_map_register_state_t_handler
  (vl_api_show_lisp_map_register_state_t * mp)
{
  vl_api_show_lisp_map_register_state_reply_t *rmp = 0;
  int rv = 0;

  REPLY_MACRO2 (VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_map_register_state_get ();
  });
}

static void
vl_api_lisp_adjacencies_get_t_handler (vl_api_lisp_adjacencies_get_t * mp)
{
  vl_api_lisp_adjacencies_get_reply_t *rmp = 0;
  lisp_adjacency_t *adjs = 0;
  int rv = 0;
  u32 size = ~0;
  u32 vni = clib_net_to_host_u32 (mp->vni);

  adjs = vnet_lisp_adjacencies_get_by_vni (vni);
  size = vec_len (adjs) * sizeof (vl_api_lisp_adjacency_t);

  REPLY_MACRO4 (VL_API_LISP_ADJACENCIES_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (vec_len (adjs));
    lisp_adjacency_copy (rmp->adjacencies, adjs);
  });

  vec_free (adjs);
}

static void
vl_api_lisp_eid_table_vni_dump_t_handler (vl_api_lisp_eid_table_vni_dump_t *
					  mp)
{
  hash_pair_t *p;
  u32 *vnis = 0;
  vl_api_registration_t *reg = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  hash_foreach_pair (p, lcm->table_id_by_vni,
  ({
    hash_set (vnis, p->key, 0);
  }));

  hash_foreach_pair (p, lcm->bd_id_by_vni,
  ({
    hash_set (vnis, p->key, 0);
  }));

  hash_foreach_pair (p, vnis,
  ({
    send_eid_table_vni (p->key, reg, mp->context);
  }));

  hash_free (vnis);
}

static void
vl_api_show_lisp_status_t_handler (vl_api_show_lisp_status_t * mp)
{
  vl_api_show_lisp_status_reply_t *rmp = NULL;
  int rv = 0;

  REPLY_MACRO2(VL_API_SHOW_LISP_STATUS_REPLY,
  ({
    rmp->is_gpe_enabled = vnet_lisp_gpe_enable_disable_status ();
    rmp->is_lisp_enabled = vnet_lisp_enable_disable_status ();
  }));
}

static void
  vl_api_lisp_get_map_request_itr_rlocs_t_handler
  (vl_api_lisp_get_map_request_itr_rlocs_t * mp)
{
  vl_api_lisp_get_map_request_itr_rlocs_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *loc_set = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  if (~0 == lcm->mreq_itr_rlocs)
    {
      tmp_str = format (0, " ");
    }
  else
    {
      loc_set =
	pool_elt_at_index (lcm->locator_set_pool, lcm->mreq_itr_rlocs);
      tmp_str = format (0, "%s", loc_set->name);
    }

  REPLY_MACRO2(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY,
  ({
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));

  vec_free (tmp_str);
}

static void
vl_api_show_lisp_pitr_t_handler (vl_api_show_lisp_pitr_t * mp)
{
  vl_api_show_lisp_pitr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  u8 is_enabled = (lcm->flags & LISP_FLAG_PITR_MODE)
    && lcm->pitr_map_index != ~0;

  if (!is_enabled)
    {
      tmp_str = format (0, "N/A");
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
      if (~0 != m->locator_set_index)
	{
	  ls =
	    pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);
	  tmp_str = format (0, "%s", ls->name);
	}
      else
	{
	  tmp_str = format (0, "N/A");
	}
    }
  vec_add1 (tmp_str, 0);

  REPLY_MACRO2(VL_API_SHOW_LISP_PITR_REPLY,
  ({
    rmp->is_enabled = lcm->flags & LISP_FLAG_PITR_MODE;
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
}

/*
 * lisp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#include <lisp/lisp-cp/lisp.api.c>

static clib_error_t *
lisp_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  lisp_base_msg_id = setup_message_id_table ();

  return NULL;
}

VLIB_API_INIT_FUNCTION (lisp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
