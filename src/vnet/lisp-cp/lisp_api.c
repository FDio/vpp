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
#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

#include <vnet/vnet_msg_enum.h>

#define vl_api_remote_locator_t_endian vl_noop_handler
#define vl_api_remote_locator_t_print vl_noop_handler
#define vl_api_local_locator_t_endian vl_noop_handler
#define vl_api_local_locator_t_print vl_noop_handler

#define vl_api_lisp_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_lisp_add_del_locator_set_t_print vl_noop_handler
#define vl_api_lisp_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_lisp_add_del_remote_mapping_t_print vl_noop_handler

#define vl_api_one_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_one_add_del_locator_set_t_print vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_print vl_noop_handler

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(LISP_ADD_DEL_LOCATOR_SET, lisp_add_del_locator_set)                   \
_(LISP_ADD_DEL_LOCATOR, lisp_add_del_locator)                           \
_(LISP_ADD_DEL_LOCAL_EID, lisp_add_del_local_eid)                       \
_(LISP_ADD_DEL_MAP_RESOLVER, lisp_add_del_map_resolver)                 \
_(LISP_ADD_DEL_MAP_SERVER, lisp_add_del_map_server)                     \
_(LISP_ENABLE_DISABLE, lisp_enable_disable)                             \
_(LISP_RLOC_PROBE_ENABLE_DISABLE, lisp_rloc_probe_enable_disable)       \
_(LISP_MAP_REGISTER_ENABLE_DISABLE, lisp_map_register_enable_disable)   \
_(LISP_ADD_DEL_REMOTE_MAPPING, lisp_add_del_remote_mapping)             \
_(LISP_ADD_DEL_ADJACENCY, lisp_add_del_adjacency)                       \
_(LISP_PITR_SET_LOCATOR_SET, lisp_pitr_set_locator_set)                 \
_(LISP_MAP_REQUEST_MODE, lisp_map_request_mode)                         \
_(LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map)               \
_(LISP_LOCATOR_SET_DUMP, lisp_locator_set_dump)                         \
_(LISP_LOCATOR_DUMP, lisp_locator_dump)                                 \
_(LISP_EID_TABLE_DUMP, lisp_eid_table_dump)                             \
_(LISP_MAP_RESOLVER_DUMP, lisp_map_resolver_dump)                       \
_(LISP_MAP_SERVER_DUMP, lisp_map_server_dump)                           \
_(LISP_EID_TABLE_MAP_DUMP, lisp_eid_table_map_dump)                     \
_(LISP_EID_TABLE_VNI_DUMP, lisp_eid_table_vni_dump)                     \
_(LISP_ADJACENCIES_GET, lisp_adjacencies_get)                           \
_(SHOW_LISP_RLOC_PROBE_STATE, show_lisp_rloc_probe_state)               \
_(SHOW_LISP_MAP_REGISTER_STATE, show_lisp_map_register_state)           \
_(SHOW_LISP_STATUS, show_lisp_status)                                   \
_(LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS,                                   \
  lisp_add_del_map_request_itr_rlocs)                                   \
_(LISP_GET_MAP_REQUEST_ITR_RLOCS, lisp_get_map_request_itr_rlocs)       \
_(SHOW_LISP_PITR, show_lisp_pitr)                                       \
_(SHOW_LISP_MAP_REQUEST_MODE, show_lisp_map_request_mode)               \
_(LISP_USE_PETR, lisp_use_petr)                                         \
_(SHOW_LISP_USE_PETR, show_lisp_use_petr)                               \

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
      gid_address_ip_set (&loc.address, &r->addr, r->is_ip4 ? IP4 : IP6);

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

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY,
  ({
    rmp->ls_index = clib_host_to_net_u32 (ls_index);
  }));
  /* *INDENT-ON* */
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

static int
unformat_lisp_eid_api (gid_address_t * dst, u32 vni, u8 type, void *src,
		       u8 len)
{
  switch (type)
    {
    case 0:			/* ipv4 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP4);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 1:			/* ipv6 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP6);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 2:			/* l2 mac */
      gid_address_type (dst) = GID_ADDR_MAC;
      clib_memcpy (&gid_address_mac (dst), src, 6);
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = vni;

  return 0;
}

static void
vl_api_lisp_add_del_local_eid_t_handler (vl_api_lisp_add_del_local_eid_t * mp)
{
  vl_api_lisp_add_del_local_eid_reply_t *rmp;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;
  uword *p = NULL;
  u32 locator_set_index = ~0, map_index = ~0;
  vnet_lisp_add_del_mapping_args_t _a, *a = &_a;
  u8 *name = NULL, *key = NULL;
  clib_memset (a, 0, sizeof (a[0]));
  clib_memset (eid, 0, sizeof (eid[0]));

  rv = unformat_lisp_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->eid, mp->prefix_len);
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

  if (*mp->key)
    key = format (0, "%s", mp->key);

  /* XXX treat batch configuration */
  a->is_add = mp->is_add;
  gid_address_copy (&a->eid, eid);
  a->locator_set_index = locator_set_index;
  a->local = 1;
  a->key = key;
  a->key_id = clib_net_to_host_u16 (mp->key_id);

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

  ip_address_set (&addr, mp->ip_address, mp->is_ipv6 ? IP6 : IP4);
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
  ip_address_set (&a->address, mp->ip_address, mp->is_ipv6 ? IP6 : IP4);

  rv = vnet_lisp_add_del_map_resolver (a);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY);
}

static void
  vl_api_lisp_map_register_enable_disable_t_handler
  (vl_api_lisp_map_register_enable_disable_t * mp)
{
  vl_api_lisp_map_register_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_map_register_enable_disable (mp->is_enabled);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_lisp_rloc_probe_enable_disable_t_handler
  (vl_api_lisp_rloc_probe_enable_disable_t * mp)
{
  vl_api_lisp_rloc_probe_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_rloc_probe_enable_disable (mp->is_enabled);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
vl_api_lisp_enable_disable_t_handler (vl_api_lisp_enable_disable_t * mp)
{
  vl_api_lisp_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_enable_disable (mp->is_en);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_show_lisp_map_request_mode_t_handler
  (vl_api_show_lisp_map_request_mode_t * mp)
{
  int rv = 0;
  vl_api_show_lisp_map_request_mode_reply_t *rmp;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY,
  ({
    rmp->mode = vnet_lisp_get_map_request_mode ();
  }));
  /* *INDENT-ON* */
}

static void
vl_api_lisp_map_request_mode_t_handler (vl_api_lisp_map_request_mode_t * mp)
{
  vl_api_lisp_map_request_mode_reply_t *rmp;
  int rv = 0;

  rv = vnet_lisp_set_map_request_mode (mp->mode);

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

  ip_address_set (&addr, &mp->address, mp->is_ip4 ? IP4 : IP6);
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

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_LISP_USE_PETR_REPLY,
  {
    rmp->status = status;
    ip_address_t *ip = &gid_address_ip (&addr);
    switch (ip_addr_version (ip))
      {
      case IP4:
        clib_memcpy (rmp->address, &ip_addr_v4 (ip),
                     sizeof (ip_addr_v4 (ip)));
        break;

      case IP6:
        clib_memcpy (rmp->address, &ip_addr_v6 (ip),
                     sizeof (ip_addr_v6 (ip)));
        break;

      default:
        ASSERT (0);
      }
    rmp->is_ip4 = (gid_address_ip_version (&addr) == IP4);
  });
  /* *INDENT-ON* */
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

  rv = unformat_lisp_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->eid, mp->eid_len);
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

  rv = unformat_lisp_eid_api (&a->leid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->leid, mp->leid_len);
  rv |= unformat_lisp_eid_api (&a->reid, clib_net_to_host_u32 (mp->vni),
			       mp->eid_type, mp->reid, mp->reid_len);

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
  rmp->_vl_msg_id = ntohs (VL_API_LISP_LOCATOR_DETAILS);
  rmp->context = context;

  rmp->local = loc->local;
  if (loc->local)
    {
      rmp->sw_if_index = ntohl (loc->sw_if_index);
    }
  else
    {
      rmp->is_ipv6 = gid_address_ip_version (&loc->address);
      ip_address_copy_addr (rmp->ip_address, &gid_address_ip (&loc->address));
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
  rmp->_vl_msg_id = ntohs (VL_API_LISP_LOCATOR_SET_DETAILS);
  rmp->context = context;

  rmp->ls_index = htonl (ls_index);
  if (lsit->local)
    {
      ASSERT (lsit->name != NULL);
      strncpy ((char *) rmp->ls_name, (char *) lsit->name,
	       vec_len (lsit->name));
    }
  else
    {
      str = format (0, "<remote-%d>", ls_index);
      strncpy ((char *) rmp->ls_name, (char *) str, vec_len (str));
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
  /* *INDENT-OFF* */
  pool_foreach (lsit, lcm->locator_set_pool,
  ({
    if (filter && !((1 == filter && lsit->local) ||
                    (2 == filter && !lsit->local)))
      {
        continue;
      }
    send_lisp_locator_set_details (lcm, lsit, reg, mp->context,
                                   lsit - lcm->locator_set_pool);
  }));
  /* *INDENT-ON* */
}

static void
lisp_fid_put_api (u8 * dst, fid_address_t * src, u8 * prefix_length)
{
  ASSERT (prefix_length);
  ip_prefix_t *ippref = &fid_addr_ippref (src);

  switch (fid_addr_type (src))
    {
    case FID_ADDR_IP_PREF:
      if (ip_prefix_version (ippref) == IP4)
	clib_memcpy (dst, &ip_prefix_v4 (ippref), 4);
      else
	clib_memcpy (dst, &ip_prefix_v6 (ippref), 16);
      prefix_length[0] = ip_prefix_len (ippref);
      break;

    case FID_ADDR_MAC:
      prefix_length[0] = 0;
      clib_memcpy (dst, fid_addr_mac (src), 6);
      break;

    default:
      clib_warning ("Unknown FID type %d!", fid_addr_type (src));
      break;
    }
}

static u8
fid_type_to_api_type (fid_address_t * fid)
{
  ip_prefix_t *ippref;

  switch (fid_addr_type (fid))
    {
    case FID_ADDR_IP_PREF:
      ippref = &fid_addr_ippref (fid);
      if (ip_prefix_version (ippref) == IP4)
	return 0;
      else if (ip_prefix_version (ippref) == IP6)
	return 1;
      else
	return ~0;

    case FID_ADDR_MAC:
      return 2;
    case FID_ADDR_NSH:
      return 3;
    }

  return ~0;
}

static void
send_lisp_eid_table_details (mapping_t * mapit,
			     vl_api_registration_t * reg, u32 context,
			     u8 filter)
{
  fid_address_t *fid;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *ls = 0;
  vl_api_lisp_eid_table_details_t *rmp = NULL;
  gid_address_t *gid = NULL;
  u8 *mac = 0;
  ip_prefix_t *ip_prefix = NULL;

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
  ip_prefix = &gid_address_ippref (gid);
  mac = gid_address_mac (gid);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_DETAILS);

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
      rmp->is_src_dst = 1;
      fid = &gid_address_sd_src (gid);
      rmp->eid_type = fid_type_to_api_type (fid);
      lisp_fid_put_api (rmp->seid, &gid_address_sd_src (gid),
			&rmp->seid_prefix_len);
      lisp_fid_put_api (rmp->eid, &gid_address_sd_dst (gid),
			&rmp->eid_prefix_len);
      break;
    case GID_ADDR_IP_PREFIX:
      rmp->eid_prefix_len = ip_prefix_len (ip_prefix);
      if (ip_prefix_version (ip_prefix) == IP4)
	{
	  rmp->eid_type = 0;	/* ipv4 type */
	  clib_memcpy (rmp->eid, &ip_prefix_v4 (ip_prefix),
		       sizeof (ip_prefix_v4 (ip_prefix)));
	}
      else
	{
	  rmp->eid_type = 1;	/* ipv6 type */
	  clib_memcpy (rmp->eid, &ip_prefix_v6 (ip_prefix),
		       sizeof (ip_prefix_v6 (ip_prefix)));
	}
      break;
    case GID_ADDR_MAC:
      rmp->eid_type = 2;	/* l2 mac type */
      clib_memcpy (rmp->eid, mac, 6);
      break;
    default:
      ASSERT (0);
    }
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (gid_address_vni (gid));
  rmp->key_id = clib_host_to_net_u16 (mapit->key_id);
  memcpy (rmp->key, mapit->key, vec_len (mapit->key));
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

      unformat_lisp_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			     mp->eid_type, mp->eid, mp->prefix_length);

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
      if ((u32) ~ 0 == mi)
	return;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      send_lisp_eid_table_details (mapit, reg, mp->context,
				   0 /* ignore filter */ );
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (mapit, lcm->mapping_pool,
      ({
        send_lisp_eid_table_details(mapit, reg, mp->context,
                                    mp->filter);
      }));
      /* *INDENT-ON* */
    }
}

static void
send_lisp_map_server_details (ip_address_t * ip, vl_api_registration_t * reg,
			      u32 context)
{
  vl_api_lisp_map_server_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_MAP_SERVER_DETAILS);

  switch (ip_addr_version (ip))
    {
    case IP4:
      rmp->is_ipv6 = 0;
      clib_memcpy (rmp->ip_address, &ip_addr_v4 (ip),
		   sizeof (ip_addr_v4 (ip)));
      break;

    case IP6:
      rmp->is_ipv6 = 1;
      clib_memcpy (rmp->ip_address, &ip_addr_v6 (ip),
		   sizeof (ip_addr_v6 (ip)));
      break;

    default:
      ASSERT (0);
    }
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
  rmp->_vl_msg_id = ntohs (VL_API_LISP_MAP_RESOLVER_DETAILS);

  switch (ip_addr_version (ip))
    {
    case IP4:
      rmp->is_ipv6 = 0;
      clib_memcpy (rmp->ip_address, &ip_addr_v4 (ip),
		   sizeof (ip_addr_v4 (ip)));
      break;

    case IP6:
      rmp->is_ipv6 = 1;
      clib_memcpy (rmp->ip_address, &ip_addr_v6 (ip),
		   sizeof (ip_addr_v6 (ip)));
      break;

    default:
      ASSERT (0);
    }
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
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_MAP_DETAILS);

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

  /* *INDENT-OFF* */
  hash_foreach_pair (p, vni_table,
  ({
    send_eid_table_map_pair (p, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
send_eid_table_vni (u32 vni, vl_api_registration_t * reg, u32 context)
{
  vl_api_lisp_eid_table_vni_details_t *rmp = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_VNI_DETAILS);
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

      switch (gid_address_type (&adj->reid))
	{
	case GID_ADDR_IP_PREFIX:
	  a.reid_prefix_len = gid_address_ippref_len (&adj->reid);
	  a.leid_prefix_len = gid_address_ippref_len (&adj->leid);
	  if (gid_address_ip_version (&adj->reid) == IP4)
	    {
	      a.eid_type = 0;	/* ipv4 type */
	      clib_memcpy (a.reid, &gid_address_ip (&adj->reid), 4);
	      clib_memcpy (a.leid, &gid_address_ip (&adj->leid), 4);
	    }
	  else
	    {
	      a.eid_type = 1;	/* ipv6 type */
	      clib_memcpy (a.reid, &gid_address_ip (&adj->reid), 16);
	      clib_memcpy (a.leid, &gid_address_ip (&adj->leid), 16);
	    }
	  break;
	case GID_ADDR_MAC:
	  a.eid_type = 2;	/* l2 mac type */
	  mac_copy (a.reid, gid_address_mac (&adj->reid));
	  mac_copy (a.leid, gid_address_mac (&adj->leid));
	  break;
	default:
	  ASSERT (0);
	}
      dst[i] = a;
    }
}

static void
  vl_api_show_lisp_rloc_probe_state_t_handler
  (vl_api_show_lisp_rloc_probe_state_t * mp)
{
  vl_api_show_lisp_rloc_probe_state_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_rloc_probe_state_get ();
  });
  /* *INDENT-ON* */
}

static void
  vl_api_show_lisp_map_register_state_t_handler
  (vl_api_show_lisp_map_register_state_t * mp)
{
  vl_api_show_lisp_map_register_state_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_map_register_state_get ();
  });
  /* *INDENT-ON* */
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

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_LISP_ADJACENCIES_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (vec_len (adjs));
    lisp_adjacency_copy (rmp->adjacencies, adjs);
  });
  /* *INDENT-ON* */

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

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

  hash_free (vnis);
}

static void
vl_api_show_lisp_status_t_handler (vl_api_show_lisp_status_t * mp)
{
  vl_api_show_lisp_status_reply_t *rmp = NULL;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_LISP_STATUS_REPLY,
  ({
    rmp->gpe_status = vnet_lisp_gpe_enable_disable_status ();
    rmp->feature_status = vnet_lisp_enable_disable_status ();
  }));
  /* *INDENT-ON* */
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

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY,
  ({
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */

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

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_LISP_PITR_REPLY,
  ({
    rmp->status = lcm->flags & LISP_FLAG_PITR_MODE;
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */
}

/*
 * lisp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_lisp;
#undef _
}

static clib_error_t *
lisp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (lisp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
