/*
 *------------------------------------------------------------------
 * one_api.c - Overlay Network Engine API
 *
 * Copyright (c) 2016-2017 Cisco and/or its affiliates.
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

#define vl_api_one_remote_locator_t_endian vl_noop_handler
#define vl_api_one_remote_locator_t_print vl_noop_handler
#define vl_api_one_local_locator_t_endian vl_noop_handler
#define vl_api_one_local_locator_t_print vl_noop_handler

#define vl_api_one_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_one_add_del_locator_set_t_print vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_print vl_noop_handler

#define vl_api_one_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_one_add_del_locator_set_t_print vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_print vl_noop_handler

#define vl_api_one_l2_arp_entry_t_endian vl_noop_handler
#define vl_api_one_l2_arp_entry_t_print vl_noop_handler
#define vl_api_one_add_del_l2_arp_entry vl_noop_handler
#define vl_api_one_l2_arp_bd_get vl_noop_handler

#define vl_api_one_ndp_entry_t_endian vl_noop_handler
#define vl_api_one_ndp_entry_t_print vl_noop_handler
#define vl_api_one_ndp_entries_get_reply_t_endian vl_noop_handler
#define vl_api_one_ndp_entries_get_reply_t_print vl_noop_handler

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

#define REPLY_DETAILS(t, body)                                  \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define foreach_vpe_api_msg                             \
_(ONE_ADD_DEL_LOCATOR_SET, one_add_del_locator_set)                     \
_(ONE_ADD_DEL_LOCATOR, one_add_del_locator)                             \
_(ONE_ADD_DEL_LOCAL_EID, one_add_del_local_eid)                         \
_(ONE_ADD_DEL_MAP_RESOLVER, one_add_del_map_resolver)                   \
_(ONE_ADD_DEL_MAP_SERVER, one_add_del_map_server)                       \
_(ONE_ENABLE_DISABLE, one_enable_disable)                               \
_(ONE_RLOC_PROBE_ENABLE_DISABLE, one_rloc_probe_enable_disable)         \
_(ONE_MAP_REGISTER_ENABLE_DISABLE, one_map_register_enable_disable)     \
_(ONE_MAP_REGISTER_FALLBACK_THRESHOLD,                                  \
  one_map_register_fallback_threshold)                                  \
_(ONE_ADD_DEL_REMOTE_MAPPING, one_add_del_remote_mapping)               \
_(ONE_ADD_DEL_ADJACENCY, one_add_del_adjacency)                         \
_(ONE_PITR_SET_LOCATOR_SET, one_pitr_set_locator_set)                   \
_(ONE_NSH_SET_LOCATOR_SET, one_nsh_set_locator_set)                     \
_(ONE_MAP_REQUEST_MODE, one_map_request_mode)                           \
_(ONE_EID_TABLE_ADD_DEL_MAP, one_eid_table_add_del_map)                 \
_(ONE_LOCATOR_SET_DUMP, one_locator_set_dump)                           \
_(ONE_LOCATOR_DUMP, one_locator_dump)                                   \
_(ONE_EID_TABLE_DUMP, one_eid_table_dump)                               \
_(ONE_MAP_RESOLVER_DUMP, one_map_resolver_dump)                         \
_(ONE_MAP_SERVER_DUMP, one_map_server_dump)                             \
_(ONE_EID_TABLE_MAP_DUMP, one_eid_table_map_dump)                       \
_(ONE_EID_TABLE_VNI_DUMP, one_eid_table_vni_dump)                       \
_(ONE_ADJACENCIES_GET, one_adjacencies_get)                             \
_(ONE_MAP_REGISTER_SET_TTL, one_map_register_set_ttl)                   \
_(SHOW_ONE_NSH_MAPPING, show_one_nsh_mapping)                           \
_(SHOW_ONE_RLOC_PROBE_STATE, show_one_rloc_probe_state)                 \
_(SHOW_ONE_MAP_REGISTER_STATE, show_one_map_register_state)             \
_(SHOW_ONE_MAP_REGISTER_TTL, show_one_map_register_ttl)                 \
_(SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD,                             \
  show_one_map_register_fallback_threshold)                             \
_(SHOW_ONE_STATUS, show_one_status)                                     \
_(ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS,                                    \
  one_add_del_map_request_itr_rlocs)                                    \
_(ONE_GET_MAP_REQUEST_ITR_RLOCS, one_get_map_request_itr_rlocs)         \
_(SHOW_ONE_PITR, show_one_pitr)                                         \
_(SHOW_ONE_MAP_REQUEST_MODE, show_one_map_request_mode)                 \
_(ONE_USE_PETR, one_use_petr)                                           \
_(SHOW_ONE_USE_PETR, show_one_use_petr)                                 \
_(SHOW_ONE_STATS_ENABLE_DISABLE, show_one_stats_enable_disable)         \
_(ONE_STATS_ENABLE_DISABLE, one_stats_enable_disable)                   \
_(ONE_STATS_DUMP, one_stats_dump)                                       \
_(ONE_STATS_FLUSH, one_stats_flush)                                     \
_(ONE_L2_ARP_BD_GET, one_l2_arp_bd_get)                                 \
_(ONE_L2_ARP_ENTRIES_GET, one_l2_arp_entries_get)                       \
_(ONE_ADD_DEL_L2_ARP_ENTRY, one_add_del_l2_arp_entry)                   \
_(ONE_ADD_DEL_NDP_ENTRY, one_add_del_ndp_entry)                         \
_(ONE_NDP_BD_GET, one_ndp_bd_get)                                       \
_(ONE_NDP_ENTRIES_GET, one_ndp_entries_get)                             \

static locator_t *
unformat_one_locs (vl_api_one_remote_locator_t * rmt_locs, u32 rloc_num)
{
  u32 i;
  locator_t *locs = 0, loc;
  vl_api_one_remote_locator_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* remote locators */
      r = &rmt_locs[i];
      memset (&loc, 0, sizeof (loc));
      gid_address_ip_set (&loc.address, &r->addr, r->is_ip4 ? IP4 : IP6);

      loc.priority = r->priority;
      loc.weight = r->weight;

      vec_add1 (locs, loc);
    }
  return locs;
}

static void
vl_api_one_map_register_set_ttl_t_handler (vl_api_one_map_register_set_ttl_t *
					   mp)
{
  vl_api_one_map_register_set_ttl_reply_t *rmp;
  int rv = 0;

  mp->ttl = clib_net_to_host_u32 (mp->ttl);
  rv = vnet_lisp_map_register_set_ttl (mp->ttl);

  REPLY_MACRO (VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY);
}

static void
  vl_api_show_one_map_register_ttl_t_handler
  (vl_api_show_one_map_register_ttl_t * mp)
{
  vl_api_show_one_map_register_ttl_reply_t *rmp;
  int rv = 0;

  u32 ttl = vnet_lisp_map_register_get_ttl ();
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY,
  ({
    rmp->ttl = clib_host_to_net_u32 (ttl);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_one_add_del_locator_set_t_handler (vl_api_one_add_del_locator_set_t *
					  mp)
{
  vl_api_one_add_del_locator_set_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  locator_t locator;
  vl_api_one_local_locator_t *ls_loc;
  u32 ls_index = ~0, locator_num;
  u8 *locator_name = NULL;
  int i;

  memset (a, 0, sizeof (a[0]));

  locator_name = format (0, "%s", mp->locator_set_name);

  a->name = locator_name;
  a->is_add = mp->is_add;
  a->local = 1;
  locator_num = clib_net_to_host_u32 (mp->locator_num);

  memset (&locator, 0, sizeof (locator));
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
  REPLY_MACRO2 (VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY,
  ({
    rmp->ls_index = clib_host_to_net_u32 (ls_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_one_add_del_locator_t_handler (vl_api_one_add_del_locator_t * mp)
{
  vl_api_one_add_del_locator_reply_t *rmp;
  int rv = 0;
  locator_t locator, *locators = NULL;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  u32 ls_index = ~0;
  u8 *locator_name = NULL;

  memset (&locator, 0, sizeof (locator));
  memset (a, 0, sizeof (a[0]));

  locator.sw_if_index = ntohl (mp->sw_if_index);
  locator.priority = mp->priority;
  locator.weight = mp->weight;
  locator.local = 1;
  vec_add1 (locators, locator);

  locator_name = format (0, "%s", mp->locator_set_name);

  a->name = locator_name;
  a->locators = locators;
  a->is_add = mp->is_add;
  a->local = 1;

  rv = vnet_lisp_add_del_locator (a, NULL, &ls_index);

  vec_free (locators);
  vec_free (locator_name);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_LOCATOR_REPLY);
}

typedef struct
{
  u32 spi;
  u8 si;
} __attribute__ ((__packed__)) lisp_nsh_api_t;

static int
unformat_one_eid_api (gid_address_t * dst, u32 vni, u8 type, void *src,
		      u8 len)
{
  lisp_nsh_api_t *nsh;

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
    case 3:			/* NSH */
      gid_address_type (dst) = GID_ADDR_NSH;
      nsh = src;
      gid_address_nsh_spi (dst) = clib_net_to_host_u32 (nsh->spi);
      gid_address_nsh_si (dst) = nsh->si;
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = vni;

  return 0;
}

static void
vl_api_one_add_del_local_eid_t_handler (vl_api_one_add_del_local_eid_t * mp)
{
  vl_api_one_add_del_local_eid_reply_t *rmp;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;
  uword *p = NULL;
  u32 locator_set_index = ~0, map_index = ~0;
  vnet_lisp_add_del_mapping_args_t _a, *a = &_a;
  u8 *name = NULL, *key = NULL;
  memset (a, 0, sizeof (a[0]));
  memset (eid, 0, sizeof (eid[0]));

  rv = unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			     mp->eid_type, mp->eid, mp->prefix_len);
  if (rv)
    goto out;

  if (gid_address_type (eid) == GID_ADDR_NSH)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  name = format (0, "%s", mp->locator_set_name);
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

  REPLY_MACRO (VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY);
}

static void
  vl_api_one_eid_table_add_del_map_t_handler
  (vl_api_one_eid_table_add_del_map_t * mp)
{
  vl_api_one_eid_table_add_del_map_reply_t *rmp;
  int rv = 0;
  rv = vnet_lisp_eid_table_map (clib_net_to_host_u32 (mp->vni),
				clib_net_to_host_u32 (mp->dp_table),
				mp->is_l2, mp->is_add);
REPLY_MACRO (VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY)}

static void
vl_api_one_add_del_map_server_t_handler (vl_api_one_add_del_map_server_t * mp)
{
  vl_api_one_add_del_map_server_reply_t *rmp;
  int rv = 0;
  ip_address_t addr;

  memset (&addr, 0, sizeof (addr));

  ip_address_set (&addr, mp->ip_address, mp->is_ipv6 ? IP6 : IP4);
  rv = vnet_lisp_add_del_map_server (&addr, mp->is_add);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY);
}

static void
vl_api_one_add_del_map_resolver_t_handler (vl_api_one_add_del_map_resolver_t
					   * mp)
{
  vl_api_one_add_del_map_resolver_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_map_resolver_args_t _a, *a = &_a;

  memset (a, 0, sizeof (a[0]));

  a->is_add = mp->is_add;
  ip_address_set (&a->address, mp->ip_address, mp->is_ipv6 ? IP6 : IP4);

  rv = vnet_lisp_add_del_map_resolver (a);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY);
}

static void
  vl_api_one_map_register_enable_disable_t_handler
  (vl_api_one_map_register_enable_disable_t * mp)
{
  vl_api_one_map_register_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_map_register_enable_disable (mp->is_enabled);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_one_rloc_probe_enable_disable_t_handler
  (vl_api_one_rloc_probe_enable_disable_t * mp)
{
  vl_api_one_rloc_probe_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_rloc_probe_enable_disable (mp->is_enabled);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_one_enable_disable_t_handler (vl_api_one_enable_disable_t * mp)
{
  vl_api_one_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_enable_disable (mp->is_en);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_show_one_map_request_mode_t_handler
  (vl_api_show_one_map_request_mode_t * mp)
{
  int rv = 0;
  vl_api_show_one_map_request_mode_reply_t *rmp;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY,
  ({
    rmp->mode = vnet_lisp_get_map_request_mode ();
  }));
  /* *INDENT-ON* */
}

static void
vl_api_one_map_request_mode_t_handler (vl_api_one_map_request_mode_t * mp)
{
  vl_api_one_map_request_mode_reply_t *rmp;
  int rv = 0;

  rv = vnet_lisp_set_map_request_mode (mp->mode);

  REPLY_MACRO (VL_API_ONE_MAP_REQUEST_MODE_REPLY);
}

static void
vl_api_one_nsh_set_locator_set_t_handler (vl_api_one_nsh_set_locator_set_t
					  * mp)
{
  vl_api_one_nsh_set_locator_set_reply_t *rmp;
  int rv = 0;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);
  rv = vnet_lisp_nsh_set_locator_set (ls_name, mp->is_add);
  vec_free (ls_name);

  REPLY_MACRO (VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY);
}

static void
vl_api_one_pitr_set_locator_set_t_handler (vl_api_one_pitr_set_locator_set_t
					   * mp)
{
  vl_api_one_pitr_set_locator_set_reply_t *rmp;
  int rv = 0;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);
  rv = vnet_lisp_pitr_set_locator_set (ls_name, mp->is_add);
  vec_free (ls_name);

  REPLY_MACRO (VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY);
}

static void
vl_api_one_use_petr_t_handler (vl_api_one_use_petr_t * mp)
{
  vl_api_one_use_petr_reply_t *rmp;
  int rv = 0;
  ip_address_t addr;

  ip_address_set (&addr, &mp->address, mp->is_ip4 ? IP4 : IP6);
  rv = vnet_lisp_use_petr (&addr, mp->is_add);

  REPLY_MACRO (VL_API_ONE_USE_PETR_REPLY);
}

static void
vl_api_show_one_use_petr_t_handler (vl_api_show_one_use_petr_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_one_use_petr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  int rv = 0;
  locator_t *loc = 0;
  u8 status = 0;
  gid_address_t addr;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  memset (&addr, 0, sizeof (addr));
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
  REPLY_MACRO2 (VL_API_SHOW_ONE_USE_PETR_REPLY,
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
  vl_api_one_add_del_map_request_itr_rlocs_t_handler
  (vl_api_one_add_del_map_request_itr_rlocs_t * mp)
{
  vl_api_one_add_del_map_request_itr_rlocs_reply_t *rmp;
  int rv = 0;
  u8 *locator_set_name = NULL;
  vnet_lisp_add_del_mreq_itr_rloc_args_t _a, *a = &_a;

  locator_set_name = format (0, "%s", mp->locator_set_name);

  a->is_add = mp->is_add;
  a->locator_set_name = locator_set_name;

  rv = vnet_lisp_add_del_mreq_itr_rlocs (a);

  vec_free (locator_set_name);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY);
}

static void
  vl_api_one_add_del_remote_mapping_t_handler
  (vl_api_one_add_del_remote_mapping_t * mp)
{
  locator_t *rlocs = 0;
  vl_api_one_add_del_remote_mapping_reply_t *rmp;
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;
  u32 rloc_num = clib_net_to_host_u32 (mp->rloc_num);

  memset (eid, 0, sizeof (eid[0]));

  rv = unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			     mp->eid_type, mp->eid, mp->eid_len);
  if (rv)
    goto send_reply;

  rlocs = unformat_one_locs (mp->rlocs, rloc_num);

  if (!mp->is_add)
    {
      vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
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
      memset (m_args, 0, sizeof (m_args[0]));
      gid_address_copy (&m_args->eid, eid);
      m_args->action = mp->action;
      m_args->is_static = 1;
      m_args->ttl = ~0;
      m_args->authoritative = 0;
      rv = vnet_lisp_add_mapping (m_args, rlocs, NULL, NULL);
    }
  else
    rv = vnet_lisp_del_mapping (eid, NULL);

  if (mp->del_all)
    vnet_lisp_clear_all_remote_adjacencies ();

out:
  vec_free (rlocs);
send_reply:
  REPLY_MACRO (VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY);
}

static void
vl_api_one_add_del_adjacency_t_handler (vl_api_one_add_del_adjacency_t * mp)
{
  vl_api_one_add_del_adjacency_reply_t *rmp;
  vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;

  int rv = 0;
  memset (a, 0, sizeof (a[0]));

  rv = unformat_one_eid_api (&a->leid, clib_net_to_host_u32 (mp->vni),
			     mp->eid_type, mp->leid, mp->leid_len);
  rv |= unformat_one_eid_api (&a->reid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->reid, mp->reid_len);

  if (rv)
    goto send_reply;

  a->is_add = mp->is_add;
  rv = vnet_lisp_add_del_adjacency (a);

send_reply:
  REPLY_MACRO (VL_API_ONE_ADD_DEL_ADJACENCY_REPLY);
}

static void
send_one_locator_details (lisp_cp_main_t * lcm,
			  locator_t * loc,
			  unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_one_locator_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_LOCATOR_DETAILS);
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_locator_dump_t_handler (vl_api_one_locator_dump_t * mp)
{
  u8 *ls_name = 0;
  unix_shared_memory_queue_t *q = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = 0;
  locator_t *loc = 0;
  u32 ls_index = ~0, *locit = 0;
  uword *p = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->is_index_set)
    ls_index = htonl (mp->ls_index);
  else
    {
      /* make sure we get a proper C-string */
      mp->ls_name[sizeof (mp->ls_name) - 1] = 0;
      ls_name = format (0, "%s", mp->ls_name);
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
    send_one_locator_details (lcm, loc, q, mp->context);
  };
out:
  vec_free (ls_name);
}

static void
send_one_locator_set_details (lisp_cp_main_t * lcm,
			      locator_set_t * lsit,
			      unix_shared_memory_queue_t * q,
			      u32 context, u32 ls_index)
{
  vl_api_one_locator_set_details_t *rmp;
  u8 *str = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_LOCATOR_SET_DETAILS);
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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_locator_set_dump_t_handler (vl_api_one_locator_set_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = NULL;
  u8 filter;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  filter = mp->filter;
  /* *INDENT-OFF* */
  pool_foreach (lsit, lcm->locator_set_pool,
  ({
    if (filter && !((1 == filter && lsit->local) ||
                    (2 == filter && !lsit->local)))
      {
        continue;
      }
    send_one_locator_set_details (lcm, lsit, q, mp->context,
                                   lsit - lcm->locator_set_pool);
  }));
  /* *INDENT-ON* */
}

static void
one_fid_put_api (u8 * dst, fid_address_t * src, u8 * prefix_length)
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
send_one_eid_table_details (mapping_t * mapit,
			    unix_shared_memory_queue_t * q,
			    u32 context, u8 filter)
{
  fid_address_t *fid;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *ls = 0;
  vl_api_one_eid_table_details_t *rmp = NULL;
  gid_address_t *gid = NULL;
  u8 *mac = 0;
  ip_prefix_t *ip_prefix = NULL;

  if (mapit->pitr_set || mapit->nsh_set)
    return;

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

  gid = &mapit->eid;
  ip_prefix = &gid_address_ippref (gid);
  mac = gid_address_mac (gid);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_EID_TABLE_DETAILS);

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
      one_fid_put_api (rmp->seid, &gid_address_sd_src (gid),
		       &rmp->seid_prefix_len);
      one_fid_put_api (rmp->eid, &gid_address_sd_dst (gid),
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
    case GID_ADDR_NSH:
      rmp->eid_type = 3;	/* NSH type */
      lisp_nsh_api_t nsh;
      nsh.spi = clib_host_to_net_u32 (gid_address_nsh_spi (gid));
      nsh.si = gid_address_nsh_si (gid);
      clib_memcpy (rmp->eid, &nsh, sizeof (nsh));
      break;
    default:
      ASSERT (0);
    }
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (gid_address_vni (gid));
  rmp->key_id = clib_host_to_net_u16 (mapit->key_id);
  memcpy (rmp->key, mapit->key, vec_len (mapit->key));
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_eid_table_dump_t_handler (vl_api_one_eid_table_dump_t * mp)
{
  u32 mi;
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *mapit = NULL;
  gid_address_t _eid, *eid = &_eid;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->eid_set)
    {
      memset (eid, 0, sizeof (*eid));

      unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			    mp->eid_type, mp->eid, mp->prefix_length);

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
      if ((u32) ~ 0 == mi)
	return;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      send_one_eid_table_details (mapit, q, mp->context,
				  0 /* ignore filter */ );
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (mapit, lcm->mapping_pool,
      ({
        send_one_eid_table_details(mapit, q, mp->context,
                                    mp->filter);
      }));
      /* *INDENT-ON* */
    }
}

static void
send_one_map_server_details (ip_address_t * ip,
			     unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_one_map_server_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_MAP_SERVER_DETAILS);

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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_map_server_dump_t_handler (vl_api_one_map_server_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  vec_foreach (mr, lcm->map_servers)
  {
    send_one_map_server_details (&mr->address, q, mp->context);
  }
}

static void
send_one_map_resolver_details (ip_address_t * ip,
			       unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_one_map_resolver_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_MAP_RESOLVER_DETAILS);

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

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_map_resolver_dump_t_handler (vl_api_one_map_resolver_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  vec_foreach (mr, lcm->map_resolvers)
  {
    send_one_map_resolver_details (&mr->address, q, mp->context);
  }
}

static void
send_eid_table_map_pair (hash_pair_t * p,
			 unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_one_eid_table_map_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_EID_TABLE_MAP_DETAILS);

  rmp->vni = clib_host_to_net_u32 (p->key);
  rmp->dp_table = clib_host_to_net_u32 (p->value[0]);
  rmp->context = context;
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_one_eid_table_map_dump_t_handler (vl_api_one_eid_table_map_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  hash_pair_t *p;
  uword *vni_table = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

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
    send_eid_table_map_pair (p, q, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
send_eid_table_vni (u32 vni, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_one_eid_table_vni_details_t *rmp = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_EID_TABLE_VNI_DETAILS);
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (vni);
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
one_adjacency_copy (vl_api_one_adjacency_t * dst, lisp_adjacency_t * adjs)
{
  lisp_adjacency_t *adj;
  vl_api_one_adjacency_t a;
  u32 i, n = vec_len (adjs);
  lisp_nsh_api_t nsh;

  for (i = 0; i < n; i++)
    {
      adj = vec_elt_at_index (adjs, i);
      memset (&a, 0, sizeof (a));

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
	case GID_ADDR_NSH:
	  a.eid_type = 3;	/* NSH type */
	  nsh.spi = clib_host_to_net_u32 (gid_address_nsh_spi (&adj->reid));
	  nsh.si = gid_address_nsh_si (&adj->reid);
	  clib_memcpy (a.reid, &nsh, sizeof (nsh));

	  nsh.spi = clib_host_to_net_u32 (gid_address_nsh_spi (&adj->leid));
	  nsh.si = gid_address_nsh_si (&adj->leid);
	  clib_memcpy (a.leid, &nsh, sizeof (nsh));
	  break;
	default:
	  ASSERT (0);
	}
      dst[i] = a;
    }
}

static void
  vl_api_show_one_rloc_probe_state_t_handler
  (vl_api_show_one_rloc_probe_state_t * mp)
{
  vl_api_show_one_rloc_probe_state_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_rloc_probe_state_get ();
  });
  /* *INDENT-ON* */
}

static void
  vl_api_show_one_map_register_state_t_handler
  (vl_api_show_one_map_register_state_t * mp)
{
  vl_api_show_one_map_register_state_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY,
  {
    rmp->is_enabled = vnet_lisp_map_register_state_get ();
  });
  /* *INDENT-ON* */
}

static void
vl_api_one_adjacencies_get_t_handler (vl_api_one_adjacencies_get_t * mp)
{
  vl_api_one_adjacencies_get_reply_t *rmp = 0;
  lisp_adjacency_t *adjs = 0;
  int rv = 0;
  u32 size = ~0;
  u32 vni = clib_net_to_host_u32 (mp->vni);

  adjs = vnet_lisp_adjacencies_get_by_vni (vni);
  size = vec_len (adjs) * sizeof (vl_api_one_adjacency_t);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_ONE_ADJACENCIES_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (vec_len (adjs));
    one_adjacency_copy (rmp->adjacencies, adjs);
  });
  /* *INDENT-ON* */

  vec_free (adjs);
}

static void
vl_api_one_eid_table_vni_dump_t_handler (vl_api_one_eid_table_vni_dump_t * mp)
{
  hash_pair_t *p;
  u32 *vnis = 0;
  unix_shared_memory_queue_t *q = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

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
    send_eid_table_vni (p->key, q, mp->context);
  }));
  /* *INDENT-ON* */

  hash_free (vnis);
}

static void
vl_api_show_one_status_t_handler (vl_api_show_one_status_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_one_status_reply_t *rmp = NULL;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_ONE_STATUS_REPLY,
  ({
    rmp->gpe_status = vnet_lisp_gpe_enable_disable_status ();
    rmp->feature_status = vnet_lisp_enable_disable_status ();
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_one_get_map_request_itr_rlocs_t_handler
  (vl_api_one_get_map_request_itr_rlocs_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_one_get_map_request_itr_rlocs_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *loc_set = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

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
  REPLY_MACRO2(VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY,
  ({
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */

  vec_free (tmp_str);
}

static void
vl_api_show_one_nsh_mapping_t_handler (vl_api_show_one_nsh_mapping_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_one_nsh_mapping_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  u8 is_set = 0;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (lcm->nsh_map_index == (u32) ~ 0)
    {
      tmp_str = format (0, "N/A");
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->nsh_map_index);
      if (~0 != m->locator_set_index)
	{
	  ls =
	    pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);
	  tmp_str = format (0, "%s", ls->name);
	  is_set = 1;
	}
      else
	{
	  tmp_str = format (0, "N/A");
	}
    }
  vec_add1 (tmp_str, 0);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_ONE_NSH_MAPPING_REPLY,
  ({
    rmp->is_set = is_set;
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_show_one_pitr_t_handler (vl_api_show_one_pitr_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_one_pitr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (!lcm->lisp_pitr)
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
  REPLY_MACRO2(VL_API_SHOW_ONE_PITR_REPLY,
  ({
    rmp->status = lcm->lisp_pitr;
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_show_one_stats_enable_disable_t_handler
  (vl_api_show_one_stats_enable_disable_t * mp)
{
  vl_api_show_one_stats_enable_disable_reply_t *rmp = NULL;
  vnet_api_error_t rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY,
  ({
    rmp->is_en = vnet_lisp_stats_enable_disable_state ();
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_one_stats_enable_disable_t_handler
  (vl_api_one_stats_enable_disable_t * mp)
{
  vl_api_one_enable_disable_reply_t *rmp = NULL;

  vnet_api_error_t rv = vnet_lisp_stats_enable_disable (mp->is_en);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
lisp_fid_addr_to_api (fid_address_t * fid, u8 * dst, u8 * api_eid_type,
		      u8 * prefix_length)
{
  switch (fid_addr_type (fid))
    {
    case FID_ADDR_IP_PREF:
      *prefix_length = fid_addr_prefix_length (fid);
      if (fid_addr_ip_version (fid) == IP4)
	{
	  *api_eid_type = 0;	/* ipv4 type */
	  clib_memcpy (dst, &fid_addr_ippref (fid), 4);
	}
      else
	{
	  *api_eid_type = 1;	/* ipv6 type */
	  clib_memcpy (dst, &fid_addr_ippref (fid), 16);
	}
      break;
    case FID_ADDR_MAC:
      *api_eid_type = 2;	/* l2 mac type */
      mac_copy (dst, fid_addr_mac (fid));
      break;
    default:
      ASSERT (0);
    }
}

static void
vl_api_one_stats_flush_t_handler (vl_api_one_stats_flush_t * mp)
{
  vl_api_one_stats_flush_reply_t *rmp;
  u8 rv;

  rv = vnet_lisp_flush_stats ();
  REPLY_MACRO (VL_API_ONE_STATS_FLUSH_REPLY);
}

static void
vl_api_one_stats_dump_t_handler (vl_api_one_stats_dump_t * mp)
{
  vl_api_one_stats_details_t *rmp;
  lisp_api_stats_t *stats, *stat;
  u8 rv = 0;

  stats = vnet_lisp_get_stats ();
  vec_foreach (stat, stats)
  {
      /* *INDENT-OFF* */
      REPLY_DETAILS (VL_API_ONE_STATS_DETAILS,
      ({
        lisp_fid_addr_to_api (&stat->deid, rmp->deid, &rmp->eid_type,
                              &rmp->deid_pref_len);
        lisp_fid_addr_to_api (&stat->seid, rmp->seid, &rmp->eid_type,
                              &rmp->seid_pref_len);
        rmp->vni = clib_host_to_net_u32 (stat->vni);

        rmp->is_ip4 = ip_addr_version (&stat->rmt_rloc) == IP4 ? 1 : 0;
        ip_address_copy_addr (rmp->rloc, &stat->rmt_rloc);
        ip_address_copy_addr (rmp->lloc, &stat->loc_rloc);

        rmp->pkt_count = clib_host_to_net_u32 (stat->counters.packets);
        rmp->bytes = clib_host_to_net_u32 (stat->counters.bytes);
      }));
      /* *INDENT-ON* */
  }
}

static void
  vl_api_one_add_del_l2_arp_entry_t_handler
  (vl_api_one_add_del_l2_arp_entry_t * mp)
{
  vl_api_one_add_del_l2_arp_entry_reply_t *rmp;
  int rv = 0;
  gid_address_t _arp, *arp = &_arp;
  memset (arp, 0, sizeof (*arp));

  gid_address_type (arp) = GID_ADDR_ARP;
  gid_address_arp_bd (arp) = clib_net_to_host_u32 (mp->bd);

  /* vpp keeps ip4 addresses in network byte order */
  ip_address_set (&gid_address_arp_ndp_ip (arp), &mp->ip4, IP4);

  rv = vnet_lisp_add_del_l2_arp_ndp_entry (arp, mp->mac, mp->is_add);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY);
}

static void
vl_api_one_add_del_ndp_entry_t_handler (vl_api_one_add_del_ndp_entry_t * mp)
{
  vl_api_one_add_del_ndp_entry_reply_t *rmp;
  int rv = 0;
  gid_address_t _g, *g = &_g;
  memset (g, 0, sizeof (*g));

  gid_address_type (g) = GID_ADDR_NDP;
  gid_address_ndp_bd (g) = clib_net_to_host_u32 (mp->bd);
  ip_address_set (&gid_address_arp_ndp_ip (g), mp->ip6, IP6);

  rv = vnet_lisp_add_del_l2_arp_ndp_entry (g, mp->mac, mp->is_add);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY);
}

static void
vl_api_one_ndp_bd_get_t_handler (vl_api_one_ndp_bd_get_t * mp)
{
  vl_api_one_ndp_bd_get_reply_t *rmp;
  int rv = 0;
  u32 i = 0;
  hash_pair_t *p;

  u32 *bds = vnet_lisp_ndp_bds_get ();
  u32 size = hash_elts (bds) * sizeof (u32);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_ONE_NDP_BD_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (hash_elts (bds));
    hash_foreach_pair (p, bds,
    ({
      rmp->bridge_domains[i++] = clib_host_to_net_u32 (p->key);
    }));
  });
  /* *INDENT-ON* */

  hash_free (bds);
}

static void
vl_api_one_l2_arp_bd_get_t_handler (vl_api_one_l2_arp_bd_get_t * mp)
{
  vl_api_one_l2_arp_bd_get_reply_t *rmp;
  int rv = 0;
  u32 i = 0;
  hash_pair_t *p;

  u32 *bds = vnet_lisp_l2_arp_bds_get ();
  u32 size = hash_elts (bds) * sizeof (u32);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_ONE_L2_ARP_BD_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (hash_elts (bds));
    hash_foreach_pair (p, bds,
    ({
      rmp->bridge_domains[i++] = clib_host_to_net_u32 (p->key);
    }));
  });
  /* *INDENT-ON* */

  hash_free (bds);
}

static void
vl_api_one_l2_arp_entries_get_t_handler (vl_api_one_l2_arp_entries_get_t * mp)
{
  vl_api_one_l2_arp_entries_get_reply_t *rmp;
  lisp_api_l2_arp_entry_t *entries = 0, *e;
  u32 i = 0;
  int rv = 0;

  u32 bd = clib_net_to_host_u32 (mp->bd);

  entries = vnet_lisp_l2_arp_entries_get_by_bd (bd);
  u32 size = vec_len (entries) * sizeof (vl_api_one_l2_arp_entry_t);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (vec_len (entries));
    vec_foreach (e, entries)
      {
        mac_copy (rmp->entries[i].mac, e->mac);
        rmp->entries[i].ip4 = e->ip4;
        i++;
      }
  });
  /* *INDENT-ON* */

  vec_free (entries);
}

static void
  vl_api_one_map_register_fallback_threshold_t_handler
  (vl_api_one_map_register_fallback_threshold_t * mp)
{
  vl_api_one_map_register_fallback_threshold_reply_t *rmp;
  int rv = 0;

  mp->value = clib_net_to_host_u32 (mp->value);
  rv = vnet_lisp_map_register_fallback_threshold_set (mp->value);
  REPLY_MACRO (VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY);
}

static void
  vl_api_show_one_map_register_fallback_threshold_t_handler
  (vl_api_show_one_map_register_fallback_threshold_t * mp)
{
  vl_api_show_one_map_register_fallback_threshold_reply_t *rmp;
  int rv = 0;

  u32 value = vnet_lisp_map_register_fallback_threshold_get ();

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY,
  ({
    rmp->value = clib_host_to_net_u32 (value);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_one_ndp_entries_get_t_handler (vl_api_one_ndp_entries_get_t * mp)
{
  vl_api_one_ndp_entries_get_reply_t *rmp = 0;
  lisp_api_ndp_entry_t *entries = 0, *e;
  u32 i = 0;
  int rv = 0;

  u32 bd = clib_net_to_host_u32 (mp->bd);

  entries = vnet_lisp_ndp_entries_get_by_bd (bd);
  u32 size = vec_len (entries) * sizeof (vl_api_one_ndp_entry_t);

  /* *INDENT-OFF* */
  REPLY_MACRO4 (VL_API_ONE_NDP_ENTRIES_GET_REPLY, size,
  {
    rmp->count = clib_host_to_net_u32 (vec_len (entries));
    vec_foreach (e, entries)
      {
        mac_copy (rmp->entries[i].mac, e->mac);
        clib_memcpy (rmp->entries[i].ip6, e->ip6, 16);
        i++;
      }
  });
  /* *INDENT-ON* */

  vec_free (entries);
}

/*
 * one_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
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
  foreach_vl_msg_name_crc_one;
#undef _
}

static clib_error_t *
one_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (one_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
