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

#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/vnet_msg_enum.h>

#define vl_api_one_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_one_add_del_locator_set_t_print vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_print vl_noop_handler

#define vl_api_one_add_del_locator_set_t_endian vl_noop_handler
#define vl_api_one_add_del_locator_set_t_print vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_endian vl_noop_handler
#define vl_api_one_add_del_remote_mapping_t_print vl_noop_handler

#define vl_api_one_add_del_l2_arp_entry vl_noop_handler
#define vl_api_one_l2_arp_bd_get vl_noop_handler

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

#define REPLY_DETAILS(t, body)                                  	\
do {                                                            	\
    vl_api_registration_t * reg;                             		\
    rv = vl_msg_api_pd_handler (mp, rv);                        	\
    reg = vl_api_client_index_to_registration (mp->client_index);	\
    if (!reg)								\
      return;								\
								  \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     	\
    rmp->_vl_msg_id = ntohs((t));                               	\
    rmp->context = mp->context;                                 	\
    do {body;} while (0);                                       	\
    vl_api_send_msg (reg, (u8 *)&rmp);                      		\
} while(0);

#define foreach_vpe_api_msg                             			\
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
_(ONE_SET_TRANSPORT_PROTOCOL, one_set_transport_protocol)               \
_(ONE_GET_TRANSPORT_PROTOCOL, one_get_transport_protocol)               \
_(ONE_ENABLE_DISABLE_XTR_MODE, one_enable_disable_xtr_mode)             \
_(ONE_SHOW_XTR_MODE, one_show_xtr_mode)                                 \
_(ONE_ENABLE_DISABLE_PITR_MODE, one_enable_disable_pitr_mode)           \
_(ONE_SHOW_PITR_MODE, one_show_pitr_mode)                               \
_(ONE_ENABLE_DISABLE_PETR_MODE, one_enable_disable_petr_mode)           \
_(ONE_SHOW_PETR_MODE, one_show_petr_mode)                               \


static locator_t *
unformat_one_locs (vl_api_remote_locator_t * rmt_locs, u32 rloc_num)
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

  REPLY_MACRO (VL_API_ONE_ADD_DEL_LOCATOR_REPLY);
}

typedef struct
{
  u32 spi;
  u8 si;
} __attribute__ ((__packed__)) lisp_nsh_api_t;

static int
unformat_one_eid_api (gid_address_t * dst, u32 vni, vl_api_eid_t * eid)
{
  fib_prefix_t prefix;

  switch (eid->type)
    {
    case EID_TYPE_API_PREFIX:
      ip_prefix_decode (&eid->address.prefix, &prefix);
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      if (prefix.fp_proto == FIB_PROTOCOL_IP4)
	gid_address_ip_set (dst, &prefix.fp_addr.ip4, AF_IP4);
      if (prefix.fp_proto == FIB_PROTOCOL_IP6)
	gid_address_ip_set (dst, &prefix.fp_addr.ip6, AF_IP6);
      gid_address_ippref_len (dst) = prefix.fp_len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case EID_TYPE_API_MAC:
      gid_address_type (dst) = GID_ADDR_MAC;
      mac_address_decode (eid->address.mac,
			  (mac_address_t *) & gid_address_mac (dst));
      break;
    case EID_TYPE_API_NSH:
      gid_address_type (dst) = GID_ADDR_NSH;
      gid_address_nsh_spi (dst) = clib_net_to_host_u32 (eid->address.nsh.spi);
      gid_address_nsh_si (dst) = eid->address.nsh.si;
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = vni;

  return 0;
}

static void
fid_to_api_eid (fid_address_t * fid, vl_api_eid_t * eid)
{
  fib_prefix_t fib_prefix;
  u32 eid_type;

  switch (fid_addr_type (fid))
    {
    case FID_ADDR_IP_PREF:
      eid_type = EID_TYPE_API_PREFIX;
      ip_prefix_to_fib_prefix (&fid_addr_ippref (fid), &fib_prefix);
      ip_prefix_encode (&fib_prefix, &eid->address.prefix);
      break;
    case FID_ADDR_MAC:
      eid_type = EID_TYPE_API_MAC;
      mac_address_encode ((mac_address_t *) fid_addr_mac (fid),
			  eid->address.mac);
      break;
    default:
      /* unknown type */
      return;
    }

  eid->type = eid_type;
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
  clib_memset (a, 0, sizeof (a[0]));
  clib_memset (eid, 0, sizeof (eid[0]));

  rv = unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni), &mp->eid);
  if (rv)
    goto out;

  if (gid_address_type (eid) == GID_ADDR_NSH)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

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

  if (mp->key.id != KEY_ID_API_HMAC_NO_KEY)
    key = format (0, "%s", mp->key.key);

  /* XXX treat batch configuration */
  a->is_add = mp->is_add;
  gid_address_copy (&a->eid, eid);
  a->locator_set_index = locator_set_index;
  a->local = 1;
  a->key = key;
  a->key_id = mp->key.id;

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

  clib_memset (&addr, 0, sizeof (addr));

  ip_address_decode2 (&mp->ip_address, &addr);

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

  clib_memset (a, 0, sizeof (a[0]));

  ip_address_decode2 (&mp->ip_address, &a->address);

  a->is_add = mp->is_add;

  rv = vnet_lisp_add_del_map_resolver (a);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY);
}

static void
  vl_api_one_map_register_enable_disable_t_handler
  (vl_api_one_map_register_enable_disable_t * mp)
{
  vl_api_one_map_register_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_map_register_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_one_rloc_probe_enable_disable_t_handler
  (vl_api_one_rloc_probe_enable_disable_t * mp)
{
  vl_api_one_rloc_probe_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_rloc_probe_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_one_enable_disable_t_handler (vl_api_one_enable_disable_t * mp)
{
  vl_api_one_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_enable_disable (mp->is_enable);
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

  mp->ls_name[sizeof (mp->ls_name) - 1] = 0;
  ls_name = format (0, "%s", mp->ls_name);
  vec_terminate_c_string (ls_name);
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

  mp->ls_name[sizeof (mp->ls_name) - 1] = 0;
  ls_name = format (0, "%s", mp->ls_name);
  vec_terminate_c_string (ls_name);
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

  ip_address_decode2 (&mp->ip_address, &addr);

  rv = vnet_lisp_use_petr (&addr, mp->is_add);

  REPLY_MACRO (VL_API_ONE_USE_PETR_REPLY);
}

static void
vl_api_show_one_use_petr_t_handler (vl_api_show_one_use_petr_t * mp)
{
  vl_api_show_one_use_petr_reply_t *rmp = NULL;
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
  REPLY_MACRO2 (VL_API_SHOW_ONE_USE_PETR_REPLY,
  {
    rmp->status = status;
    ip_address_t *ip = &gid_address_ip (&addr);

    ip_address_encode2 (ip, &rmp->ip_address);
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

  mp->locator_set_name[sizeof (mp->locator_set_name) - 1] = 0;
  locator_set_name = format (0, "%s", mp->locator_set_name);
  vec_terminate_c_string (locator_set_name);

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

  clib_memset (eid, 0, sizeof (eid[0]));

  rv = unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni), &mp->deid);
  if (rv)
    goto send_reply;

  rlocs = unformat_one_locs (mp->rlocs, rloc_num);

  if (!mp->is_add)
    {
      vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
      clib_memset (a, 0, sizeof (a[0]));
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
  clib_memset (a, 0, sizeof (a[0]));

  rv =
    unformat_one_eid_api (&a->leid, clib_net_to_host_u32 (mp->vni),
			  &mp->leid);
  rv |=
    unformat_one_eid_api (&a->reid, clib_net_to_host_u32 (mp->vni),
			  &mp->reid);

  if (rv)
    goto send_reply;

  a->is_add = mp->is_add;
  rv = vnet_lisp_add_del_adjacency (a);

send_reply:
  REPLY_MACRO (VL_API_ONE_ADD_DEL_ADJACENCY_REPLY);
}

static void
send_one_locator_details (lisp_cp_main_t * lcm,
			  locator_t * loc, vl_api_registration_t * reg,
			  u32 context)
{
  vl_api_one_locator_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_LOCATOR_DETAILS);
  rmp->context = context;

  rmp->local = loc->local;
  if (loc->local)
    {
      rmp->sw_if_index = ntohl (loc->sw_if_index);
    }
  else
    {
      ip_address_encode2 (&loc->address.ippref.addr, &rmp->ip_address);
    }
  rmp->priority = loc->priority;
  rmp->weight = loc->weight;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_locator_dump_t_handler (vl_api_one_locator_dump_t * mp)
{
  u8 *ls_name = 0;
  vl_api_registration_t *reg;
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
    send_one_locator_details (lcm, loc, reg, mp->context);
  };
out:
  vec_free (ls_name);
}

static void
send_one_locator_set_details (lisp_cp_main_t * lcm,
			      locator_set_t * lsit,
			      vl_api_registration_t * reg, u32 context,
			      u32 ls_index)
{
  vl_api_one_locator_set_details_t *rmp;
  u8 *str = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
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

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_locator_set_dump_t_handler (vl_api_one_locator_set_dump_t * mp)
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
    send_one_locator_set_details (lcm, lsit, reg, mp->context,
                                   lsit - lcm->locator_set_pool);
  }));
  /* *INDENT-ON* */
}

static void
send_one_eid_table_details (mapping_t * mapit,
			    vl_api_registration_t * reg, u32 context,
			    u8 filter)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *ls = 0;
  vl_api_one_eid_table_details_t *rmp = NULL;
  gid_address_t *gid = NULL;
  u32 eid_type;
  fib_prefix_t fib_prefix;

  if (mapit->pitr_set || mapit->nsh_set)
    return;

  switch (ntohl (filter))
    {
    case ONE_FILTER_API_ALL:	/* all mappings */
      break;

    case ONE_FILTER_API_LOCAL:	/* local only */
      if (!mapit->local)
	return;
      break;
    case ONE_FILTER_API_REMOTE:	/* remote only */
      if (mapit->local)
	return;
      break;
    default:
      clib_warning ("Filter error, unknown filter: %d", filter);
      return;
    }

  gid = &mapit->eid;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
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
      fid_to_api_eid (&gid_address_sd_src (gid), &rmp->seid);
      fid_to_api_eid (&gid_address_sd_dst (gid), &rmp->deid);
      break;
    case GID_ADDR_IP_PREFIX:
      eid_type = EID_TYPE_API_PREFIX;
      rmp->seid.type = eid_type;
      ip_prefix_to_fib_prefix (&gid_address_ippref (gid), &fib_prefix);
      ip_prefix_encode (&fib_prefix, &rmp->seid.address.prefix);
      break;
    case GID_ADDR_MAC:
      eid_type = EID_TYPE_API_MAC;
      rmp->seid.type = eid_type;
      mac_address_encode ((mac_address_t *) gid_address_mac (gid),
			  rmp->seid.address.mac);
      break;
    case GID_ADDR_NSH:
      eid_type = EID_TYPE_API_NSH;
      rmp->seid.type = eid_type;
      rmp->seid.address.nsh.spi =
	clib_host_to_net_u32 (gid_address_nsh_spi (gid));
      rmp->seid.address.nsh.si = gid_address_nsh_si (gid);
      break;
    default:
      /* unknown type */
      return;
    }

  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (gid_address_vni (gid));
  rmp->key.id = mapit->key_id;
  memcpy (rmp->key.key, mapit->key, vec_len (mapit->key));
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_eid_table_dump_t_handler (vl_api_one_eid_table_dump_t * mp)
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

      unformat_one_eid_api (eid, clib_net_to_host_u32 (mp->vni), &mp->eid);

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
      if ((u32) ~ 0 == mi)
	return;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      send_one_eid_table_details (mapit, reg, mp->context,
				  0 /* ignore filter */ );
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (mapit, lcm->mapping_pool,
      ({
        send_one_eid_table_details(mapit, reg, mp->context,
                                    mp->filter);
      }));
      /* *INDENT-ON* */
    }
}

static void
send_one_map_server_details (ip_address_t * ip, vl_api_registration_t * reg,
			     u32 context)
{
  vl_api_one_map_server_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_MAP_SERVER_DETAILS);


  ip_address_encode2 (ip, &rmp->ip_address);

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_map_server_dump_t_handler (vl_api_one_map_server_dump_t * mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (mr, lcm->map_servers)
  {
    send_one_map_server_details (&mr->address, reg, mp->context);
  }
}

static void
send_one_map_resolver_details (ip_address_t * ip,
			       vl_api_registration_t * reg, u32 context)
{
  vl_api_one_map_resolver_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_MAP_RESOLVER_DETAILS);

  ip_address_encode2 (ip, &rmp->ip_address);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_map_resolver_dump_t_handler (vl_api_one_map_resolver_dump_t * mp)
{
  vl_api_registration_t *reg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (mr, lcm->map_resolvers)
  {
    send_one_map_resolver_details (&mr->address, reg, mp->context);
  }
}

static void
send_eid_table_map_pair (hash_pair_t * p, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_one_eid_table_map_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_EID_TABLE_MAP_DETAILS);

  rmp->vni = clib_host_to_net_u32 (p->key);
  rmp->dp_table = clib_host_to_net_u32 (p->value[0]);
  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_one_eid_table_map_dump_t_handler (vl_api_one_eid_table_map_dump_t * mp)
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
  vl_api_one_eid_table_vni_details_t *rmp = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ONE_EID_TABLE_VNI_DETAILS);
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (vni);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
one_adjacency_copy (vl_api_one_adjacency_t * dst, lisp_adjacency_t * adjs)
{
  lisp_adjacency_t *adj;
  vl_api_one_adjacency_t a;
  u32 i, n = vec_len (adjs);
  fib_prefix_t rfib_prefix, lfib_prefix;
  u32 eid_type;

  for (i = 0; i < n; i++)
    {
      adj = vec_elt_at_index (adjs, i);
      clib_memset (&a, 0, sizeof (a));

      switch (gid_address_type (&adj->reid))
	{
	case GID_ADDR_IP_PREFIX:
	  eid_type = EID_TYPE_API_PREFIX;
	  ip_prefix_to_fib_prefix (&gid_address_ippref (&adj->reid),
				   &rfib_prefix);
	  ip_prefix_to_fib_prefix (&gid_address_ippref (&adj->leid),
				   &lfib_prefix);
	  ip_prefix_encode (&rfib_prefix, &a.reid.address.prefix);
	  ip_prefix_encode (&lfib_prefix, &a.leid.address.prefix);
	  break;
	case GID_ADDR_MAC:
	  eid_type = EID_TYPE_API_PREFIX;
	  mac_address_encode ((mac_address_t *) gid_address_mac (&adj->reid),
			      a.reid.address.mac);
	  mac_address_encode ((mac_address_t *) gid_address_mac (&adj->leid),
			      a.leid.address.mac);
	  break;
	case GID_ADDR_NSH:
	  eid_type = EID_TYPE_API_PREFIX;
	  a.reid.address.nsh.spi =
	    clib_host_to_net_u32 (gid_address_nsh_spi (&adj->reid));
	  a.reid.address.nsh.si = gid_address_nsh_si (&adj->reid);
	  a.leid.address.nsh.spi =
	    clib_host_to_net_u32 (gid_address_nsh_spi (&adj->leid));
	  a.leid.address.nsh.si = gid_address_nsh_si (&adj->leid);
	  break;
	default:
	  ALWAYS_ASSERT (0);
	}
      a.reid.type = eid_type;
      a.leid.type = eid_type;
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
    rmp->is_enable = vnet_lisp_rloc_probe_state_get ();
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
    rmp->is_enable = vnet_lisp_map_register_state_get ();
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
  vl_api_registration_t *reg;
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
vl_api_show_one_status_t_handler (vl_api_show_one_status_t * mp)
{
  vl_api_show_one_status_reply_t *rmp = NULL;
  int rv = 0;

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
  vl_api_one_get_map_request_itr_rlocs_reply_t *rmp = NULL;
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
  vl_api_show_one_nsh_mapping_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  u8 is_set = 0;
  int rv = 0;

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
  vl_api_show_one_pitr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  u8 is_enable = (lcm->flags & LISP_FLAG_PITR_MODE)
    && lcm->pitr_map_index != ~0;

  if (!is_enable)
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
    rmp->status = lcm->flags & LISP_FLAG_PITR_MODE;
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
    rmp->is_enable = vnet_lisp_stats_enable_disable_state ();
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_one_stats_enable_disable_t_handler
  (vl_api_one_stats_enable_disable_t * mp)
{
  vl_api_one_enable_disable_reply_t *rmp = NULL;

  vnet_api_error_t rv = vnet_lisp_stats_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_REPLY);
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
        fid_to_api_eid (&stat->deid, &rmp->deid);
        fid_to_api_eid (&stat->seid, &rmp->seid);
        rmp->vni = clib_host_to_net_u32 (stat->vni);

        ip_address_encode2 (&stat->rmt_rloc, &rmp->rloc);
        ip_address_encode2 (&stat->loc_rloc, &rmp->lloc);

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
  ip4_address_t ip4;
  mac_address_t mac;
  clib_memset (arp, 0, sizeof (*arp));

  gid_address_type (arp) = GID_ADDR_ARP;
  gid_address_arp_bd (arp) = clib_net_to_host_u32 (mp->bd);

  ip4_address_decode (mp->entry.ip4, &ip4);
  ip_address_set (&gid_address_arp_ndp_ip (arp), &ip4, AF_IP4);
  mac_address_decode (mp->entry.mac, &mac);

  rv = vnet_lisp_add_del_l2_arp_ndp_entry (arp, mac.bytes, mp->is_add);

  REPLY_MACRO (VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY);
}

static void
vl_api_one_add_del_ndp_entry_t_handler (vl_api_one_add_del_ndp_entry_t * mp)
{
  vl_api_one_add_del_ndp_entry_reply_t *rmp;
  int rv = 0;
  gid_address_t _g, *g = &_g;
  ip6_address_t ip6;
  mac_address_t mac;
  clib_memset (g, 0, sizeof (*g));

  gid_address_type (g) = GID_ADDR_NDP;
  gid_address_ndp_bd (g) = clib_net_to_host_u32 (mp->bd);

  ip6_address_decode (mp->entry.ip6, &ip6);
  ip_address_set (&gid_address_arp_ndp_ip (g), &ip6, AF_IP6);
  mac_address_decode (mp->entry.mac, &mac);

  rv = vnet_lisp_add_del_l2_arp_ndp_entry (g, mac.bytes, mp->is_add);

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
	mac_address_encode ((mac_address_t *) e->mac, rmp->entries[i].mac);
	ip4_address_encode ((ip4_address_t *) &e->ip4, rmp->entries[i].ip4);
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
  vl_api_one_set_transport_protocol_t_handler
  (vl_api_one_set_transport_protocol_t * mp)
{
  vl_api_one_set_transport_protocol_reply_t *rmp;
  int rv = 0;

  rv = vnet_lisp_set_transport_protocol (mp->protocol);

  REPLY_MACRO (VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY);
}

static void
  vl_api_one_get_transport_protocol_t_handler
  (vl_api_one_get_transport_protocol_t * mp)
{
  vl_api_one_get_transport_protocol_reply_t *rmp;
  int rv = 0;
  u8 proto = (u8) vnet_lisp_get_transport_protocol ();

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY,
  ({
    rmp->protocol = proto;
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
	mac_address_encode ((mac_address_t *) e->mac, rmp->entries[i].mac);
	ip6_address_encode ((ip6_address_t *) &e->ip6, rmp->entries[i].ip6);
        i++;
      }
  });
  /* *INDENT-ON* */

  vec_free (entries);
}

static void
  vl_api_one_enable_disable_xtr_mode_t_handler
  (vl_api_one_enable_disable_xtr_mode_t * mp)
{
  vl_api_one_enable_disable_xtr_mode_reply_t *rmp = 0;
  int rv = vnet_lisp_enable_disable_xtr_mode (mp->is_enable);

  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY);
}

static void
vl_api_one_show_xtr_mode_t_handler (vl_api_one_show_xtr_mode_t * mp)
{
  vl_api_one_show_xtr_mode_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_ONE_SHOW_XTR_MODE_REPLY,
  {
    rmp->is_enable = vnet_lisp_get_xtr_mode ();
  });
  /* *INDENT-ON* */
}

static void
  vl_api_one_enable_disable_pitr_mode_t_handler
  (vl_api_one_enable_disable_pitr_mode_t * mp)
{
  vl_api_one_enable_disable_pitr_mode_reply_t *rmp = 0;
  int rv = vnet_lisp_enable_disable_pitr_mode (mp->is_enable);

  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY);
}

static void
vl_api_one_show_pitr_mode_t_handler (vl_api_one_show_pitr_mode_t * mp)
{
  vl_api_one_show_pitr_mode_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_ONE_SHOW_PITR_MODE_REPLY,
  {
    rmp->is_enable = vnet_lisp_get_pitr_mode ();
  });
  /* *INDENT-ON* */
}

static void
  vl_api_one_enable_disable_petr_mode_t_handler
  (vl_api_one_enable_disable_petr_mode_t * mp)
{
  vl_api_one_enable_disable_petr_mode_reply_t *rmp = 0;
  int rv = vnet_lisp_enable_disable_petr_mode (mp->is_enable);

  REPLY_MACRO (VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY);
}

static void
vl_api_one_show_petr_mode_t_handler (vl_api_one_show_petr_mode_t * mp)
{
  vl_api_one_show_petr_mode_reply_t *rmp = 0;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_ONE_SHOW_PETR_MODE_REPLY,
  {
    rmp->is_enable = vnet_lisp_get_petr_mode ();
  });
  /* *INDENT-ON* */
}

/*
 * one_api_hookup
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
  foreach_vl_msg_name_crc_one;
#undef _
}

static clib_error_t *
one_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

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
