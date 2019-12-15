/*
 *------------------------------------------------------------------
 * ip_api.c - vnet ip api
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip_punt_drop.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/mfib/mfib_signal.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_api.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>

#include <vnet/vnet_msg_enum.h>

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

#include <vnet/format_fns.h>

#define foreach_ip_api_msg                                              \
_(SW_INTERFACE_IP6_ENABLE_DISABLE, sw_interface_ip6_enable_disable)     \
_(IP_TABLE_DUMP, ip_table_dump)                                         \
_(IP_ROUTE_DUMP, ip_route_dump)                                         \
_(IP_MTABLE_DUMP, ip_mtable_dump)                                       \
_(IP_MROUTE_DUMP, ip_mroute_dump)                                       \
_(IP_MROUTE_ADD_DEL, ip_mroute_add_del)                                 \
_(MFIB_SIGNAL_DUMP, mfib_signal_dump)                                   \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_UNNUMBERED_DUMP, ip_unnumbered_dump)                               \
_(IP_DUMP, ip_dump)                                                     \
_(IP_TABLE_REPLACE_BEGIN, ip_table_replace_begin)                       \
_(IP_TABLE_REPLACE_END, ip_table_replace_end)                           \
_(IP_TABLE_FLUSH, ip_table_flush)                                       \
_(IP_ROUTE_ADD_DEL, ip_route_add_del)                                   \
_(IP_TABLE_ADD_DEL, ip_table_add_del)                                   \
_(IP_PUNT_POLICE, ip_punt_police)                                       \
_(IP_PUNT_REDIRECT, ip_punt_redirect)                                   \
_(SET_IP_FLOW_HASH,set_ip_flow_hash)                                    \
_(IP_CONTAINER_PROXY_ADD_DEL, ip_container_proxy_add_del)               \
_(IP_CONTAINER_PROXY_DUMP, ip_container_proxy_dump)                     \
_(IOAM_ENABLE, ioam_enable)                                             \
_(IOAM_DISABLE, ioam_disable)                                           \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL,                               \
  ip_source_and_port_range_check_add_del)                               \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL,                     \
  ip_source_and_port_range_check_interface_add_del)                     \
_(IP_SOURCE_CHECK_INTERFACE_ADD_DEL,                                    \
  ip_source_check_interface_add_del)                                    \
 _(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS,                             \
   sw_interface_ip6_set_link_local_address)                             \
_(IP_REASSEMBLY_SET, ip_reassembly_set)                                 \
_(IP_REASSEMBLY_GET, ip_reassembly_get)                                 \
_(IP_REASSEMBLY_ENABLE_DISABLE, ip_reassembly_enable_disable)           \
_(IP_PUNT_REDIRECT_DUMP, ip_punt_redirect_dump)

static void
  vl_api_sw_interface_ip6_enable_disable_t_handler
  (vl_api_sw_interface_ip6_enable_disable_t * mp)
{
  vl_api_sw_interface_ip6_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ((mp->enable == 1) ?
	ip6_link_enable (ntohl (mp->sw_if_index)) :
	ip6_link_disable (ntohl (mp->sw_if_index)));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY);
}

static void
send_ip_table_details (vpe_api_main_t * am,
		       vl_api_registration_t * reg,
		       u32 context, const fib_table_t * table)
{
  vl_api_ip_table_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_TABLE_DETAILS);
  mp->context = context;

  mp->table.is_ip6 = (table->ft_proto == FIB_PROTOCOL_IP6);
  mp->table.table_id = htonl (table->ft_table_id);
  memcpy (mp->table.name, table->ft_desc,
	  clib_min (vec_len (table->ft_desc), sizeof (mp->table.name)));

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ip_table_dump_t_handler (vl_api_ip_table_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  fib_table_t *fib_table;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (fib_table, ip4_main.fibs,
  ({
    send_ip_table_details(am, reg, mp->context, fib_table);
  }));
  pool_foreach (fib_table, ip6_main.fibs,
  ({
    /* don't send link locals */
    if (fib_table->ft_flags & FIB_TABLE_FLAG_IP6_LL)
      continue;
    send_ip_table_details(am, reg, mp->context, fib_table);
  }));
  /* *INDENT-ON* */
}

typedef struct vl_api_ip_fib_dump_walk_ctx_t_
{
  fib_node_index_t *feis;
} vl_api_ip_fib_dump_walk_ctx_t;

static fib_table_walk_rc_t
vl_api_ip_fib_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_ip_fib_dump_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->feis, fei);

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
send_ip_route_details (vpe_api_main_t * am,
		       vl_api_registration_t * reg,
		       u32 context, fib_node_index_t fib_entry_index)
{
  fib_route_path_t *rpaths, *rpath;
  vl_api_ip_route_details_t *mp;
  const fib_prefix_t *pfx;
  vl_api_fib_path_t *fp;
  int path_count;

  rpaths = NULL;
  pfx = fib_entry_get_prefix (fib_entry_index);
  rpaths = fib_entry_encode (fib_entry_index);

  path_count = vec_len (rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ROUTE_DETAILS);
  mp->context = context;

  ip_prefix_encode (pfx, &mp->route.prefix);
  mp->route.table_id =
    htonl (fib_table_get_table_id
	   (fib_entry_get_fib_index (fib_entry_index), pfx->fp_proto));
  mp->route.n_paths = path_count;
  mp->route.stats_index =
    htonl (fib_table_entry_get_stats_index
	   (fib_entry_get_fib_index (fib_entry_index), pfx));

  fp = mp->route.paths;
  vec_foreach (rpath, rpaths)
  {
    fib_api_path_encode (rpath, fp);
    fp++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
  vec_free (rpaths);
}

typedef struct apt_ip6_fib_show_ctx_t_
{
  fib_node_index_t *entries;
} api_ip6_fib_show_ctx_t;

static void
vl_api_ip_route_dump_t_handler (vl_api_ip_route_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  fib_node_index_t *fib_entry_index;
  vl_api_registration_t *reg;
  fib_protocol_t fproto;
  u32 fib_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vl_api_ip_fib_dump_walk_ctx_t ctx = {
    .feis = NULL,
  };

  fproto = (mp->table.is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  fib_index = fib_table_find (fproto, ntohl (mp->table.table_id));

  if (INDEX_INVALID == fib_index)
    return;

  fib_table_walk (fib_index, fproto, vl_api_ip_fib_dump_walk, &ctx);

  vec_foreach (fib_entry_index, ctx.feis)
  {
    send_ip_route_details (am, reg, mp->context, *fib_entry_index);
  }

  vec_free (ctx.feis);
}

static void
send_ip_mtable_details (vl_api_registration_t * reg,
			u32 context, const mfib_table_t * mfib_table)
{
  vl_api_ip_mtable_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_MTABLE_DETAILS);
  mp->context = context;

  mp->table.table_id = htonl (mfib_table->mft_table_id);
  mp->table.is_ip6 = (FIB_PROTOCOL_IP6 == mfib_table->mft_proto);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ip_mtable_dump_t_handler (vl_api_ip_mtable_dump_t * mp)
{
  vl_api_registration_t *reg;
  mfib_table_t *mfib_table;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (mfib_table, ip4_main.mfibs,
  ({
      send_ip_mtable_details (reg, mp->context, mfib_table);
  }));
  pool_foreach (mfib_table, ip6_main.mfibs,
  ({
      send_ip_mtable_details (reg, mp->context, mfib_table);
  }));
  /* *INDENT-ON* */
}

typedef struct vl_api_ip_mfib_dump_ctx_t_
{
  fib_node_index_t *entries;
} vl_api_ip_mfib_dump_ctx_t;

static walk_rc_t
mfib_route_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_ip_mfib_dump_ctx_t *ctx = arg;

  vec_add1 (ctx->entries, fei);

  return (WALK_CONTINUE);
}

static void
send_ip_mroute_details (vpe_api_main_t * am,
			vl_api_registration_t * reg,
			u32 context, fib_node_index_t mfib_entry_index)
{
  fib_route_path_t *rpaths, *rpath;
  vl_api_ip_mroute_details_t *mp;
  const mfib_prefix_t *pfx;
  vl_api_mfib_path_t *fp;
  int path_count;

  rpaths = NULL;
  pfx = mfib_entry_get_prefix (mfib_entry_index);
  rpaths = mfib_entry_encode (mfib_entry_index);

  path_count = vec_len (rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_MROUTE_DETAILS);
  mp->context = context;

  ip_mprefix_encode (pfx, &mp->route.prefix);
  mp->route.table_id =
    htonl (mfib_table_get_table_id
	   (mfib_entry_get_fib_index (mfib_entry_index), pfx->fp_proto));
  mp->route.n_paths = htonl (path_count);
  fp = mp->route.paths;
  vec_foreach (rpath, rpaths)
  {
    mfib_api_path_encode (rpath, fp);
    fp++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
  vec_free (rpaths);
}

static void
vl_api_ip_mroute_dump_t_handler (vl_api_ip_mroute_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  fib_node_index_t *mfeip;
  fib_protocol_t fproto;
  u32 fib_index;

  vl_api_ip_mfib_dump_ctx_t ctx = {
    .entries = NULL,
  };

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  fproto = fib_ip_proto (mp->table.is_ip6);
  fib_index = mfib_table_find (fproto, ntohl (mp->table.table_id));

  if (INDEX_INVALID == fib_index)
    return;

  mfib_table_walk (fib_index, fproto, mfib_route_dump_walk, &ctx);

  vec_sort_with_function (ctx.entries, mfib_entry_cmp_for_sort);

  vec_foreach (mfeip, ctx.entries)
  {
    send_ip_mroute_details (am, reg, mp->context, *mfeip);
  }

  vec_free (ctx.entries);
}

static void
vl_api_ip_punt_police_t_handler (vl_api_ip_punt_police_t * mp,
				 vlib_main_t * vm)
{
  vl_api_ip_punt_police_reply_t *rmp;
  int rv = 0;

  if (mp->is_ip6)
    ip6_punt_policer_add_del (mp->is_add, ntohl (mp->policer_index));
  else
    ip4_punt_policer_add_del (mp->is_add, ntohl (mp->policer_index));

  REPLY_MACRO (VL_API_IP_PUNT_POLICE_REPLY);
}

static void
vl_api_ip_punt_redirect_t_handler (vl_api_ip_punt_redirect_t * mp,
				   vlib_main_t * vm)
{
  vl_api_ip_punt_redirect_reply_t *rmp;
  int rv = 0;
  ip46_type_t ipv;
  ip46_address_t nh;

  if (!vnet_sw_if_index_is_api_valid (ntohl (mp->punt.tx_sw_if_index)))
    goto bad_sw_if_index;

  ipv = ip_address_decode (&mp->punt.nh, &nh);
  if (mp->is_add)
    {
      if (ipv == IP46_TYPE_IP6)
	{
	  ip6_punt_redirect_add (ntohl (mp->punt.rx_sw_if_index),
				 ntohl (mp->punt.tx_sw_if_index), &nh);
	}
      else if (ipv == IP46_TYPE_IP4)
	{
	  ip4_punt_redirect_add (ntohl (mp->punt.rx_sw_if_index),
				 ntohl (mp->punt.tx_sw_if_index), &nh);
	}
    }
  else
    {
      if (ipv == IP46_TYPE_IP6)
	{
	  ip6_punt_redirect_del (ntohl (mp->punt.rx_sw_if_index));
	}
      else if (ipv == IP46_TYPE_IP4)
	{
	  ip4_punt_redirect_del (ntohl (mp->punt.rx_sw_if_index));
	}
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IP_PUNT_REDIRECT_REPLY);
}

void
ip_table_delete (fib_protocol_t fproto, u32 table_id, u8 is_api)
{
  u32 fib_index, mfib_index;

  /*
   * ignore action on the default table - this is always present
   * and cannot be added nor deleted from the API
   */
  if (0 != table_id)
    {
      /*
       * The API holds only one lock on the table.
       * i.e. it can be added many times via the API but needs to be
       * deleted only once.
       * The FIB index for unicast and multicast is not necessarily the
       * same, since internal VPP systesm (like LISP and SR) create
       * their own unicast tables.
       */
      fib_index = fib_table_find (fproto, table_id);
      mfib_index = mfib_table_find (fproto, table_id);

      if (~0 != fib_index)
	{
	  fib_table_unlock (fib_index, fproto,
			    (is_api ? FIB_SOURCE_API : FIB_SOURCE_CLI));
	}
      if (~0 != mfib_index)
	{
	  mfib_table_unlock (mfib_index, fproto,
			     (is_api ? MFIB_SOURCE_API : MFIB_SOURCE_CLI));
	}
    }
}

void
vl_api_ip_table_add_del_t_handler (vl_api_ip_table_add_del_t * mp)
{
  vl_api_ip_table_add_del_reply_t *rmp;
  fib_protocol_t fproto = (mp->table.is_ip6 ?
			   FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  u32 table_id = ntohl (mp->table.table_id);
  int rv = 0;

  if (mp->is_add)
    {
      ip_table_create (fproto, table_id, 1, mp->table.name);
    }
  else
    {
      ip_table_delete (fproto, table_id, 1);
    }

  REPLY_MACRO (VL_API_IP_TABLE_ADD_DEL_REPLY);
}

static int
ip_route_add_del_t_handler (vl_api_ip_route_add_del_t * mp, u32 * stats_index)
{
  fib_route_path_t *rpaths = NULL, *rpath;
  fib_entry_flag_t entry_flags;
  vl_api_fib_path_t *apath;
  fib_prefix_t pfx;
  u32 fib_index;
  int rv, ii;

  entry_flags = FIB_ENTRY_FLAG_NONE;
  ip_prefix_decode (&mp->route.prefix, &pfx);

  rv = fib_api_table_id_decode (pfx.fp_proto,
				ntohl (mp->route.table_id), &fib_index);
  if (0 != rv)
    goto out;

  if (0 != mp->route.n_paths)
    vec_validate (rpaths, mp->route.n_paths - 1);

  for (ii = 0; ii < mp->route.n_paths; ii++)
    {
      apath = &mp->route.paths[ii];
      rpath = &rpaths[ii];

      rv = fib_api_path_decode (apath, rpath);

      if ((rpath->frp_flags & FIB_ROUTE_PATH_LOCAL) &&
	  (~0 == rpath->frp_sw_if_index))
	entry_flags |= (FIB_ENTRY_FLAG_CONNECTED | FIB_ENTRY_FLAG_LOCAL);

      if (0 != rv)
	goto out;
    }

  rv = fib_api_route_add_del (mp->is_add,
			      mp->is_multipath,
			      fib_index, &pfx, entry_flags, rpaths);

  if (mp->is_add && 0 == rv)
    *stats_index = fib_table_entry_get_stats_index (fib_index, &pfx);

out:
  vec_free (rpaths);

  return (rv);
}

void
vl_api_ip_route_add_del_t_handler (vl_api_ip_route_add_del_t * mp)
{
  vl_api_ip_route_add_del_reply_t *rmp;
  u32 stats_index = ~0;
  int rv;

  rv = ip_route_add_del_t_handler (mp, &stats_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IP_ROUTE_ADD_DEL_REPLY,
  ({
    rmp->stats_index = htonl (stats_index);
  }))
  /* *INDENT-ON* */
}

void
ip_table_create (fib_protocol_t fproto,
		 u32 table_id, u8 is_api, const u8 * name)
{
  u32 fib_index, mfib_index;

  /*
   * ignore action on the default table - this is always present
   * and cannot be added nor deleted from the API
   */
  if (0 != table_id)
    {
      /*
       * The API holds only one lock on the table.
       * i.e. it can be added many times via the API but needs to be
       * deleted only once.
       * The FIB index for unicast and multicast is not necessarily the
       * same, since internal VPP systesm (like LISP and SR) create
       * their own unicast tables.
       */
      fib_index = fib_table_find (fproto, table_id);
      mfib_index = mfib_table_find (fproto, table_id);

      if (~0 == fib_index)
	{
	  fib_table_find_or_create_and_lock_w_name (fproto, table_id,
						    (is_api ?
						     FIB_SOURCE_API :
						     FIB_SOURCE_CLI), name);
	}
      if (~0 == mfib_index)
	{
	  mfib_table_find_or_create_and_lock_w_name (fproto, table_id,
						     (is_api ?
						      MFIB_SOURCE_API :
						      MFIB_SOURCE_CLI), name);
	}
    }
}

static u32
mroute_add_del_handler (u8 is_add,
			u8 is_multipath,
			u32 fib_index,
			const mfib_prefix_t * prefix,
			u32 entry_flags,
			u32 rpf_id, fib_route_path_t * rpaths)
{
  u32 mfib_entry_index = ~0;

  if (0 == vec_len (rpaths))
    {
      mfib_entry_index = mfib_table_entry_update (fib_index, prefix,
						  MFIB_SOURCE_API,
						  rpf_id, entry_flags);
    }
  else
    {
      if (is_add)
	{
	  mfib_entry_index =
	    mfib_table_entry_paths_update (fib_index, prefix,
					   MFIB_SOURCE_API, rpaths);
	}
      else
	{
	  mfib_table_entry_paths_remove (fib_index, prefix,
					 MFIB_SOURCE_API, rpaths);
	}
    }

  return (mfib_entry_index);
}

static int
api_mroute_add_del_t_handler (vl_api_ip_mroute_add_del_t * mp,
			      u32 * stats_index)
{
  fib_route_path_t *rpath, *rpaths = NULL;
  fib_node_index_t mfib_entry_index;
  mfib_prefix_t pfx;
  u32 fib_index;
  int rv;
  u16 ii;

  ip_mprefix_decode (&mp->route.prefix, &pfx);

  rv = mfib_api_table_id_decode (pfx.fp_proto,
				 ntohl (mp->route.table_id), &fib_index);
  if (0 != rv)
    goto out;

  vec_validate (rpaths, mp->route.n_paths - 1);

  for (ii = 0; ii < mp->route.n_paths; ii++)
    {
      rpath = &rpaths[ii];

      rv = mfib_api_path_decode (&mp->route.paths[ii], rpath);

      if (0 != rv)
	goto out;
    }

  mfib_entry_index = mroute_add_del_handler (mp->is_add,
					     mp->is_add,
					     fib_index, &pfx,
					     ntohl (mp->route.entry_flags),
					     ntohl (mp->route.rpf_id),
					     rpaths);

  if (~0 != mfib_entry_index)
    *stats_index = mfib_entry_get_stats_index (mfib_entry_index);

out:
  return (rv);
}

void
vl_api_ip_mroute_add_del_t_handler (vl_api_ip_mroute_add_del_t * mp)
{
  vl_api_ip_mroute_add_del_reply_t *rmp;
  u32 stats_index = ~0;
  int rv;

  rv = api_mroute_add_del_t_handler (mp, &stats_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IP_MROUTE_ADD_DEL_REPLY,
  ({
    rmp->stats_index = htonl (stats_index);
  }));
  /* *INDENT-ON* */
}

static void
send_ip_details (vpe_api_main_t * am,
		 vl_api_registration_t * reg, u32 sw_if_index, u8 is_ipv6,
		 u32 context)
{
  vl_api_ip_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_DETAILS);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = is_ipv6;
  mp->context = context;

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
send_ip_address_details (vpe_api_main_t * am,
			 vl_api_registration_t * reg,
			 const fib_prefix_t * pfx,
			 u32 sw_if_index, u32 context)
{
  vl_api_ip_address_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ADDRESS_DETAILS);

  ip_prefix_encode (pfx, &mp->prefix);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ip_address_dump_t_handler (vl_api_ip_address_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  ip6_main_t *im6 = &ip6_main;
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_interface_address_t *ia = 0;
  u32 sw_if_index = ~0;
  int rv __attribute__ ((unused)) = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->is_ipv6)
    {
      /* *INDENT-OFF* */
      /* Do not send subnet details of the IP-interface for
       * unnumbered interfaces. otherwise listening clients
       * will be confused that the subnet is applied on more
       * than one interface */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 0,
      ({
        fib_prefix_t pfx = {
          .fp_addr.ip6 = *(ip6_address_t *)ip_interface_address_get_address (lm6, ia),
          .fp_len = ia->address_length,
          .fp_proto = FIB_PROTOCOL_IP6,
        };
        send_ip_address_details(am, reg, &pfx, sw_if_index, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 0,
      ({
        fib_prefix_t pfx = {
          .fp_addr.ip4 = *(ip4_address_t *)ip_interface_address_get_address (lm4, ia),
          .fp_len = ia->address_length,
          .fp_proto = FIB_PROTOCOL_IP4,
        };

        send_ip_address_details(am, reg, &pfx, sw_if_index, mp->context);
      }));
      /* *INDENT-ON* */
    }

  BAD_SW_IF_INDEX_LABEL;
}

static void
send_ip_unnumbered_details (vpe_api_main_t * am,
			    vl_api_registration_t * reg,
			    u32 sw_if_index, u32 ip_sw_if_index, u32 context)
{
  vl_api_ip_unnumbered_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_UNNUMBERED_DETAILS);

  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->ip_sw_if_index = htonl (ip_sw_if_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ip_unnumbered_dump_t_handler (vl_api_ip_unnumbered_dump_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  int rv __attribute__ ((unused)) = 0;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  vnet_sw_interface_t *si;
  u32 sw_if_index;

  sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (~0 != sw_if_index)
    {
      VALIDATE_SW_IF_INDEX (mp);

      si = vnet_get_sw_interface (vnm, ntohl (mp->sw_if_index));

      if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	{
	  send_ip_unnumbered_details (am, reg,
				      sw_if_index,
				      si->unnumbered_sw_if_index,
				      mp->context);
	}
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (si, im->sw_interfaces,
      ({
        if ((si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED))
          {
            send_ip_unnumbered_details(am, reg,
                                       si->sw_if_index,
                                       si->unnumbered_sw_if_index,
                                       mp->context);
          }
      }));
      /* *INDENT-ON* */
    }

  BAD_SW_IF_INDEX_LABEL;
}

static void
vl_api_ip_dump_t_handler (vl_api_ip_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  //vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vl_api_registration_t *reg;
  vnet_sw_interface_t *si, *sorted_sis;
  u32 sw_if_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* Gather interfaces. */
  sorted_sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
  _vec_len (sorted_sis) = 0;
  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces,
  ({
    vec_add1 (sorted_sis, si[0]);
  }));
  /* *INDENT-ON* */

  vec_foreach (si, sorted_sis)
  {
    if (!(si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED))
      {
	/* if (mp->is_ipv6 && !ip6_interface_enabled (vm, si->sw_if_index)) */
	/*   { */
	/*     continue; */
	/*   } */
	sw_if_index = si->sw_if_index;
	send_ip_details (am, reg, sw_if_index, mp->is_ipv6, mp->context);
      }
  }

  vec_free (sorted_sis);
}

static void
set_ip6_flow_hash (vl_api_set_ip_flow_hash_t * mp)
{
  vl_api_set_ip_flow_hash_reply_t *rmp;
  int rv;
  u32 table_id;
  flow_hash_config_t flow_hash_config = 0;

  table_id = ntohl (mp->vrf_id);

#define _(a,b) if (mp->a) flow_hash_config |= b;
  foreach_flow_hash_bit;
#undef _

  rv = vnet_set_ip6_flow_hash (table_id, flow_hash_config);

  REPLY_MACRO (VL_API_SET_IP_FLOW_HASH_REPLY);
}

static void
set_ip4_flow_hash (vl_api_set_ip_flow_hash_t * mp)
{
  vl_api_set_ip_flow_hash_reply_t *rmp;
  int rv;
  u32 table_id;
  flow_hash_config_t flow_hash_config = 0;

  table_id = ntohl (mp->vrf_id);

#define _(a,b) if (mp->a) flow_hash_config |= b;
  foreach_flow_hash_bit;
#undef _

  rv = vnet_set_ip4_flow_hash (table_id, flow_hash_config);

  REPLY_MACRO (VL_API_SET_IP_FLOW_HASH_REPLY);
}


static void
vl_api_set_ip_flow_hash_t_handler (vl_api_set_ip_flow_hash_t * mp)
{
  if (mp->is_ipv6 == 0)
    set_ip4_flow_hash (mp);
  else
    set_ip6_flow_hash (mp);
}

void
vl_mfib_signal_send_one (vl_api_registration_t * reg,
			 u32 context, const mfib_signal_t * mfs)
{
  vl_api_mfib_signal_details_t *mp;
  const mfib_prefix_t *prefix;
  mfib_table_t *mfib;
  mfib_itf_t *mfi;

  mp = vl_msg_api_alloc (sizeof (*mp));

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MFIB_SIGNAL_DETAILS);
  mp->context = context;

  mfi = mfib_itf_get (mfs->mfs_itf);
  prefix = mfib_entry_get_prefix (mfs->mfs_entry);
  mfib = mfib_table_get (mfib_entry_get_fib_index (mfs->mfs_entry),
			 prefix->fp_proto);
  mp->table_id = ntohl (mfib->mft_table_id);
  mp->sw_if_index = ntohl (mfi->mfi_sw_if_index);

  ip_mprefix_encode (prefix, &mp->prefix);

  if (0 != mfs->mfs_buffer_len)
    {
      mp->ip_packet_len = ntohs (mfs->mfs_buffer_len);

      memcpy (mp->ip_packet_data, mfs->mfs_buffer, mfs->mfs_buffer_len);
    }
  else
    {
      mp->ip_packet_len = 0;
    }

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_mfib_signal_dump_t_handler (vl_api_mfib_signal_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  while (vl_api_can_send_msg (reg) && mfib_signal_send_one (reg, mp->context))
    ;
}

static void
  vl_api_ip_container_proxy_add_del_t_handler
  (vl_api_ip_container_proxy_add_del_t * mp)
{
  vl_api_ip_container_proxy_add_del_reply_t *rmp;
  vnet_ip_container_proxy_args_t args;
  int rv = 0;
  clib_error_t *error;

  clib_memset (&args, 0, sizeof (args));

  ip_prefix_decode (&mp->pfx, &args.prefix);

  args.sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  args.is_add = mp->is_add;
  if ((error = vnet_ip_container_proxy_add_del (&args)))
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }

  REPLY_MACRO (VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY);
}

typedef struct ip_container_proxy_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ip_container_proxy_walk_ctx_t;

static int
ip_container_proxy_send_details (const fib_prefix_t * pfx, u32 sw_if_index,
				 void *args)
{
  vl_api_ip_container_proxy_details_t *mp;
  ip_container_proxy_walk_ctx_t *ctx = args;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_CONTAINER_PROXY_DETAILS);
  mp->context = ctx->context;

  mp->sw_if_index = ntohl (sw_if_index);
  ip_prefix_encode (pfx, &mp->prefix);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return 1;
}

static void
vl_api_ip_container_proxy_dump_t_handler (vl_api_ip_container_proxy_dump_t *
					  mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  ip_container_proxy_walk_ctx_t ctx = {
    .context = mp->context,
    .reg = reg,
  };

  ip_container_proxy_walk (ip_container_proxy_send_details, &ctx);
}

static void
vl_api_ioam_enable_t_handler (vl_api_ioam_enable_t * mp)
{
  int rv = 0;
  vl_api_ioam_enable_reply_t *rmp;
  clib_error_t *error;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = ip6_ioam_enable (mp->trace_enable, mp->pot_enable,
			   mp->seqno, mp->analyse);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_IOAM_ENABLE_REPLY);
}

static void
vl_api_ioam_disable_t_handler (vl_api_ioam_disable_t * mp)
{
  int rv = 0;
  vl_api_ioam_disable_reply_t *rmp;
  clib_error_t *error;

  error = clear_ioam_rewrite_fn ();
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_IOAM_DISABLE_REPLY);
}

static void
  vl_api_ip_source_and_port_range_check_add_del_t_handler
  (vl_api_ip_source_and_port_range_check_add_del_t * mp)
{
  vl_api_ip_source_and_port_range_check_add_del_reply_t *rmp;
  int rv = 0;

  u8 is_add = mp->is_add;
  fib_prefix_t pfx;
  u16 *low_ports = 0;
  u16 *high_ports = 0;
  u32 vrf_id;
  u16 tmp_low, tmp_high;
  u8 num_ranges;
  int i;

  ip_prefix_decode (&mp->prefix, &pfx);

  // Validate port range
  num_ranges = mp->number_of_ranges;
  if (num_ranges > 32)
    {				// This is size of array in VPE.API
      rv = VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;
      goto reply;
    }

  vec_reset_length (low_ports);
  vec_reset_length (high_ports);

  for (i = 0; i < num_ranges; i++)
    {
      tmp_low = mp->low_ports[i];
      tmp_high = mp->high_ports[i];
      // If tmp_low <= tmp_high then only need to check tmp_low = 0
      // If tmp_low <= tmp_high then only need to check tmp_high > 65535
      if (tmp_low > tmp_high || tmp_low == 0 || tmp_high > 65535)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto reply;
	}
      vec_add1 (low_ports, tmp_low);
      vec_add1 (high_ports, tmp_high + 1);
    }

  vrf_id = ntohl (mp->vrf_id);

  if (vrf_id < 1)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }


  if (FIB_PROTOCOL_IP6 == pfx.fp_proto)
    {
      rv = ip6_source_and_port_range_check_add_del (&pfx.fp_addr.ip6,
						    pfx.fp_len,
						    vrf_id,
						    low_ports,
						    high_ports, is_add);
    }
  else
    {
      rv = ip4_source_and_port_range_check_add_del (&pfx.fp_addr.ip4,
						    pfx.fp_len,
						    vrf_id,
						    low_ports,
						    high_ports, is_add);
    }

reply:
  vec_free (low_ports);
  vec_free (high_ports);
  REPLY_MACRO (VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY);
}

static void
  vl_api_ip_source_and_port_range_check_interface_add_del_t_handler
  (vl_api_ip_source_and_port_range_check_interface_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *rmp;
  ip4_main_t *im = &ip4_main;
  int rv;
  u32 sw_if_index;
  u32 fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  u32 vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  uword *p = 0;
  int i;

  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT] =
    ntohl (mp->tcp_out_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT] =
    ntohl (mp->udp_out_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN] =
    ntohl (mp->tcp_in_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN] =
    ntohl (mp->udp_in_vrf_id);


  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
    {
      if (vrf_id[i] != 0 && vrf_id[i] != ~0)
	{
	  p = hash_get (im->fib_index_by_table_id, vrf_id[i]);

	  if (p == 0)
	    {
	      rv = VNET_API_ERROR_INVALID_VALUE;
	      goto reply;
	    }

	  fib_index[i] = p[0];
	}
      else
	fib_index[i] = ~0;
    }
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    set_ip_source_and_port_range_check (vm, fib_index, sw_if_index,
					mp->is_add);

  BAD_SW_IF_INDEX_LABEL;
reply:

  REPLY_MACRO (VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY);
}

static void
  vl_api_sw_interface_ip6_set_link_local_address_t_handler
  (vl_api_sw_interface_ip6_set_link_local_address_t * mp)
{
  vl_api_sw_interface_ip6_set_link_local_address_reply_t *rmp;
  ip6_address_t ip;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  ip6_address_decode (mp->ip, &ip);

  rv = ip6_set_link_local_address (ntohl (mp->sw_if_index), &ip);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY);
}

typedef union
{
  u32 fib_index;
} ip4_source_check_config_t;

static void
  vl_api_ip_source_check_interface_add_del_t_handler
  (vl_api_ip_source_check_interface_add_del_t * mp)
{
  vl_api_ip_source_check_interface_add_del_reply_t *rmp;
  int rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 is_add = mp->is_add;
  char *feature_name =
    mp->loose ? "ip4-source-check-via-any" : "ip4-source-check-via-rx";

  ip4_source_check_config_t config;

  VALIDATE_SW_IF_INDEX (mp);

  config.fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
  rv =
    vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index,
				 is_add, &config, sizeof (config));
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IP_SOURCE_CHECK_INTERFACE_ADD_DEL_REPLY);
}


static void
vl_api_ip_table_replace_begin_t_handler (vl_api_ip_table_replace_begin_t * mp)
{
  vl_api_ip_table_replace_begin_reply_t *rmp;
  fib_protocol_t fproto;
  u32 fib_index;
  int rv = 0;

  fproto = (mp->table.is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  fib_index = fib_table_find (fproto, ntohl (mp->table.table_id));

  if (INDEX_INVALID == fib_index)
    rv = VNET_API_ERROR_NO_SUCH_FIB;
  else
    {
      fib_table_mark (fib_index, fproto, FIB_SOURCE_API);
      mfib_table_mark (mfib_table_find (fproto, ntohl (mp->table.table_id)),
		       fproto, MFIB_SOURCE_API);
    }
  REPLY_MACRO (VL_API_IP_TABLE_REPLACE_BEGIN_REPLY);
}

static void
vl_api_ip_table_replace_end_t_handler (vl_api_ip_table_replace_end_t * mp)
{
  vl_api_ip_table_replace_end_reply_t *rmp;
  fib_protocol_t fproto;
  u32 fib_index;
  int rv = 0;

  fproto = (mp->table.is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  fib_index = fib_table_find (fproto, ntohl (mp->table.table_id));

  if (INDEX_INVALID == fib_index)
    rv = VNET_API_ERROR_NO_SUCH_FIB;
  else
    {
      fib_table_sweep (fib_index, fproto, FIB_SOURCE_API);
      mfib_table_sweep (mfib_table_find
			(fproto, ntohl (mp->table.table_id)), fproto,
			MFIB_SOURCE_API);
    }
  REPLY_MACRO (VL_API_IP_TABLE_REPLACE_END_REPLY);
}

static void
vl_api_ip_table_flush_t_handler (vl_api_ip_table_flush_t * mp)
{
  vl_api_ip_table_flush_reply_t *rmp;
  fib_protocol_t fproto;
  u32 fib_index;
  int rv = 0;

  fproto = (mp->table.is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  fib_index = fib_table_find (fproto, ntohl (mp->table.table_id));

  if (INDEX_INVALID == fib_index)
    rv = VNET_API_ERROR_NO_SUCH_FIB;
  else
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_interface_main_t *im = &vnm->interface_main;
      vnet_sw_interface_t *si;

      /* Shut down interfaces in this FIB / clean out intfc routes */
      /* *INDENT-OFF* */
      pool_foreach (si, im->sw_interfaces,
      ({
        if (fib_index == fib_table_get_index_for_sw_if_index (fproto,
                                                              si->sw_if_index))
          {
            u32 flags = si->flags;
            flags &= ~VNET_SW_INTERFACE_FLAG_ADMIN_UP;
            vnet_sw_interface_set_flags (vnm, si->sw_if_index, flags);
          }
      }));
      /* *INDENT-ON* */

      fib_table_flush (fib_index, fproto, FIB_SOURCE_API);
      mfib_table_flush (mfib_table_find (fproto, ntohl (mp->table.table_id)),
			fproto, MFIB_SOURCE_API);
    }

  REPLY_MACRO (VL_API_IP_TABLE_FLUSH_REPLY);
}

void
vl_api_ip_reassembly_set_t_handler (vl_api_ip_reassembly_set_t * mp)
{
  vl_api_ip_reassembly_set_reply_t *rmp;
  int rv = 0;
  switch ((vl_api_ip_reass_type_t) clib_net_to_host_u32 (mp->type))
    {
    case IP_REASS_TYPE_FULL:
      if (mp->is_ip6)
	{
	  rv = ip6_full_reass_set (clib_net_to_host_u32 (mp->timeout_ms),
				   clib_net_to_host_u32
				   (mp->max_reassemblies),
				   clib_net_to_host_u32
				   (mp->max_reassembly_length),
				   clib_net_to_host_u32
				   (mp->expire_walk_interval_ms));
	}
      else
	{
	  rv = ip4_full_reass_set (clib_net_to_host_u32 (mp->timeout_ms),
				   clib_net_to_host_u32
				   (mp->max_reassemblies),
				   clib_net_to_host_u32
				   (mp->max_reassembly_length),
				   clib_net_to_host_u32
				   (mp->expire_walk_interval_ms));
	}
      break;
    case IP_REASS_TYPE_SHALLOW_VIRTUAL:
      if (mp->is_ip6)
	{
	  rv =
	    ip6_sv_reass_set (clib_net_to_host_u32 (mp->timeout_ms),
			      clib_net_to_host_u32 (mp->max_reassemblies),
			      clib_net_to_host_u32
			      (mp->max_reassembly_length),
			      clib_net_to_host_u32
			      (mp->expire_walk_interval_ms));
	}
      else
	{
	  rv = ip4_sv_reass_set (clib_net_to_host_u32 (mp->timeout_ms),
				 clib_net_to_host_u32 (mp->max_reassemblies),
				 clib_net_to_host_u32
				 (mp->max_reassembly_length),
				 clib_net_to_host_u32
				 (mp->expire_walk_interval_ms));
	}
      break;
    }

  REPLY_MACRO (VL_API_IP_REASSEMBLY_SET_REPLY);
}

void
vl_api_ip_reassembly_get_t_handler (vl_api_ip_reassembly_get_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  vl_api_ip_reassembly_get_reply_t *rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IP_REASSEMBLY_GET_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;
  u32 timeout_ms;
  u32 max_reassemblies;
  u32 max_reassembly_length;
  u32 expire_walk_interval_ms;
  switch ((vl_api_ip_reass_type_t) clib_net_to_host_u32 (mp->type))
    {
    case IP_REASS_TYPE_FULL:
      if (mp->is_ip6)
	{
	  rmp->is_ip6 = 1;
	  ip6_full_reass_get (&timeout_ms, &max_reassemblies,
			      &max_reassembly_length,
			      &expire_walk_interval_ms);
	}
      else
	{
	  rmp->is_ip6 = 0;
	  ip4_full_reass_get (&timeout_ms, &max_reassemblies,
			      &max_reassembly_length,
			      &expire_walk_interval_ms);
	}
      break;
    case IP_REASS_TYPE_SHALLOW_VIRTUAL:
      if (mp->is_ip6)
	{
	  rmp->is_ip6 = 1;
	  ip6_sv_reass_get (&timeout_ms, &max_reassemblies,
			    &max_reassembly_length, &expire_walk_interval_ms);
	}
      else
	{
	  rmp->is_ip6 = 0;
	  ip4_sv_reass_get (&timeout_ms, &max_reassemblies,
			    &max_reassembly_length, &expire_walk_interval_ms);
	}
      break;
    }
  rmp->timeout_ms = clib_host_to_net_u32 (timeout_ms);
  rmp->max_reassemblies = clib_host_to_net_u32 (max_reassemblies);
  rmp->max_reassembly_length = clib_host_to_net_u32 (max_reassembly_length);
  rmp->expire_walk_interval_ms =
    clib_host_to_net_u32 (expire_walk_interval_ms);
  vl_api_send_msg (rp, (u8 *) rmp);
}

void
  vl_api_ip_reassembly_enable_disable_t_handler
  (vl_api_ip_reassembly_enable_disable_t * mp)
{
  vl_api_ip_reassembly_enable_disable_reply_t *rmp;
  int rv = 0;
  switch ((vl_api_ip_reass_type_t) clib_net_to_host_u32 (mp->type))
    {
    case IP_REASS_TYPE_FULL:
      rv =
	ip4_full_reass_enable_disable (clib_net_to_host_u32 (mp->sw_if_index),
				       mp->enable_ip4);
      if (0 == rv)
	rv =
	  ip6_full_reass_enable_disable (clib_net_to_host_u32
					 (mp->sw_if_index), mp->enable_ip6);
      break;
    case IP_REASS_TYPE_SHALLOW_VIRTUAL:
      rv =
	ip4_sv_reass_enable_disable (clib_net_to_host_u32 (mp->sw_if_index),
				     mp->enable_ip4);
      if (0 == rv)
	{
	  rv =
	    ip6_sv_reass_enable_disable (clib_net_to_host_u32
					 (mp->sw_if_index), mp->enable_ip6);
	}
      break;
    }

  REPLY_MACRO (VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY);
}

typedef struct ip_punt_redirect_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ip_punt_redirect_walk_ctx_t;

static walk_rc_t
send_ip_punt_redirect_details (u32 rx_sw_if_index,
			       const ip_punt_redirect_rx_t * ipr, void *arg)
{
  ip_punt_redirect_walk_ctx_t *ctx = arg;
  vl_api_ip_punt_redirect_details_t *mp;
  fib_path_encode_ctx_t path_ctx = {
    .rpaths = NULL,
  };

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (WALK_STOP);;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_PUNT_REDIRECT_DETAILS);
  mp->context = ctx->context;

  fib_path_list_walk_w_ext (ipr->pl, NULL, fib_path_encode, &path_ctx);

  mp->punt.rx_sw_if_index = htonl (rx_sw_if_index);
  mp->punt.tx_sw_if_index = htonl (path_ctx.rpaths[0].frp_sw_if_index);

  ip_address_encode (&path_ctx.rpaths[0].frp_addr,
		     fib_proto_to_ip46 (ipr->fproto), &mp->punt.nh);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  vec_free (path_ctx.rpaths);

  return (WALK_CONTINUE);
}

static void
vl_api_ip_punt_redirect_dump_t_handler (vl_api_ip_punt_redirect_dump_t * mp)
{
  vl_api_registration_t *reg;
  fib_protocol_t fproto;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  fproto = mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;

  ip_punt_redirect_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  if (~0 != mp->sw_if_index)
    {
      u32 rx_sw_if_index;
      index_t pri;

      rx_sw_if_index = ntohl (mp->sw_if_index);
      pri = ip_punt_redirect_find (fproto, rx_sw_if_index);

      if (INDEX_INVALID == pri)
	return;

      send_ip_punt_redirect_details (rx_sw_if_index,
				     ip_punt_redirect_get (pri), &ctx);
    }
  else
    ip_punt_redirect_walk (fproto, send_ip_punt_redirect_details, &ctx);
}

#define vl_msg_name_crc_list
#include <vnet/ip/ip.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_ip;
#undef _
}

static clib_error_t *
ip_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ip_api_msg;
#undef _

  /*
   * Mark the route add/del API as MP safe
   */
  am->is_mp_safe[VL_API_IP_ROUTE_ADD_DEL] = 1;
  am->is_mp_safe[VL_API_IP_ROUTE_ADD_DEL_REPLY] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (ip_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
