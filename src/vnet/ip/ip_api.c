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
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_api.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/mfib/mfib_signal.h>
#include <vnet/mfib/mfib_entry.h>

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


#define foreach_ip_api_msg                                              \
_(IP_FIB_DUMP, ip_fib_dump)                                             \
_(IP6_FIB_DUMP, ip6_fib_dump)                                           \
_(IP_MFIB_DUMP, ip_mfib_dump)                                           \
_(IP6_MFIB_DUMP, ip6_mfib_dump)                                         \
_(IP_NEIGHBOR_DUMP, ip_neighbor_dump)                                   \
_(IP_MROUTE_ADD_DEL, ip_mroute_add_del)                                 \
_(MFIB_SIGNAL_DUMP, mfib_signal_dump)                                   \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_DUMP, ip_dump)                                                     \
_(IP_NEIGHBOR_ADD_DEL, ip_neighbor_add_del)                             \
_(IP_ADD_DEL_ROUTE, ip_add_del_route)                                   \
_(IP_TABLE_ADD_DEL, ip_table_add_del)                                   \
_(SET_IP_FLOW_HASH,set_ip_flow_hash)                                    \
_(SW_INTERFACE_IP6ND_RA_CONFIG, sw_interface_ip6nd_ra_config)           \
_(SW_INTERFACE_IP6ND_RA_PREFIX, sw_interface_ip6nd_ra_prefix)           \
_(IP6ND_PROXY_ADD_DEL, ip6nd_proxy_add_del)                             \
_(IP6ND_PROXY_DUMP, ip6nd_proxy_dump)                                   \
_(SW_INTERFACE_IP6_ENABLE_DISABLE, sw_interface_ip6_enable_disable )    \
_(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS, 				\
  sw_interface_ip6_set_link_local_address)

extern void stats_dslock_with_hint (int hint, int tag);
extern void stats_dsunlock (void);

static void
send_ip_neighbor_details (u8 is_ipv6,
			  u8 is_static,
			  u8 * mac_address,
			  u8 * ip_address,
			  unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_ip_neighbor_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_NEIGHBOR_DETAILS);
  mp->context = context;
  mp->is_ipv6 = is_ipv6;
  mp->is_static = is_static;
  memcpy (mp->mac_address, mac_address, 6);
  memcpy (mp->ip_address, ip_address, (is_ipv6) ? 16 : 4);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_ip_neighbor_dump_t_handler (vl_api_ip_neighbor_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (mp->is_ipv6)
    {
      ip6_neighbor_t *n, *ns;

      ns = ip6_neighbors_entries (sw_if_index);
      /* *INDENT-OFF* */
      vec_foreach (n, ns)
      {
        send_ip_neighbor_details
          (mp->is_ipv6, ((n->flags & IP6_NEIGHBOR_FLAG_STATIC) ? 1 : 0),
           (u8 *) n->link_layer_address,
           (u8 *) & (n->key.ip6_address.as_u8),
           q, mp->context);
      }
      /* *INDENT-ON* */
      vec_free (ns);
    }
  else
    {
      ethernet_arp_ip4_entry_t *n, *ns;

      ns = ip4_neighbor_entries (sw_if_index);
      /* *INDENT-OFF* */
      vec_foreach (n, ns)
      {
        send_ip_neighbor_details (mp->is_ipv6,
          ((n->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC) ? 1 : 0),
          (u8*) n->ethernet_address,
          (u8*) & (n->ip4_address.as_u8),
          q, mp->context);
      }
      /* *INDENT-ON* */
      vec_free (ns);
    }
}


void
copy_fib_next_hop (fib_route_path_encode_t * api_rpath, void *fp_arg)
{
  int is_ip4;
  vl_api_fib_path_t *fp = (vl_api_fib_path_t *) fp_arg;

  if (api_rpath->rpath.frp_proto == DPO_PROTO_IP4)
    fp->afi = IP46_TYPE_IP4;
  else if (api_rpath->rpath.frp_proto == DPO_PROTO_IP6)
    fp->afi = IP46_TYPE_IP6;
  else
    {
      is_ip4 = ip46_address_is_ip4 (&api_rpath->rpath.frp_addr);
      if (is_ip4)
	fp->afi = IP46_TYPE_IP4;
      else
	fp->afi = IP46_TYPE_IP6;
    }
  if (fp->afi == IP46_TYPE_IP4)
    memcpy (fp->next_hop, &api_rpath->rpath.frp_addr.ip4,
	    sizeof (api_rpath->rpath.frp_addr.ip4));
  else
    memcpy (fp->next_hop, &api_rpath->rpath.frp_addr.ip6,
	    sizeof (api_rpath->rpath.frp_addr.ip6));
}

static void
send_ip_fib_details (vpe_api_main_t * am,
		     unix_shared_memory_queue_t * q,
		     const fib_table_t * table,
		     const fib_prefix_t * pfx,
		     fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_ip_fib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path_t *fp;
  int path_count;

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_FIB_DETAILS);
  mp->context = context;

  mp->table_id = htonl (table->ft_table_id);
  memcpy (mp->table_name, table->ft_desc,
	  clib_min (vec_len (table->ft_desc), sizeof (mp->table_name)));
  mp->address_length = pfx->fp_len;
  memcpy (mp->address, &pfx->fp_addr.ip4, sizeof (pfx->fp_addr.ip4));

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));
    switch (api_rpath->dpo.dpoi_type)
      {
      case DPO_RECEIVE:
	fp->is_local = true;
	break;
      case DPO_DROP:
	fp->is_drop = true;
	break;
      case DPO_IP_NULL:
	switch (api_rpath->dpo.dpoi_index)
	  {
	  case IP_NULL_ACTION_NONE:
	    fp->is_drop = true;
	    break;
	  case IP_NULL_ACTION_SEND_ICMP_UNREACH:
	    fp->is_unreach = true;
	    break;
	  case IP_NULL_ACTION_SEND_ICMP_PROHIBIT:
	    fp->is_prohibit = true;
	    break;
	  default:
	    break;
	  }
	break;
      default:
	break;
      }
    fp->weight = api_rpath->rpath.frp_weight;
    fp->preference = api_rpath->rpath.frp_preference;
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct vl_api_ip_fib_dump_walk_ctx_t_
{
  fib_node_index_t *feis;
} vl_api_ip_fib_dump_walk_ctx_t;

static int
vl_api_ip_fib_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_ip_fib_dump_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->feis, fei);

  return (1);
}

static void
vl_api_ip_fib_dump_t_handler (vl_api_ip_fib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  ip4_main_t *im = &ip4_main;
  fib_table_t *fib_table;
  fib_node_index_t *lfeip;
  fib_prefix_t pfx;
  u32 fib_index;
  fib_route_path_encode_t *api_rpaths;
  vl_api_ip_fib_dump_walk_ctx_t ctx = {
    .feis = NULL,
  };

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (fib_table, im->fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP4,
                   vl_api_ip_fib_dump_walk,
                   &ctx);
  }));
  /* *INDENT-ON* */

  vec_sort_with_function (ctx.feis, fib_entry_cmp_for_sort);

  vec_foreach (lfeip, ctx.feis)
  {
    fib_entry_get_prefix (*lfeip, &pfx);
    fib_index = fib_entry_get_fib_index (*lfeip);
    fib_table = fib_table_get (fib_index, pfx.fp_proto);
    api_rpaths = NULL;
    fib_entry_encode (*lfeip, &api_rpaths);
    send_ip_fib_details (am, q, fib_table, &pfx, api_rpaths, mp->context);
    vec_free (api_rpaths);
  }

  vec_free (ctx.feis);
}

static void
send_ip6_fib_details (vpe_api_main_t * am,
		      unix_shared_memory_queue_t * q,
		      u32 table_id, fib_prefix_t * pfx,
		      fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_ip6_fib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path_t *fp;
  int path_count;

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP6_FIB_DETAILS);
  mp->context = context;

  mp->table_id = htonl (table_id);
  mp->address_length = pfx->fp_len;
  memcpy (mp->address, &pfx->fp_addr.ip6, sizeof (pfx->fp_addr.ip6));

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));
    switch (api_rpath->dpo.dpoi_type)
      {
      case DPO_RECEIVE:
	fp->is_local = true;
	break;
      case DPO_DROP:
	fp->is_drop = true;
	break;
      case DPO_IP_NULL:
	switch (api_rpath->dpo.dpoi_index)
	  {
	  case IP_NULL_DPO_ACTION_NUM + IP_NULL_ACTION_NONE:
	    fp->is_drop = true;
	    break;
	  case IP_NULL_DPO_ACTION_NUM + IP_NULL_ACTION_SEND_ICMP_UNREACH:
	    fp->is_unreach = true;
	    break;
	  case IP_NULL_DPO_ACTION_NUM + IP_NULL_ACTION_SEND_ICMP_PROHIBIT:
	    fp->is_prohibit = true;
	    break;
	  default:
	    break;
	  }
	break;
      default:
	break;
      }
    fp->weight = api_rpath->rpath.frp_weight;
    fp->preference = api_rpath->rpath.frp_preference;
    fp->sw_if_index = api_rpath->rpath.frp_sw_if_index;
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct apt_ip6_fib_show_ctx_t_
{
  u32 fib_index;
  fib_node_index_t *entries;
} api_ip6_fib_show_ctx_t;

static void
api_ip6_fib_table_put_entries (clib_bihash_kv_24_8_t * kvp, void *arg)
{
  api_ip6_fib_show_ctx_t *ctx = arg;

  if ((kvp->key[2] >> 32) == ctx->fib_index)
    {
      vec_add1 (ctx->entries, kvp->value);
    }
}

static void
api_ip6_fib_table_get_all (unix_shared_memory_queue_t * q,
			   vl_api_ip6_fib_dump_t * mp,
			   fib_table_t * fib_table)
{
  vpe_api_main_t *am = &vpe_api_main;
  ip6_main_t *im6 = &ip6_main;
  fib_node_index_t *fib_entry_index;
  api_ip6_fib_show_ctx_t ctx = {
    .fib_index = fib_table->ft_index,
    .entries = NULL,
  };
  fib_route_path_encode_t *api_rpaths;
  fib_prefix_t pfx;

  BV (clib_bihash_foreach_key_value_pair)
    ((BVT (clib_bihash) *) & im6->ip6_table[IP6_FIB_TABLE_NON_FWDING].
     ip6_hash, api_ip6_fib_table_put_entries, &ctx);

  vec_sort_with_function (ctx.entries, fib_entry_cmp_for_sort);

  vec_foreach (fib_entry_index, ctx.entries)
  {
    fib_entry_get_prefix (*fib_entry_index, &pfx);
    api_rpaths = NULL;
    fib_entry_encode (*fib_entry_index, &api_rpaths);
    send_ip6_fib_details (am, q,
			  fib_table->ft_table_id,
			  &pfx, api_rpaths, mp->context);
    vec_free (api_rpaths);
  }

  vec_free (ctx.entries);
}

static void
vl_api_ip6_fib_dump_t_handler (vl_api_ip6_fib_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  ip6_main_t *im6 = &ip6_main;
  fib_table_t *fib_table;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (fib_table, im6->fibs,
  ({
    api_ip6_fib_table_get_all(q, mp, fib_table);
  }));
  /* *INDENT-ON* */
}

static void
send_ip_mfib_details (unix_shared_memory_queue_t * q,
		      u32 context, u32 table_id, fib_node_index_t mfei)
{
  fib_route_path_encode_t *api_rpath, *api_rpaths = NULL;
  vl_api_ip_mfib_details_t *mp;
  mfib_entry_t *mfib_entry;
  vl_api_fib_path_t *fp;
  mfib_prefix_t pfx;
  int path_count;

  mfib_entry = mfib_entry_get (mfei);
  mfib_entry_get_prefix (mfei, &pfx);
  mfib_entry_encode (mfei, &api_rpaths);

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_FIB_DETAILS);
  mp->context = context;

  mp->rpf_id = mfib_entry->mfe_rpf_id;
  mp->entry_flags = mfib_entry->mfe_flags;
  mp->table_id = htonl (table_id);
  mp->address_length = pfx.fp_len;
  memcpy (mp->grp_address, &pfx.fp_grp_addr.ip4,
	  sizeof (pfx.fp_grp_addr.ip4));
  memcpy (mp->src_address, &pfx.fp_src_addr.ip4,
	  sizeof (pfx.fp_src_addr.ip4));

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));

    fp->weight = 0;
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }
  vec_free (api_rpaths);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct vl_api_ip_mfib_dump_ctc_t_
{
  fib_node_index_t *entries;
} vl_api_ip_mfib_dump_ctc_t;

static int
vl_api_ip_mfib_table_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_ip_mfib_dump_ctc_t *ctx = arg;

  vec_add1 (ctx->entries, fei);

  return (0);
}

static void
vl_api_ip_mfib_dump_t_handler (vl_api_ip_mfib_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  ip4_main_t *im = &ip4_main;
  mfib_table_t *mfib_table;
  fib_node_index_t *mfeip;
  vl_api_ip_mfib_dump_ctc_t ctx = {
    .entries = NULL,
  };

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;


  /* *INDENT-OFF* */
  pool_foreach (mfib_table, im->mfibs,
  ({
    ip4_mfib_table_walk(&mfib_table->v4,
                        vl_api_ip_mfib_table_dump_walk,
                        &ctx);

    vec_sort_with_function (ctx.entries, mfib_entry_cmp_for_sort);

    vec_foreach (mfeip, ctx.entries)
    {
      send_ip_mfib_details (q, mp->context,
                            mfib_table->mft_table_id,
                            *mfeip);
    }
    vec_reset_length (ctx.entries);

  }));
  /* *INDENT-ON* */

  vec_free (ctx.entries);
}

static void
send_ip6_mfib_details (vpe_api_main_t * am,
		       unix_shared_memory_queue_t * q,
		       u32 table_id,
		       mfib_prefix_t * pfx,
		       fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_ip6_mfib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path_t *fp;
  int path_count;

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP6_FIB_DETAILS);
  mp->context = context;

  mp->table_id = htonl (table_id);
  mp->address_length = pfx->fp_len;
  memcpy (mp->grp_address, &pfx->fp_grp_addr.ip6,
	  sizeof (pfx->fp_grp_addr.ip6));
  memcpy (mp->src_address, &pfx->fp_src_addr.ip6,
	  sizeof (pfx->fp_src_addr.ip6));

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));

    fp->weight = 0;
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct vl_api_ip6_mfib_dump_ctc_t_
{
  fib_node_index_t *entries;
} vl_api_ip6_mfib_dump_ctc_t;

static int
vl_api_ip6_mfib_table_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_ip6_mfib_dump_ctc_t *ctx = arg;

  vec_add1 (ctx->entries, fei);

  return (0);
}

static void
vl_api_ip6_mfib_dump_t_handler (vl_api_ip6_mfib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  ip6_main_t *im = &ip6_main;
  mfib_table_t *mfib_table;
  fib_node_index_t *mfeip;
  mfib_prefix_t pfx;
  fib_route_path_encode_t *api_rpaths = NULL;
  vl_api_ip6_mfib_dump_ctc_t ctx = {
    .entries = NULL,
  };

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;


  /* *INDENT-OFF* */
  pool_foreach (mfib_table, im->mfibs,
  ({
    ip6_mfib_table_walk(&mfib_table->v6,
                        vl_api_ip6_mfib_table_dump_walk,
                        &ctx);

    vec_sort_with_function (ctx.entries, mfib_entry_cmp_for_sort);

    vec_foreach(mfeip, ctx.entries)
    {
      mfib_entry_get_prefix (*mfeip, &pfx);
      mfib_entry_encode (*mfeip, &api_rpaths);
      send_ip6_mfib_details (am, q,
                             mfib_table->mft_table_id,
                             &pfx, api_rpaths,
                             mp->context);
    }
    vec_reset_length (api_rpaths);
    vec_reset_length (ctx.entries);

  }));
  /* *INDENT-ON* */

  vec_free (ctx.entries);
  vec_free (api_rpaths);
}

static void
vl_api_ip_neighbor_add_del_t_handler (vl_api_ip_neighbor_add_del_t * mp,
				      vlib_main_t * vm)
{
  vl_api_ip_neighbor_add_del_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  stats_dslock_with_hint (1 /* release hint */ , 7 /* tag */ );

  /*
   * there's no validation here of the ND/ARP entry being added.
   * The expectation is that the FIB will ensure that nothing bad
   * will come of adding bogus entries.
   */
  if (mp->is_ipv6)
    {
      if (mp->is_add)
	rv = vnet_set_ip6_ethernet_neighbor
	  (vm, ntohl (mp->sw_if_index),
	   (ip6_address_t *) (mp->dst_address),
	   mp->mac_address, sizeof (mp->mac_address), mp->is_static,
	   mp->is_no_adj_fib);
      else
	rv = vnet_unset_ip6_ethernet_neighbor
	  (vm, ntohl (mp->sw_if_index),
	   (ip6_address_t *) (mp->dst_address),
	   mp->mac_address, sizeof (mp->mac_address));
    }
  else
    {
      ethernet_arp_ip4_over_ethernet_address_t a;

      clib_memcpy (&a.ethernet, mp->mac_address, 6);
      clib_memcpy (&a.ip4, mp->dst_address, 4);

      if (mp->is_add)
	rv = vnet_arp_set_ip4_over_ethernet (vnm, ntohl (mp->sw_if_index),
					     &a, mp->is_static,
					     mp->is_no_adj_fib);
      else
	rv =
	  vnet_arp_unset_ip4_over_ethernet (vnm, ntohl (mp->sw_if_index), &a);
    }

  BAD_SW_IF_INDEX_LABEL;

  stats_dsunlock ();
  REPLY_MACRO (VL_API_IP_NEIGHBOR_ADD_DEL_REPLY);
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
  fib_protocol_t fproto = (mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  u32 table_id = ntohl (mp->table_id);
  int rv = 0;

  if (mp->is_add)
    {
      ip_table_create (fproto, table_id, 1, mp->name);
    }
  else
    {
      ip_table_delete (fproto, table_id, 1);
    }

  REPLY_MACRO (VL_API_IP_TABLE_ADD_DEL_REPLY);
}

int
add_del_route_t_handler (u8 is_multipath,
			 u8 is_add,
			 u8 is_drop,
			 u8 is_unreach,
			 u8 is_prohibit,
			 u8 is_local,
			 u8 is_multicast,
			 u8 is_classify,
			 u32 classify_table_index,
			 u8 is_resolve_host,
			 u8 is_resolve_attached,
			 u8 is_interface_rx,
			 u8 is_rpf_id,
			 u32 fib_index,
			 const fib_prefix_t * prefix,
			 dpo_proto_t next_hop_proto,
			 const ip46_address_t * next_hop,
			 u32 next_hop_sw_if_index,
			 u8 next_hop_fib_index,
			 u16 next_hop_weight,
			 u16 next_hop_preference,
			 mpls_label_t next_hop_via_label,
			 mpls_label_t * next_hop_out_label_stack)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  fib_route_path_flags_t path_flags = FIB_ROUTE_PATH_FLAG_NONE;
  fib_route_path_t path = {
    .frp_proto = next_hop_proto,
    .frp_addr = (NULL == next_hop ? zero_addr : *next_hop),
    .frp_sw_if_index = next_hop_sw_if_index,
    .frp_fib_index = next_hop_fib_index,
    .frp_weight = next_hop_weight,
    .frp_preference = next_hop_preference,
    .frp_label_stack = next_hop_out_label_stack,
  };
  fib_route_path_t *paths = NULL;
  fib_entry_flag_t entry_flags = FIB_ENTRY_FLAG_NONE;

  /*
   * the special INVALID label meams we are not recursing via a
   * label. Exp-null value is never a valid via-label so that
   * also means it's not a via-label and means clients that set
   * it to 0 by default get the expected behaviour
   */
  if ((MPLS_LABEL_INVALID != next_hop_via_label) &&
      (0 != next_hop_via_label))
    {
      path.frp_proto = DPO_PROTO_MPLS;
      path.frp_local_label = next_hop_via_label;
      path.frp_eos = MPLS_NON_EOS;
    }
  if (is_resolve_host)
    path_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
  if (is_resolve_attached)
    path_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
  if (is_interface_rx)
    path_flags |= FIB_ROUTE_PATH_INTF_RX;
  if (is_rpf_id)
    path_flags |= FIB_ROUTE_PATH_RPF_ID;
  if (is_multicast)
    entry_flags |= FIB_ENTRY_FLAG_MULTICAST;

  path.frp_flags = path_flags;

  if (is_multipath)
    {
      stats_dslock_with_hint (1 /* release hint */ , 10 /* tag */ );


      vec_add1 (paths, path);

      if (is_add)
	fib_table_entry_path_add2 (fib_index,
				   prefix,
				   FIB_SOURCE_API, entry_flags, paths);
      else
	fib_table_entry_path_remove2 (fib_index,
				      prefix, FIB_SOURCE_API, paths);

      vec_free (paths);
      stats_dsunlock ();
      return 0;
    }

  stats_dslock_with_hint (1 /* release hint */ , 2 /* tag */ );

  if (is_drop || is_local || is_classify || is_unreach || is_prohibit)
    {
      /*
       * special route types that link directly to the adj
       */
      if (is_add)
	{
	  dpo_id_t dpo = DPO_INVALID;
	  dpo_proto_t dproto;

	  dproto = fib_proto_to_dpo (prefix->fp_proto);

	  if (is_drop)
	    ip_null_dpo_add_and_lock (dproto, IP_NULL_ACTION_NONE, &dpo);
	  else if (is_local)
	    receive_dpo_add_or_lock (dproto, ~0, NULL, &dpo);
	  else if (is_unreach)
	    ip_null_dpo_add_and_lock (dproto,
				      IP_NULL_ACTION_SEND_ICMP_UNREACH, &dpo);
	  else if (is_prohibit)
	    ip_null_dpo_add_and_lock (dproto,
				      IP_NULL_ACTION_SEND_ICMP_PROHIBIT,
				      &dpo);
	  else if (is_classify)
	    {
	      if (pool_is_free_index (cm->tables,
				      ntohl (classify_table_index)))
		{
		  stats_dsunlock ();
		  return VNET_API_ERROR_NO_SUCH_TABLE;
		}

	      dpo_set (&dpo, DPO_CLASSIFY, dproto,
		       classify_dpo_create (dproto,
					    ntohl (classify_table_index)));
	    }
	  else
	    {
	      stats_dsunlock ();
	      return VNET_API_ERROR_NO_SUCH_TABLE;
	    }

	  fib_table_entry_special_dpo_update (fib_index,
					      prefix,
					      FIB_SOURCE_API,
					      FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
	  dpo_reset (&dpo);
	}
      else
	{
	  fib_table_entry_special_remove (fib_index, prefix, FIB_SOURCE_API);
	}
    }
  else
    {
      if (is_add)
	{
	  vec_add1 (paths, path);
	  fib_table_entry_update (fib_index,
				  prefix, FIB_SOURCE_API, entry_flags, paths);
	  vec_free (paths);
	}
      else
	{
	  fib_table_entry_delete (fib_index, prefix, FIB_SOURCE_API);
	}
    }

  stats_dsunlock ();
  return (0);
}

int
add_del_route_check (fib_protocol_t table_proto,
		     u32 table_id,
		     u32 next_hop_sw_if_index,
		     dpo_proto_t next_hop_table_proto,
		     u32 next_hop_table_id,
		     u8 is_rpf_id, u32 * fib_index, u32 * next_hop_fib_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  /* Temporaray whilst I do the CSIT dance */
  u8 create_missing_tables = 1;

  *fib_index = fib_table_find (table_proto, ntohl (table_id));
  if (~0 == *fib_index)
    {
      if (create_missing_tables)
	{
	  *fib_index = fib_table_find_or_create_and_lock (table_proto,
							  ntohl (table_id),
							  FIB_SOURCE_API);
	}
      else
	{
	  /* No such VRF, and we weren't asked to create one */
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}
    }

  if (!is_rpf_id && ~0 != ntohl (next_hop_sw_if_index))
    {
      if (pool_is_free_index (vnm->interface_main.sw_interfaces,
			      ntohl (next_hop_sw_if_index)))
	{
	  return VNET_API_ERROR_NO_MATCHING_INTERFACE;
	}
    }
  else
    {
      fib_protocol_t fib_nh_proto;

      if (next_hop_table_proto > DPO_PROTO_MPLS)
	return (0);

      fib_nh_proto = dpo_proto_to_fib (next_hop_table_proto);

      if (is_rpf_id)
	*next_hop_fib_index = mfib_table_find (fib_nh_proto,
					       ntohl (next_hop_table_id));
      else
	*next_hop_fib_index = fib_table_find (fib_nh_proto,
					      ntohl (next_hop_table_id));

      if (~0 == *next_hop_fib_index)
	{
	  if (create_missing_tables)
	    {
	      if (is_rpf_id)
		*next_hop_fib_index =
		  mfib_table_find_or_create_and_lock (fib_nh_proto,
						      ntohl
						      (next_hop_table_id),
						      MFIB_SOURCE_API);
	      else
		*next_hop_fib_index =
		  fib_table_find_or_create_and_lock (fib_nh_proto,
						     ntohl
						     (next_hop_table_id),
						     FIB_SOURCE_API);
	    }
	  else
	    {
	      /* No such VRF, and we weren't asked to create one */
	      return VNET_API_ERROR_NO_SUCH_FIB;
	    }
	}
    }

  return (0);
}

static int
ip4_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  u32 fib_index, next_hop_fib_index;
  mpls_label_t *label_stack = NULL;
  int rv, ii, n_labels;;

  rv = add_del_route_check (FIB_PROTOCOL_IP4,
			    mp->table_id,
			    mp->next_hop_sw_if_index,
			    DPO_PROTO_IP4,
			    mp->next_hop_table_id,
			    0, &fib_index, &next_hop_fib_index);

  if (0 != rv)
    return (rv);

  fib_prefix_t pfx = {
    .fp_len = mp->dst_address_length,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  clib_memcpy (&pfx.fp_addr.ip4, mp->dst_address, sizeof (pfx.fp_addr.ip4));

  ip46_address_t nh;
  memset (&nh, 0, sizeof (nh));
  memcpy (&nh.ip4, mp->next_hop_address, sizeof (nh.ip4));

  n_labels = mp->next_hop_n_out_labels;
  if (n_labels == 0)
    ;
  else if (1 == n_labels)
    vec_add1 (label_stack, ntohl (mp->next_hop_out_label_stack[0]));
  else
    {
      vec_validate (label_stack, n_labels - 1);
      for (ii = 0; ii < n_labels; ii++)
	label_stack[ii] = ntohl (mp->next_hop_out_label_stack[ii]);
    }

  return (add_del_route_t_handler (mp->is_multipath,
				   mp->is_add,
				   mp->is_drop,
				   mp->is_unreach,
				   mp->is_prohibit,
				   mp->is_local, 0,
				   mp->is_classify,
				   mp->classify_table_index,
				   mp->is_resolve_host,
				   mp->is_resolve_attached, 0, 0,
				   fib_index, &pfx, DPO_PROTO_IP4,
				   &nh,
				   ntohl (mp->next_hop_sw_if_index),
				   next_hop_fib_index,
				   mp->next_hop_weight,
				   mp->next_hop_preference,
				   ntohl (mp->next_hop_via_label),
				   label_stack));
}

static int
ip6_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  u32 fib_index, next_hop_fib_index;
  mpls_label_t *label_stack = NULL;
  int rv, ii, n_labels;;

  rv = add_del_route_check (FIB_PROTOCOL_IP6,
			    mp->table_id,
			    mp->next_hop_sw_if_index,
			    DPO_PROTO_IP6,
			    mp->next_hop_table_id,
			    0, &fib_index, &next_hop_fib_index);

  if (0 != rv)
    return (rv);

  fib_prefix_t pfx = {
    .fp_len = mp->dst_address_length,
    .fp_proto = FIB_PROTOCOL_IP6,
  };
  clib_memcpy (&pfx.fp_addr.ip6, mp->dst_address, sizeof (pfx.fp_addr.ip6));

  ip46_address_t nh;
  memset (&nh, 0, sizeof (nh));
  memcpy (&nh.ip6, mp->next_hop_address, sizeof (nh.ip6));

  n_labels = mp->next_hop_n_out_labels;
  if (n_labels == 0)
    ;
  else if (1 == n_labels)
    vec_add1 (label_stack, ntohl (mp->next_hop_out_label_stack[0]));
  else
    {
      vec_validate (label_stack, n_labels - 1);
      for (ii = 0; ii < n_labels; ii++)
	label_stack[ii] = ntohl (mp->next_hop_out_label_stack[ii]);
    }

  return (add_del_route_t_handler (mp->is_multipath,
				   mp->is_add,
				   mp->is_drop,
				   mp->is_unreach,
				   mp->is_prohibit,
				   mp->is_local, 0,
				   mp->is_classify,
				   mp->classify_table_index,
				   mp->is_resolve_host,
				   mp->is_resolve_attached, 0, 0,
				   fib_index, &pfx, DPO_PROTO_IP6,
				   &nh, ntohl (mp->next_hop_sw_if_index),
				   next_hop_fib_index,
				   mp->next_hop_weight,
				   mp->next_hop_preference,
				   ntohl (mp->next_hop_via_label),
				   label_stack));
}

void
vl_api_ip_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  vl_api_ip_add_del_route_reply_t *rmp;
  int rv;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  if (mp->is_ipv6)
    rv = ip6_add_del_route_t_handler (mp);
  else
    rv = ip4_add_del_route_t_handler (mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_IP_ADD_DEL_ROUTE_REPLY);
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

static int
add_del_mroute_check (fib_protocol_t table_proto,
		      u32 table_id,
		      u32 next_hop_sw_if_index, u8 is_local, u32 * fib_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  *fib_index = mfib_table_find (table_proto, ntohl (table_id));
  if (~0 == *fib_index)
    {
      /* No such table */
      return VNET_API_ERROR_NO_SUCH_FIB;
    }

  if (~0 != ntohl (next_hop_sw_if_index))
    {
      if (pool_is_free_index (vnm->interface_main.sw_interfaces,
			      ntohl (next_hop_sw_if_index)))
	{
	  return VNET_API_ERROR_NO_MATCHING_INTERFACE;
	}
    }

  return (0);
}

static int
mroute_add_del_handler (u8 is_add,
			u8 is_local,
			u32 fib_index,
			const mfib_prefix_t * prefix,
			u32 entry_flags,
			fib_rpf_id_t rpf_id,
			u32 next_hop_sw_if_index, u32 itf_flags)
{
  stats_dslock_with_hint (1 /* release hint */ , 2 /* tag */ );

  fib_route_path_t path = {
    .frp_sw_if_index = next_hop_sw_if_index,
    .frp_proto = fib_proto_to_dpo (prefix->fp_proto),
  };

  if (is_local)
    path.frp_flags |= FIB_ROUTE_PATH_LOCAL;


  if (!is_local && ~0 == next_hop_sw_if_index)
    {
      mfib_table_entry_update (fib_index, prefix,
			       MFIB_SOURCE_API, rpf_id, entry_flags);
    }
  else
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (fib_index, prefix,
					MFIB_SOURCE_API, &path, itf_flags);
	}
      else
	{
	  mfib_table_entry_path_remove (fib_index, prefix,
					MFIB_SOURCE_API, &path);
	}
    }

  stats_dsunlock ();
  return (0);
}

static int
api_mroute_add_del_t_handler (vl_api_ip_mroute_add_del_t * mp)
{
  fib_protocol_t fproto;
  u32 fib_index;
  int rv;

  fproto = (mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  rv = add_del_mroute_check (fproto,
			     mp->table_id,
			     mp->next_hop_sw_if_index,
			     mp->is_local, &fib_index);

  if (0 != rv)
    return (rv);

  mfib_prefix_t pfx = {
    .fp_len = ntohs (mp->grp_address_length),
    .fp_proto = fproto,
  };

  if (FIB_PROTOCOL_IP4 == fproto)
    {
      clib_memcpy (&pfx.fp_grp_addr.ip4, mp->grp_address,
		   sizeof (pfx.fp_grp_addr.ip4));
      clib_memcpy (&pfx.fp_src_addr.ip4, mp->src_address,
		   sizeof (pfx.fp_src_addr.ip4));
    }
  else
    {
      clib_memcpy (&pfx.fp_grp_addr.ip6, mp->grp_address,
		   sizeof (pfx.fp_grp_addr.ip6));
      clib_memcpy (&pfx.fp_src_addr.ip6, mp->src_address,
		   sizeof (pfx.fp_src_addr.ip6));
    }

  return (mroute_add_del_handler (mp->is_add,
				  mp->is_local,
				  fib_index, &pfx,
				  ntohl (mp->entry_flags),
				  ntohl (mp->rpf_id),
				  ntohl (mp->next_hop_sw_if_index),
				  ntohl (mp->itf_flags)));
}

void
vl_api_ip_mroute_add_del_t_handler (vl_api_ip_mroute_add_del_t * mp)
{
  vl_api_ip_mroute_add_del_reply_t *rmp;
  int rv;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  rv = api_mroute_add_del_t_handler (mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_IP_MROUTE_ADD_DEL_REPLY);
}

static void
send_ip_details (vpe_api_main_t * am,
		 unix_shared_memory_queue_t * q, u32 sw_if_index,
		 u8 is_ipv6, u32 context)
{
  vl_api_ip_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_DETAILS);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = is_ipv6;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_ip_address_details (vpe_api_main_t * am,
			 unix_shared_memory_queue_t * q,
			 u8 * ip, u16 prefix_length,
			 u32 sw_if_index, u8 is_ipv6, u32 context)
{
  vl_api_ip_address_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ADDRESS_DETAILS);

  if (is_ipv6)
    {
      clib_memcpy (&mp->ip, ip, sizeof (mp->ip));
    }
  else
    {
      u32 *tp = (u32 *) mp->ip;
      *tp = *(u32 *) ip;
    }
  mp->prefix_length = prefix_length;
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->is_ipv6 = is_ipv6;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_ip_address_dump_t_handler (vl_api_ip_address_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  ip6_address_t *r6;
  ip4_address_t *r4;
  ip6_main_t *im6 = &ip6_main;
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_interface_address_t *ia = 0;
  u32 sw_if_index = ~0;
  int rv __attribute__ ((unused)) = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  if (mp->is_ipv6)
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index,
                                    1 /* honor unnumbered */,
      ({
        r6 = ip_interface_address_get_address (lm6, ia);
        u16 prefix_length = ia->address_length;
        send_ip_address_details(am, q, (u8*)r6, prefix_length,
				sw_if_index, 1, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index,
                                    1 /* honor unnumbered */,
      ({
        r4 = ip_interface_address_get_address (lm4, ia);
        u16 prefix_length = ia->address_length;
        send_ip_address_details(am, q, (u8*)r4, prefix_length,
				sw_if_index, 0, mp->context);
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
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  unix_shared_memory_queue_t *q;
  vnet_sw_interface_t *si, *sorted_sis;
  u32 sw_if_index = ~0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

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
	if (mp->is_ipv6 && !ip6_interface_enabled (vm, si->sw_if_index))
	  {
	    continue;
	  }
	sw_if_index = si->sw_if_index;
	send_ip_details (am, q, sw_if_index, mp->is_ipv6, mp->context);
      }
  }
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

static void
  vl_api_sw_interface_ip6nd_ra_config_t_handler
  (vl_api_sw_interface_ip6nd_ra_config_t * mp)
{
  vl_api_sw_interface_ip6nd_ra_config_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  u8 is_no, suppress, managed, other, ll_option, send_unicast, cease,
    default_router;

  is_no = mp->is_no == 1;
  suppress = mp->suppress == 1;
  managed = mp->managed == 1;
  other = mp->other == 1;
  ll_option = mp->ll_option == 1;
  send_unicast = mp->send_unicast == 1;
  cease = mp->cease == 1;
  default_router = mp->default_router == 1;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ip6_neighbor_ra_config (vm, ntohl (mp->sw_if_index),
			       suppress, managed, other,
			       ll_option, send_unicast, cease,
			       default_router, ntohl (mp->lifetime),
			       ntohl (mp->initial_count),
			       ntohl (mp->initial_interval),
			       ntohl (mp->max_interval),
			       ntohl (mp->min_interval), is_no);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY);
}

static void
  vl_api_sw_interface_ip6nd_ra_prefix_t_handler
  (vl_api_sw_interface_ip6nd_ra_prefix_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t *rmp;
  int rv = 0;
  u8 is_no, use_default, no_advertise, off_link, no_autoconfig, no_onlink;

  VALIDATE_SW_IF_INDEX (mp);

  is_no = mp->is_no == 1;
  use_default = mp->use_default == 1;
  no_advertise = mp->no_advertise == 1;
  off_link = mp->off_link == 1;
  no_autoconfig = mp->no_autoconfig == 1;
  no_onlink = mp->no_onlink == 1;

  rv = ip6_neighbor_ra_prefix (vm, ntohl (mp->sw_if_index),
			       (ip6_address_t *) mp->address,
			       mp->address_length, use_default,
			       ntohl (mp->val_lifetime),
			       ntohl (mp->pref_lifetime), no_advertise,
			       off_link, no_autoconfig, no_onlink, is_no);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY);
}

static void
send_ip6nd_proxy_details (unix_shared_memory_queue_t * q,
			  u32 context,
			  const ip46_address_t * addr, u32 sw_if_index)
{
  vl_api_ip6nd_proxy_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP6ND_PROXY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  memcpy (mp->address, addr, 16);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

typedef struct api_ip6nd_proxy_fib_table_walk_ctx_t_
{
  u32 *indices;
} api_ip6nd_proxy_fib_table_walk_ctx_t;

static int
api_ip6nd_proxy_fib_table_walk (fib_node_index_t fei, void *arg)
{
  api_ip6nd_proxy_fib_table_walk_ctx_t *ctx = arg;

  if (fib_entry_is_sourced (fei, FIB_SOURCE_IP6_ND_PROXY))
    {
      vec_add1 (ctx->indices, fei);
    }

  return (1);
}

static void
vl_api_ip6nd_proxy_dump_t_handler (vl_api_ip6nd_proxy_dump_t * mp)
{
  ip6_main_t *im6 = &ip6_main;
  fib_table_t *fib_table;
  api_ip6nd_proxy_fib_table_walk_ctx_t ctx = {
    .indices = NULL,
  };
  fib_node_index_t *feip;
  fib_prefix_t pfx;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (fib_table, im6->fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP6,
                   api_ip6nd_proxy_fib_table_walk,
                   &ctx);
  }));
  /* *INDENT-ON* */

  vec_sort_with_function (ctx.indices, fib_entry_cmp_for_sort);

  vec_foreach (feip, ctx.indices)
  {
    fib_entry_get_prefix (*feip, &pfx);

    send_ip6nd_proxy_details (q,
			      mp->context,
			      &pfx.fp_addr,
			      fib_entry_get_resolving_interface (*feip));
  }

  vec_free (ctx.indices);
}

static void
vl_api_ip6nd_proxy_add_del_t_handler (vl_api_ip6nd_proxy_add_del_t * mp)
{
  vl_api_ip6nd_proxy_add_del_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ip6_neighbor_proxy_add_del (ntohl (mp->sw_if_index),
				   (ip6_address_t *) mp->address, mp->is_del);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP6ND_PROXY_ADD_DEL_REPLY);
}

static void
  vl_api_sw_interface_ip6_enable_disable_t_handler
  (vl_api_sw_interface_ip6_enable_disable_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_ip6_enable_disable_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;

  vnm->api_errno = 0;

  VALIDATE_SW_IF_INDEX (mp);

  error =
    (mp->enable == 1) ? enable_ip6_interface (vm,
					      ntohl (mp->sw_if_index)) :
    disable_ip6_interface (vm, ntohl (mp->sw_if_index));

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = vnm->api_errno;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_sw_interface_ip6_set_link_local_address_t_handler
  (vl_api_sw_interface_ip6_set_link_local_address_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_ip6_set_link_local_address_reply_t *rmp;
  int rv = 0;
  clib_error_t *error;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  VALIDATE_SW_IF_INDEX (mp);

  error = set_ip6_link_local_address (vm,
				      ntohl (mp->sw_if_index),
				      (ip6_address_t *) mp->address);
  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = vnm->api_errno;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY);
}

void
vl_mfib_signal_send_one (unix_shared_memory_queue_t * q,
			 u32 context, const mfib_signal_t * mfs)
{
  vl_api_mfib_signal_details_t *mp;
  mfib_prefix_t prefix;
  mfib_table_t *mfib;
  mfib_itf_t *mfi;

  mp = vl_msg_api_alloc (sizeof (*mp));

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MFIB_SIGNAL_DETAILS);
  mp->context = context;

  mfi = mfib_itf_get (mfs->mfs_itf);
  mfib_entry_get_prefix (mfs->mfs_entry, &prefix);
  mfib = mfib_table_get (mfib_entry_get_fib_index (mfs->mfs_entry),
			 prefix.fp_proto);
  mp->table_id = ntohl (mfib->mft_table_id);
  mp->sw_if_index = ntohl (mfi->mfi_sw_if_index);

  if (FIB_PROTOCOL_IP4 == prefix.fp_proto)
    {
      mp->grp_address_len = ntohs (prefix.fp_len);

      memcpy (mp->grp_address, &prefix.fp_grp_addr.ip4, 4);
      if (prefix.fp_len > 32)
	{
	  memcpy (mp->src_address, &prefix.fp_src_addr.ip4, 4);
	}
    }
  else
    {
      mp->grp_address_len = ntohs (prefix.fp_len);

      ASSERT (0);
    }

  if (0 != mfs->mfs_buffer_len)
    {
      mp->ip_packet_len = ntohs (mfs->mfs_buffer_len);

      memcpy (mp->ip_packet_data, mfs->mfs_buffer, mfs->mfs_buffer_len);
    }
  else
    {
      mp->ip_packet_len = 0;
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mfib_signal_dump_t_handler (vl_api_mfib_signal_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  while (q->cursize < q->maxsize && mfib_signal_send_one (q, mp->context))
    ;
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
  api_main_t *am = &api_main;

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
