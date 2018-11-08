/*
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
 */

#include <vlibmemory/api.h>
#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-cp/packets.h>
#include <vnet/lisp-cp/lisp_msg_serdes.h>
#include <vnet/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/lisp-gpe/lisp_gpe_tunnel.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/packet.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_VALUE_U24 0xffffff

/* mapping timer control constants (in seconds) */
#define TIME_UNTIL_REFETCH_OR_DELETE  20
#define MAPPING_TIMEOUT (((m->ttl) * 60) - TIME_UNTIL_REFETCH_OR_DELETE)

lisp_cp_main_t lisp_control_main;

u8 *format_lisp_cp_input_trace (u8 * s, va_list * args);
static void *send_map_request_thread_fn (void *arg);

typedef enum
{
  LISP_CP_INPUT_NEXT_DROP,
  LISP_CP_INPUT_N_NEXT,
} lisp_cp_input_next_t;

typedef struct
{
  u8 is_resend;
  gid_address_t seid;
  gid_address_t deid;
  u8 smr_invoked;
} map_request_args_t;

u8
vnet_lisp_get_map_request_mode (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->map_request_mode;
}

static u16
auth_data_len_by_key_id (lisp_key_type_t key_id)
{
  switch (key_id)
    {
    case HMAC_SHA_1_96:
      return SHA1_AUTH_DATA_LEN;
    case HMAC_SHA_256_128:
      return SHA256_AUTH_DATA_LEN;
    default:
      clib_warning ("unsupported key type: %d!", key_id);
      return (u16) ~ 0;
    }
  return (u16) ~ 0;
}

static const EVP_MD *
get_encrypt_fcn (lisp_key_type_t key_id)
{
  switch (key_id)
    {
    case HMAC_SHA_1_96:
      return EVP_sha1 ();
    case HMAC_SHA_256_128:
      return EVP_sha256 ();
    default:
      clib_warning ("unsupported encryption key type: %d!", key_id);
      break;
    }
  return 0;
}

static int
queue_map_request (gid_address_t * seid, gid_address_t * deid,
		   u8 smr_invoked, u8 is_resend);

ip_interface_address_t *
ip_interface_get_first_interface_address (ip_lookup_main_t * lm,
					  u32 sw_if_index, u8 loop)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *swif = vnet_get_sw_interface (vnm, sw_if_index);
  if (loop && swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
    sw_if_index = swif->unnumbered_sw_if_index;
  u32 ia =
    (vec_len ((lm)->if_address_pool_index_by_sw_if_index) > (sw_if_index)) ?
    vec_elt ((lm)->if_address_pool_index_by_sw_if_index, (sw_if_index)) :
    (u32) ~ 0;
  return pool_elt_at_index ((lm)->if_address_pool, ia);
}

void *
ip_interface_get_first_address (ip_lookup_main_t * lm, u32 sw_if_index,
				u8 version)
{
  ip_interface_address_t *ia;

  ia = ip_interface_get_first_interface_address (lm, sw_if_index, 1);
  if (!ia)
    return 0;
  return ip_interface_address_get_address (lm, ia);
}

int
ip_interface_get_first_ip_address (lisp_cp_main_t * lcm, u32 sw_if_index,
				   u8 version, ip_address_t * result)
{
  ip_lookup_main_t *lm;
  void *addr;

  lm = (version == IP4) ? &lcm->im4->lookup_main : &lcm->im6->lookup_main;
  addr = ip_interface_get_first_address (lm, sw_if_index, version);
  if (!addr)
    return 0;

  ip_address_set (result, addr, version);
  return 1;
}

/**
 * convert from a LISP address to a FIB prefix
 */
void
ip_address_to_fib_prefix (const ip_address_t * addr, fib_prefix_t * prefix)
{
  if (addr->version == IP4)
    {
      prefix->fp_len = 32;
      prefix->fp_proto = FIB_PROTOCOL_IP4;
      memset (&prefix->fp_addr.pad, 0, sizeof (prefix->fp_addr.pad));
      memcpy (&prefix->fp_addr.ip4, &addr->ip, sizeof (prefix->fp_addr.ip4));
    }
  else
    {
      prefix->fp_len = 128;
      prefix->fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&prefix->fp_addr.ip6, &addr->ip, sizeof (prefix->fp_addr.ip6));
    }
}

/**
 * convert from a LISP to a FIB prefix
 */
void
ip_prefix_to_fib_prefix (const ip_prefix_t * ip_prefix,
			 fib_prefix_t * fib_prefix)
{
  ip_address_to_fib_prefix (&ip_prefix->addr, fib_prefix);
  fib_prefix->fp_len = ip_prefix->len;
}

/**
 * Find the sw_if_index of the interface that would be used to egress towards
 * dst.
 */
u32
ip_fib_get_egress_iface_for_dst (lisp_cp_main_t * lcm, ip_address_t * dst)
{
  fib_node_index_t fei;
  fib_prefix_t prefix;

  ip_address_to_fib_prefix (dst, &prefix);

  fei = fib_table_lookup (0, &prefix);

  return (fib_entry_get_resolving_interface (fei));
}

/**
 * Find first IP of the interface that would be used to egress towards dst.
 * Returns 1 if the address is found 0 otherwise.
 */
int
ip_fib_get_first_egress_ip_for_dst (lisp_cp_main_t * lcm, ip_address_t * dst,
				    ip_address_t * result)
{
  u32 si;
  ip_lookup_main_t *lm;
  void *addr = 0;
  u8 ipver;

  ASSERT (result != 0);

  ipver = ip_addr_version (dst);

  lm = (ipver == IP4) ? &lcm->im4->lookup_main : &lcm->im6->lookup_main;
  si = ip_fib_get_egress_iface_for_dst (lcm, dst);

  if ((u32) ~ 0 == si)
    return 0;

  /* find the first ip address */
  addr = ip_interface_get_first_address (lm, si, ipver);
  if (0 == addr)
    return 0;

  ip_address_set (result, addr, ipver);
  return 1;
}

static int
dp_add_del_iface (lisp_cp_main_t * lcm, u32 vni, u8 is_l2, u8 is_add,
		  u8 with_default_route)
{
  uword *dp_table;

  if (!is_l2)
    {
      dp_table = hash_get (lcm->table_id_by_vni, vni);

      if (!dp_table)
	{
	  clib_warning ("vni %d not associated to a vrf!", vni);
	  return VNET_API_ERROR_INVALID_VALUE;
	}
    }
  else
    {
      dp_table = hash_get (lcm->bd_id_by_vni, vni);
      if (!dp_table)
	{
	  clib_warning ("vni %d not associated to a bridge domain!", vni);
	  return VNET_API_ERROR_INVALID_VALUE;
	}
    }

  /* enable/disable data-plane interface */
  if (is_add)
    {
      if (is_l2)
	lisp_gpe_tenant_l2_iface_add_or_lock (vni, dp_table[0]);
      else
	lisp_gpe_tenant_l3_iface_add_or_lock (vni, dp_table[0],
					      with_default_route);
    }
  else
    {
      if (is_l2)
	lisp_gpe_tenant_l2_iface_unlock (vni);
      else
	lisp_gpe_tenant_l3_iface_unlock (vni);
    }

  return 0;
}

static void
dp_del_fwd_entry (lisp_cp_main_t * lcm, u32 dst_map_index)
{
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  fwd_entry_t *fe = 0;
  uword *feip = 0;
  memset (a, 0, sizeof (*a));

  feip = hash_get (lcm->fwd_entry_by_mapping_index, dst_map_index);
  if (!feip)
    return;

  fe = pool_elt_at_index (lcm->fwd_entry_pool, feip[0]);

  /* delete dp fwd entry */
  u32 sw_if_index;
  a->is_add = 0;
  a->locator_pairs = fe->locator_pairs;
  a->vni = gid_address_vni (&fe->reid);
  gid_address_copy (&a->rmt_eid, &fe->reid);
  if (fe->is_src_dst)
    gid_address_copy (&a->lcl_eid, &fe->leid);

  vnet_lisp_gpe_del_fwd_counters (a, feip[0]);
  vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);

  /* delete entry in fwd table */
  hash_unset (lcm->fwd_entry_by_mapping_index, dst_map_index);
  vec_free (fe->locator_pairs);
  pool_put (lcm->fwd_entry_pool, fe);
}

/**
 * Finds first remote locator with best (lowest) priority that has a local
 * peer locator with an underlying route to it.
 *
 */
static u32
get_locator_pairs (lisp_cp_main_t * lcm, mapping_t * lcl_map,
		   mapping_t * rmt_map, locator_pair_t ** locator_pairs)
{
  u32 i, limitp = 0, li, found = 0, esi;
  locator_set_t *rmt_ls, *lcl_ls;
  ip_address_t _lcl_addr, *lcl_addr = &_lcl_addr;
  locator_t *lp, *rmt = 0;
  uword *checked = 0;
  locator_pair_t pair;

  rmt_ls =
    pool_elt_at_index (lcm->locator_set_pool, rmt_map->locator_set_index);
  lcl_ls =
    pool_elt_at_index (lcm->locator_set_pool, lcl_map->locator_set_index);

  if (!rmt_ls || vec_len (rmt_ls->locator_indices) == 0)
    return 0;

  while (1)
    {
      rmt = 0;

      /* find unvisited remote locator with best priority */
      for (i = 0; i < vec_len (rmt_ls->locator_indices); i++)
	{
	  if (0 != hash_get (checked, i))
	    continue;

	  li = vec_elt (rmt_ls->locator_indices, i);
	  lp = pool_elt_at_index (lcm->locator_pool, li);

	  /* we don't support non-IP locators for now */
	  if (gid_address_type (&lp->address) != GID_ADDR_IP_PREFIX)
	    continue;

	  if ((found && lp->priority == limitp)
	      || (!found && lp->priority >= limitp))
	    {
	      rmt = lp;

	      /* don't search for locators with lower priority and don't
	       * check this locator again*/
	      limitp = lp->priority;
	      hash_set (checked, i, 1);
	      break;
	    }
	}
      /* check if a local locator with a route to remote locator exists */
      if (rmt != 0)
	{
	  /* find egress sw_if_index for rmt locator */
	  esi =
	    ip_fib_get_egress_iface_for_dst (lcm,
					     &gid_address_ip (&rmt->address));
	  if ((u32) ~ 0 == esi)
	    continue;

	  for (i = 0; i < vec_len (lcl_ls->locator_indices); i++)
	    {
	      li = vec_elt (lcl_ls->locator_indices, i);
	      locator_t *sl = pool_elt_at_index (lcm->locator_pool, li);

	      /* found local locator with the needed sw_if_index */
	      if (sl->sw_if_index == esi)
		{
		  /* and it has an address */
		  if (0 == ip_interface_get_first_ip_address (lcm,
							      sl->sw_if_index,
							      gid_address_ip_version
							      (&rmt->address),
							      lcl_addr))
		    continue;

		  memset (&pair, 0, sizeof (pair));
		  ip_address_copy (&pair.rmt_loc,
				   &gid_address_ip (&rmt->address));
		  ip_address_copy (&pair.lcl_loc, lcl_addr);
		  pair.weight = rmt->weight;
		  pair.priority = rmt->priority;
		  vec_add1 (locator_pairs[0], pair);
		  found = 1;
		}
	    }
	}
      else
	break;
    }

  hash_free (checked);
  return found;
}

static void
gid_address_sd_to_flat (gid_address_t * dst, gid_address_t * src,
			fid_address_t * fid)
{
  ASSERT (GID_ADDR_SRC_DST == gid_address_type (src));

  dst[0] = src[0];

  switch (fid_addr_type (fid))
    {
    case FID_ADDR_IP_PREF:
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ippref (dst) = fid_addr_ippref (fid);
      break;
    case FID_ADDR_MAC:
      gid_address_type (dst) = GID_ADDR_MAC;
      mac_copy (gid_address_mac (dst), fid_addr_mac (fid));
      break;
    default:
      clib_warning ("Unsupported fid type %d!", fid_addr_type (fid));
      break;
    }
}

u8
vnet_lisp_map_register_state_get (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->map_registering;
}

u8
vnet_lisp_rloc_probe_state_get (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->rloc_probing;
}

static void
dp_add_fwd_entry (lisp_cp_main_t * lcm, u32 src_map_index, u32 dst_map_index)
{
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  gid_address_t *rmt_eid, *lcl_eid;
  mapping_t *lcl_map, *rmt_map;
  u32 sw_if_index, **rmts, rmts_idx;
  uword *feip = 0, *dpid, *rmts_stored_idxp = 0;
  fwd_entry_t *fe;
  u8 type, is_src_dst = 0;
  int rv;

  memset (a, 0, sizeof (*a));

  /* remove entry if it already exists */
  feip = hash_get (lcm->fwd_entry_by_mapping_index, dst_map_index);
  if (feip)
    dp_del_fwd_entry (lcm, dst_map_index);

  /*
   * Determine local mapping and eid
   */
  if (lcm->flags & LISP_FLAG_PITR_MODE)
    {
      if (lcm->pitr_map_index != ~0)
	lcl_map = pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
      else
	{
	  clib_warning ("no PITR mapping configured!");
	  return;
	}
    }
  else
    lcl_map = pool_elt_at_index (lcm->mapping_pool, src_map_index);
  lcl_eid = &lcl_map->eid;

  /*
   * Determine remote mapping and eid
   */
  rmt_map = pool_elt_at_index (lcm->mapping_pool, dst_map_index);
  rmt_eid = &rmt_map->eid;

  /*
   * Build and insert data plane forwarding entry
   */
  a->is_add = 1;

  if (MR_MODE_SRC_DST == lcm->map_request_mode)
    {
      if (GID_ADDR_SRC_DST == gid_address_type (rmt_eid))
	{
	  gid_address_sd_to_flat (&a->rmt_eid, rmt_eid,
				  &gid_address_sd_dst (rmt_eid));
	  gid_address_sd_to_flat (&a->lcl_eid, rmt_eid,
				  &gid_address_sd_src (rmt_eid));
	}
      else
	{
	  gid_address_copy (&a->rmt_eid, rmt_eid);
	  gid_address_copy (&a->lcl_eid, lcl_eid);
	}
      is_src_dst = 1;
    }
  else
    gid_address_copy (&a->rmt_eid, rmt_eid);

  a->vni = gid_address_vni (&a->rmt_eid);
  a->is_src_dst = is_src_dst;

  /* get vrf or bd_index associated to vni */
  type = gid_address_type (&a->rmt_eid);
  if (GID_ADDR_IP_PREFIX == type)
    {
      dpid = hash_get (lcm->table_id_by_vni, a->vni);
      if (!dpid)
	{
	  clib_warning ("vni %d not associated to a vrf!", a->vni);
	  return;
	}
      a->table_id = dpid[0];
    }
  else if (GID_ADDR_MAC == type)
    {
      dpid = hash_get (lcm->bd_id_by_vni, a->vni);
      if (!dpid)
	{
	  clib_warning ("vni %d not associated to a bridge domain !", a->vni);
	  return;
	}
      a->bd_id = dpid[0];
    }

  /* find best locator pair that 1) verifies LISP policy 2) are connected */
  rv = get_locator_pairs (lcm, lcl_map, rmt_map, &a->locator_pairs);

  /* Either rmt mapping is negative or we can't find underlay path.
   * Try again with petr if configured */
  if (rv == 0 && (lcm->flags & LISP_FLAG_USE_PETR))
    {
      rmt_map = lisp_get_petr_mapping (lcm);
      rv = get_locator_pairs (lcm, lcl_map, rmt_map, &a->locator_pairs);
    }

  /* negative entry */
  if (rv == 0)
    {
      a->is_negative = 1;
      a->action = rmt_map->action;
    }

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);
  if (rv)
    {
      if (a->locator_pairs)
	vec_free (a->locator_pairs);
      return;
    }

  /* add tunnel to fwd entry table */
  pool_get (lcm->fwd_entry_pool, fe);
  vnet_lisp_gpe_add_fwd_counters (a, fe - lcm->fwd_entry_pool);

  fe->locator_pairs = a->locator_pairs;
  gid_address_copy (&fe->reid, &a->rmt_eid);

  if (is_src_dst)
    gid_address_copy (&fe->leid, &a->lcl_eid);
  else
    gid_address_copy (&fe->leid, lcl_eid);

  fe->is_src_dst = is_src_dst;
  hash_set (lcm->fwd_entry_by_mapping_index, dst_map_index,
	    fe - lcm->fwd_entry_pool);

  /* Add rmt mapping to the vector of adjacent mappings to lcl mapping */
  rmts_stored_idxp =
    hash_get (lcm->lcl_to_rmt_adjs_by_lcl_idx, src_map_index);
  if (!rmts_stored_idxp)
    {
      pool_get (lcm->lcl_to_rmt_adjacencies, rmts);
      memset (rmts, 0, sizeof (*rmts));
      rmts_idx = rmts - lcm->lcl_to_rmt_adjacencies;
      hash_set (lcm->lcl_to_rmt_adjs_by_lcl_idx, src_map_index, rmts_idx);
    }
  else
    {
      rmts_idx = (u32) (*rmts_stored_idxp);
      rmts = pool_elt_at_index (lcm->lcl_to_rmt_adjacencies, rmts_idx);
    }
  vec_add1 (rmts[0], dst_map_index);
}

typedef struct
{
  u32 si;
  u32 di;
} fwd_entry_mt_arg_t;

static void *
dp_add_fwd_entry_thread_fn (void *arg)
{
  fwd_entry_mt_arg_t *a = arg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  dp_add_fwd_entry (lcm, a->si, a->di);
  return 0;
}

static int
dp_add_fwd_entry_from_mt (u32 si, u32 di)
{
  fwd_entry_mt_arg_t a;

  memset (&a, 0, sizeof (a));
  a.si = si;
  a.di = di;

  vl_api_rpc_call_main_thread (dp_add_fwd_entry_thread_fn,
			       (u8 *) & a, sizeof (a));
  return 0;
}

/**
 * Returns vector of adjacencies.
 *
 * The caller must free the vector returned by this function.
 *
 * @param vni virtual network identifier
 * @return vector of adjacencies
 */
lisp_adjacency_t *
vnet_lisp_adjacencies_get_by_vni (u32 vni)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  fwd_entry_t *fwd;
  lisp_adjacency_t *adjs = 0, adj;

  /* *INDENT-OFF* */
  pool_foreach(fwd, lcm->fwd_entry_pool,
  ({
    if (gid_address_vni (&fwd->reid) != vni)
      continue;

    gid_address_copy (&adj.reid, &fwd->reid);
    gid_address_copy (&adj.leid, &fwd->leid);
    vec_add1 (adjs, adj);
  }));
  /* *INDENT-ON* */

  return adjs;
}

static lisp_msmr_t *
get_map_server (ip_address_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *m;

  vec_foreach (m, lcm->map_servers)
  {
    if (!ip_address_cmp (&m->address, a))
      {
	return m;
      }
  }
  return 0;
}

static lisp_msmr_t *
get_map_resolver (ip_address_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *m;

  vec_foreach (m, lcm->map_resolvers)
  {
    if (!ip_address_cmp (&m->address, a))
      {
	return m;
      }
  }
  return 0;
}

int
vnet_lisp_add_del_map_server (ip_address_t * addr, u8 is_add)
{
  u32 i;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t _ms, *ms = &_ms;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (is_add)
    {
      if (get_map_server (addr))
	{
	  clib_warning ("map-server %U already exists!", format_ip_address,
			addr);
	  return -1;
	}

      memset (ms, 0, sizeof (*ms));
      ip_address_copy (&ms->address, addr);
      vec_add1 (lcm->map_servers, ms[0]);

      if (vec_len (lcm->map_servers) == 1)
	lcm->do_map_server_election = 1;
    }
  else
    {
      for (i = 0; i < vec_len (lcm->map_servers); i++)
	{
	  ms = vec_elt_at_index (lcm->map_servers, i);
	  if (!ip_address_cmp (&ms->address, addr))
	    {
	      if (!ip_address_cmp (&ms->address, &lcm->active_map_server))
		lcm->do_map_server_election = 1;

	      vec_del1 (lcm->map_servers, i);
	      break;
	    }
	}
    }

  return 0;
}

/**
 * Add/remove mapping to/from map-cache. Overwriting not allowed.
 */
int
vnet_lisp_map_cache_add_del (vnet_lisp_add_del_mapping_args_t * a,
			     u32 * map_index_result)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 mi, *map_indexp, map_index, i;
  u32 **rmts = 0, *remote_idxp, rmts_itr, remote_idx;
  uword *rmts_idxp;
  mapping_t *m, *old_map;
  u32 **eid_indexes;

  if (gid_address_type (&a->eid) == GID_ADDR_NSH)
    {
      if (gid_address_vni (&a->eid) != 0)
	{
	  clib_warning ("Supported only default VNI for NSH!");
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}
      if (gid_address_nsh_spi (&a->eid) > MAX_VALUE_U24)
	{
	  clib_warning ("SPI is greater than 24bit!");
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}
    }

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &a->eid);
  old_map = mi != ~0 ? pool_elt_at_index (lcm->mapping_pool, mi) : 0;
  if (a->is_add)
    {
      /* TODO check if overwriting and take appropriate actions */
      if (mi != GID_LOOKUP_MISS && !gid_address_cmp (&old_map->eid, &a->eid))
	{
	  clib_warning ("eid %U found in the eid-table", format_gid_address,
			&a->eid);
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      pool_get (lcm->mapping_pool, m);
      gid_address_copy (&m->eid, &a->eid);
      m->locator_set_index = a->locator_set_index;
      m->ttl = a->ttl;
      m->action = a->action;
      m->local = a->local;
      m->is_static = a->is_static;
      m->key = vec_dup (a->key);
      m->key_id = a->key_id;

      map_index = m - lcm->mapping_pool;
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, &a->eid, map_index,
			      1);

      if (pool_is_free_index (lcm->locator_set_pool, a->locator_set_index))
	{
	  clib_warning ("Locator set with index %d doesn't exist",
			a->locator_set_index);
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      /* add eid to list of eids supported by locator-set */
      vec_validate (lcm->locator_set_to_eids, a->locator_set_index);
      eid_indexes = vec_elt_at_index (lcm->locator_set_to_eids,
				      a->locator_set_index);
      vec_add1 (eid_indexes[0], map_index);

      if (a->local)
	{
	  /* mark as local */
	  vec_add1 (lcm->local_mappings_indexes, map_index);
	}
      map_index_result[0] = map_index;
    }
  else
    {
      if (mi == GID_LOOKUP_MISS)
	{
	  clib_warning ("eid %U not found in the eid-table",
			format_gid_address, &a->eid);
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      /* clear locator-set to eids binding */
      eid_indexes = vec_elt_at_index (lcm->locator_set_to_eids,
				      a->locator_set_index);
      for (i = 0; i < vec_len (eid_indexes[0]); i++)
	{
	  map_indexp = vec_elt_at_index (eid_indexes[0], i);
	  if (map_indexp[0] == mi)
	    break;
	}
      vec_del1 (eid_indexes[0], i);

      /* remove local mark if needed */
      m = pool_elt_at_index (lcm->mapping_pool, mi);
      if (m->local)
	{
	  /* Remove adjacencies associated with the local mapping */
	  rmts_idxp = hash_get (lcm->lcl_to_rmt_adjs_by_lcl_idx, mi);
	  if (rmts_idxp)
	    {
	      rmts =
		pool_elt_at_index (lcm->lcl_to_rmt_adjacencies, rmts_idxp[0]);
	      vec_foreach (remote_idxp, rmts[0])
	      {
		dp_del_fwd_entry (lcm, remote_idxp[0]);
	      }
	      vec_free (rmts[0]);
	      pool_put (lcm->lcl_to_rmt_adjacencies, rmts);
	      hash_unset (lcm->lcl_to_rmt_adjs_by_lcl_idx, mi);
	    }

	  u32 k, *lm_indexp;
	  for (k = 0; k < vec_len (lcm->local_mappings_indexes); k++)
	    {
	      lm_indexp = vec_elt_at_index (lcm->local_mappings_indexes, k);
	      if (lm_indexp[0] == mi)
		break;
	    }
	  vec_del1 (lcm->local_mappings_indexes, k);
	}
      else
	{
	  /* Remove remote (if present) from the vectors of lcl-to-rmts
	   * TODO: Address this in a more efficient way.
	   */
	  /* *INDENT-OFF* */
	  pool_foreach (rmts, lcm->lcl_to_rmt_adjacencies,
	  ({
	    vec_foreach_index (rmts_itr, rmts[0])
	    {
	      remote_idx = vec_elt (rmts[0], rmts_itr);
	      if (mi == remote_idx)
		{
		  vec_del1 (rmts[0], rmts_itr);
		  break;
		}
	    }
	  }));
	  /* *INDENT-ON* */
	}

      /* remove mapping from dictionary */
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, &a->eid, 0, 0);
      gid_address_free (&m->eid);
      pool_put_index (lcm->mapping_pool, mi);
    }

  return 0;
}

/**
 *  Add/update/delete mapping to/in/from map-cache.
 */
int
vnet_lisp_add_del_local_mapping (vnet_lisp_add_del_mapping_args_t * a,
				 u32 * map_index_result)
{
  uword *dp_table = 0;
  u32 vni;
  u8 type;

  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  vni = gid_address_vni (&a->eid);
  type = gid_address_type (&a->eid);
  if (GID_ADDR_IP_PREFIX == type)
    dp_table = hash_get (lcm->table_id_by_vni, vni);
  else if (GID_ADDR_MAC == type)
    dp_table = hash_get (lcm->bd_id_by_vni, vni);

  if (!dp_table && GID_ADDR_NSH != type)
    {
      clib_warning ("vni %d not associated to a %s!", vni,
		    GID_ADDR_IP_PREFIX == type ? "vrf" : "bd");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* store/remove mapping from map-cache */
  return vnet_lisp_map_cache_add_del (a, map_index_result);
}

static void
add_l2_arp_bd (BVT (clib_bihash_kv) * kvp, void *arg)
{
  u32 **ht = arg;
  u32 version = (u32) kvp->key[0];
  if (IP6 == version)
    return;

  u32 bd = (u32) (kvp->key[0] >> 32);
  hash_set (ht[0], bd, 0);
}

u32 *
vnet_lisp_l2_arp_bds_get (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 *bds = 0;

  gid_dict_foreach_l2_arp_ndp_entry (&lcm->mapping_index_by_gid,
				     add_l2_arp_bd, &bds);
  return bds;
}

static void
add_ndp_bd (BVT (clib_bihash_kv) * kvp, void *arg)
{
  u32 **ht = arg;
  u32 version = (u32) kvp->key[0];
  if (IP4 == version)
    return;

  u32 bd = (u32) (kvp->key[0] >> 32);
  hash_set (ht[0], bd, 0);
}

u32 *
vnet_lisp_ndp_bds_get (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 *bds = 0;

  gid_dict_foreach_l2_arp_ndp_entry (&lcm->mapping_index_by_gid,
				     add_ndp_bd, &bds);
  return bds;
}

typedef struct
{
  void *vector;
  u32 bd;
} lisp_add_l2_arp_ndp_args_t;

static void
add_l2_arp_entry (BVT (clib_bihash_kv) * kvp, void *arg)
{
  lisp_add_l2_arp_ndp_args_t *a = arg;
  lisp_api_l2_arp_entry_t **vector = a->vector, e;

  u32 version = (u32) kvp->key[0];
  if (IP6 == version)
    return;

  u32 bd = (u32) (kvp->key[0] >> 32);

  if (bd == a->bd)
    {
      mac_copy (e.mac, (void *) &kvp->value);
      e.ip4 = (u32) kvp->key[1];
      vec_add1 (vector[0], e);
    }
}

lisp_api_l2_arp_entry_t *
vnet_lisp_l2_arp_entries_get_by_bd (u32 bd)
{
  lisp_api_l2_arp_entry_t *entries = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_add_l2_arp_ndp_args_t a;

  a.vector = &entries;
  a.bd = bd;

  gid_dict_foreach_l2_arp_ndp_entry (&lcm->mapping_index_by_gid,
				     add_l2_arp_entry, &a);
  return entries;
}

static void
add_ndp_entry (BVT (clib_bihash_kv) * kvp, void *arg)
{
  lisp_add_l2_arp_ndp_args_t *a = arg;
  lisp_api_ndp_entry_t **vector = a->vector, e;

  u32 version = (u32) kvp->key[0];
  if (IP4 == version)
    return;

  u32 bd = (u32) (kvp->key[0] >> 32);

  if (bd == a->bd)
    {
      mac_copy (e.mac, (void *) &kvp->value);
      clib_memcpy (e.ip6, &kvp->key[1], 16);
      vec_add1 (vector[0], e);
    }
}

lisp_api_ndp_entry_t *
vnet_lisp_ndp_entries_get_by_bd (u32 bd)
{
  lisp_api_ndp_entry_t *entries = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_add_l2_arp_ndp_args_t a;

  a.vector = &entries;
  a.bd = bd;

  gid_dict_foreach_l2_arp_ndp_entry (&lcm->mapping_index_by_gid,
				     add_ndp_entry, &a);
  return entries;
}

int
vnet_lisp_add_del_l2_arp_ndp_entry (gid_address_t * key, u8 * mac, u8 is_add)
{
  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  int rc = 0;

  u64 res = gid_dictionary_lookup (&lcm->mapping_index_by_gid, key);
  if (is_add)
    {
      if (res != GID_LOOKUP_MISS_L2)
	{
	  clib_warning ("Entry %U exists in DB!", format_gid_address, key);
	  return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}
      u64 val = mac_to_u64 (mac);
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, key, val,
			      1 /* is_add */ );
    }
  else
    {
      if (res == GID_LOOKUP_MISS_L2)
	{
	  clib_warning ("ONE entry %U not found - cannot delete!",
			format_gid_address, key);
	  return -1;
	}
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, key, 0,
			      0 /* is_add */ );
    }

  return rc;
}

int
vnet_lisp_eid_table_map (u32 vni, u32 dp_id, u8 is_l2, u8 is_add)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  uword *dp_idp, *vnip, **dp_table_by_vni, **vni_by_dp_table;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  dp_table_by_vni = is_l2 ? &lcm->bd_id_by_vni : &lcm->table_id_by_vni;
  vni_by_dp_table = is_l2 ? &lcm->vni_by_bd_id : &lcm->vni_by_table_id;

  if (!is_l2 && (vni == 0 || dp_id == 0))
    {
      clib_warning ("can't add/del default vni-vrf mapping!");
      return -1;
    }

  dp_idp = hash_get (dp_table_by_vni[0], vni);
  vnip = hash_get (vni_by_dp_table[0], dp_id);

  if (is_add)
    {
      if (dp_idp || vnip)
	{
	  clib_warning ("vni %d or vrf %d already used in vrf/vni "
			"mapping!", vni, dp_id);
	  return -1;
	}
      hash_set (dp_table_by_vni[0], vni, dp_id);
      hash_set (vni_by_dp_table[0], dp_id, vni);

      /* create dp iface */
      dp_add_del_iface (lcm, vni, is_l2, 1 /* is_add */ ,
			1 /* with_default_route */ );
    }
  else
    {
      if (!dp_idp || !vnip)
	{
	  clib_warning ("vni %d or vrf %d not used in any vrf/vni! "
			"mapping!", vni, dp_id);
	  return -1;
	}
      /* remove dp iface */
      dp_add_del_iface (lcm, vni, is_l2, 0 /* is_add */ , 0 /* unused */ );

      hash_unset (dp_table_by_vni[0], vni);
      hash_unset (vni_by_dp_table[0], dp_id);
    }
  return 0;

}

/* return 0 if the two locator sets are identical 1 otherwise */
static u8
compare_locators (lisp_cp_main_t * lcm, u32 * old_ls_indexes,
		  locator_t * new_locators)
{
  u32 i, old_li;
  locator_t *old_loc, *new_loc;

  if (vec_len (old_ls_indexes) != vec_len (new_locators))
    return 1;

  for (i = 0; i < vec_len (new_locators); i++)
    {
      old_li = vec_elt (old_ls_indexes, i);
      old_loc = pool_elt_at_index (lcm->locator_pool, old_li);

      new_loc = vec_elt_at_index (new_locators, i);

      if (locator_cmp (old_loc, new_loc))
	return 1;
    }
  return 0;
}

typedef struct
{
  u8 is_negative;
  void *lcm;
  gid_address_t *eids_to_be_deleted;
} remove_mapping_args_t;

/**
 * Callback invoked when a sub-prefix is found
 */
static void
remove_mapping_if_needed (u32 mi, void *arg)
{
  u8 delete = 0;
  remove_mapping_args_t *a = arg;
  lisp_cp_main_t *lcm = a->lcm;
  mapping_t *m;
  locator_set_t *ls;

  m = pool_elt_at_index (lcm->mapping_pool, mi);
  if (!m)
    return;

  ls = pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);

  if (a->is_negative)
    {
      if (0 != vec_len (ls->locator_indices))
	delete = 1;
    }
  else
    {
      if (0 == vec_len (ls->locator_indices))
	delete = 1;
    }

  if (delete)
    vec_add1 (a->eids_to_be_deleted, m->eid);
}

/**
 * This function searches map cache and looks for IP prefixes that are subset
 * of the provided one. If such prefix is found depending on 'is_negative'
 * it does follows:
 *
 * 1) if is_negative is true and found prefix points to positive mapping,
 *    then the mapping is removed
 * 2) if is_negative is false and found prefix points to negative mapping,
 *    then the mapping is removed
 */
static void
remove_overlapping_sub_prefixes (lisp_cp_main_t * lcm, gid_address_t * eid,
				 u8 is_negative)
{
  gid_address_t *e;
  remove_mapping_args_t a;

  memset (&a, 0, sizeof (a));

  /* do this only in src/dst mode ... */
  if (MR_MODE_SRC_DST != lcm->map_request_mode)
    return;

  /* ... and  only for IP prefix */
  if (GID_ADDR_SRC_DST != gid_address_type (eid)
      || (FID_ADDR_IP_PREF != gid_address_sd_dst_type (eid)))
    return;

  a.is_negative = is_negative;
  a.lcm = lcm;

  gid_dict_foreach_subprefix (&lcm->mapping_index_by_gid, eid,
			      remove_mapping_if_needed, &a);

  vec_foreach (e, a.eids_to_be_deleted)
  {
    vnet_lisp_add_del_adjacency_args_t _adj_args, *adj_args = &_adj_args;

    memset (adj_args, 0, sizeof (adj_args[0]));
    gid_address_copy (&adj_args->reid, e);
    adj_args->is_add = 0;
    if (vnet_lisp_add_del_adjacency (adj_args))
      clib_warning ("failed to del adjacency!");

    vnet_lisp_del_mapping (e, NULL);
  }

  vec_free (a.eids_to_be_deleted);
}

static void
mapping_delete_timer (lisp_cp_main_t * lcm, u32 mi)
{
  timing_wheel_delete (&lcm->wheel, mi);
}

static int
is_local_ip (lisp_cp_main_t * lcm, ip_address_t * addr)
{
  fib_node_index_t fei;
  fib_prefix_t prefix;
  fib_entry_flag_t flags;

  ip_address_to_fib_prefix (addr, &prefix);

  fei = fib_table_lookup (0, &prefix);
  flags = fib_entry_get_flags (fei);
  return (FIB_ENTRY_FLAG_LOCAL & flags);
}

/**
 * Adds/updates mapping. Does not program forwarding.
 *
 * @param a parameters of the new mapping
 * @param rlocs vector of remote locators
 * @param res_map_index index of the newly created mapping
 * @param locators_changed indicator if locators were updated in the mapping
 * @return return code
 */
int
vnet_lisp_add_mapping (vnet_lisp_add_del_mapping_args_t * a,
		       locator_t * rlocs,
		       u32 * res_map_index, u8 * is_updated)
{
  vnet_lisp_add_del_locator_set_args_t _ls_args, *ls_args = &_ls_args;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 mi, ls_index = 0, dst_map_index;
  mapping_t *old_map;
  locator_t *loc;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (res_map_index)
    res_map_index[0] = ~0;
  if (is_updated)
    is_updated[0] = 0;

  memset (ls_args, 0, sizeof (ls_args[0]));

  ls_args->locators = rlocs;
  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &a->eid);
  old_map = ((u32) ~ 0 != mi) ? pool_elt_at_index (lcm->mapping_pool, mi) : 0;

  /* check if none of the locators match locally configured address */
  vec_foreach (loc, rlocs)
  {
    ip_prefix_t *p = &gid_address_ippref (&loc->address);
    if (is_local_ip (lcm, &ip_prefix_addr (p)))
      {
	clib_warning ("RLOC %U matches a local address!",
		      format_gid_address, &loc->address);
	return VNET_API_ERROR_LISP_RLOC_LOCAL;
      }
  }

  /* overwrite: if mapping already exists, decide if locators should be
   * updated and be done */
  if (old_map && gid_address_cmp (&old_map->eid, &a->eid) == 0)
    {
      if (!a->is_static && (old_map->is_static || old_map->local))
	{
	  /* do not overwrite local or static remote mappings */
	  clib_warning ("mapping %U rejected due to collision with local "
			"or static remote mapping!", format_gid_address,
			&a->eid);
	  return 0;
	}

      locator_set_t *old_ls;

      /* update mapping attributes */
      old_map->action = a->action;
      if (old_map->action != a->action && NULL != is_updated)
	is_updated[0] = 1;

      old_map->authoritative = a->authoritative;
      old_map->ttl = a->ttl;

      old_ls = pool_elt_at_index (lcm->locator_set_pool,
				  old_map->locator_set_index);
      if (compare_locators (lcm, old_ls->locator_indices, ls_args->locators))
	{
	  /* set locator-set index to overwrite */
	  ls_args->is_add = 1;
	  ls_args->index = old_map->locator_set_index;
	  vnet_lisp_add_del_locator_set (ls_args, 0);
	  if (is_updated)
	    is_updated[0] = 1;
	}
      if (res_map_index)
	res_map_index[0] = mi;
    }
  /* new mapping */
  else
    {
      if (is_updated)
	is_updated[0] = 1;
      remove_overlapping_sub_prefixes (lcm, &a->eid, 0 == ls_args->locators);

      ls_args->is_add = 1;
      ls_args->index = ~0;

      vnet_lisp_add_del_locator_set (ls_args, &ls_index);

      /* add mapping */
      a->is_add = 1;
      a->locator_set_index = ls_index;
      vnet_lisp_map_cache_add_del (a, &dst_map_index);

      if (res_map_index)
	res_map_index[0] = dst_map_index;
    }

  /* success */
  return 0;
}

/**
 * Removes a mapping. Does not program forwarding.
 *
 * @param eid end-host identifier
 * @param res_map_index index of the removed mapping
 * @return return code
 */
int
vnet_lisp_del_mapping (gid_address_t * eid, u32 * res_map_index)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  vnet_lisp_add_del_mapping_args_t _m_args, *m_args = &_m_args;
  vnet_lisp_add_del_locator_set_args_t _ls_args, *ls_args = &_ls_args;
  mapping_t *old_map;
  u32 mi;

  memset (ls_args, 0, sizeof (ls_args[0]));
  memset (m_args, 0, sizeof (m_args[0]));
  if (res_map_index)
    res_map_index[0] = ~0;

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
  old_map = ((u32) ~ 0 != mi) ? pool_elt_at_index (lcm->mapping_pool, mi) : 0;

  if (old_map == 0 || gid_address_cmp (&old_map->eid, eid) != 0)
    {
      clib_warning ("cannot delete mapping for eid %U",
		    format_gid_address, eid);
      return -1;
    }

  m_args->is_add = 0;
  gid_address_copy (&m_args->eid, eid);
  m_args->locator_set_index = old_map->locator_set_index;

  /* delete mapping associated from map-cache */
  vnet_lisp_map_cache_add_del (m_args, 0);

  ls_args->is_add = 0;
  ls_args->index = old_map->locator_set_index;

  /* delete locator set */
  vnet_lisp_add_del_locator_set (ls_args, 0);

  /* delete timer associated to the mapping if any */
  if (old_map->timer_set)
    mapping_delete_timer (lcm, mi);

  /* return old mapping index */
  if (res_map_index)
    res_map_index[0] = mi;

  /* success */
  return 0;
}

int
vnet_lisp_clear_all_remote_adjacencies (void)
{
  int rv = 0;
  u32 mi, *map_indices = 0, *map_indexp;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  vnet_lisp_add_del_mapping_args_t _dm_args, *dm_args = &_dm_args;
  vnet_lisp_add_del_locator_set_args_t _ls, *ls = &_ls;

  /* *INDENT-OFF* */
  pool_foreach_index (mi, lcm->mapping_pool,
  ({
    vec_add1 (map_indices, mi);
  }));
  /* *INDENT-ON* */

  vec_foreach (map_indexp, map_indices)
  {
    mapping_t *map = pool_elt_at_index (lcm->mapping_pool, map_indexp[0]);
    if (!map->local)
      {
	dp_del_fwd_entry (lcm, map_indexp[0]);

	dm_args->is_add = 0;
	gid_address_copy (&dm_args->eid, &map->eid);
	dm_args->locator_set_index = map->locator_set_index;

	/* delete mapping associated to fwd entry */
	vnet_lisp_map_cache_add_del (dm_args, 0);

	ls->is_add = 0;
	ls->local = 0;
	ls->index = map->locator_set_index;
	/* delete locator set */
	rv = vnet_lisp_add_del_locator_set (ls, 0);
	if (rv != 0)
	  goto cleanup;
      }
  }

cleanup:
  if (map_indices)
    vec_free (map_indices);
  return rv;
}

/**
 * Adds adjacency or removes forwarding entry associated to remote mapping.
 * Note that adjacencies are not stored, they only result in forwarding entries
 * being created.
 */
int
vnet_lisp_add_del_adjacency (vnet_lisp_add_del_adjacency_args_t * a)
{
  lisp_cp_main_t *lcm = &lisp_control_main;
  u32 local_mi, remote_mi = ~0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  remote_mi = gid_dictionary_sd_lookup (&lcm->mapping_index_by_gid,
					&a->reid, &a->leid);
  if (GID_LOOKUP_MISS == remote_mi)
    {
      clib_warning ("Remote eid %U not found. Cannot add adjacency!",
		    format_gid_address, &a->reid);

      return -1;
    }

  if (a->is_add)
    {
      /* check if source eid has an associated mapping. If pitr mode is on,
       * just use the pitr's mapping */
      if (lcm->flags & LISP_FLAG_PITR_MODE)
	{
	  if (lcm->pitr_map_index != ~0)
	    {
	      local_mi = lcm->pitr_map_index;
	    }
	  else
	    {
	      /* PITR mode is on, but no mapping is configured */
	      return -1;
	    }
	}
      else
	{
	  if (gid_address_type (&a->reid) == GID_ADDR_NSH)
	    {
	      if (lcm->nsh_map_index == ~0)
		local_mi = GID_LOOKUP_MISS;
	      else
		local_mi = lcm->nsh_map_index;
	    }
	  else
	    {
	      local_mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid,
						&a->leid);
	    }
	}

      if (GID_LOOKUP_MISS == local_mi)
	{
	  clib_warning ("Local eid %U not found. Cannot add adjacency!",
			format_gid_address, &a->leid);

	  return -1;
	}

      /* update forwarding */
      dp_add_fwd_entry (lcm, local_mi, remote_mi);
    }
  else
    dp_del_fwd_entry (lcm, remote_mi);

  return 0;
}

int
vnet_lisp_set_map_request_mode (u8 mode)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (mode >= _MR_MODE_MAX)
    {
      clib_warning ("Invalid LISP map request mode %d!", mode);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  lcm->map_request_mode = mode;
  return 0;
}

int
vnet_lisp_nsh_set_locator_set (u8 * locator_set_name, u8 is_add)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  u32 locator_set_index = ~0;
  mapping_t *m;
  uword *p;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (is_add)
    {
      if (lcm->nsh_map_index == (u32) ~ 0)
	{
	  p = hash_get_mem (lcm->locator_set_index_by_name, locator_set_name);
	  if (!p)
	    {
	      clib_warning ("locator-set %v doesn't exist", locator_set_name);
	      return -1;
	    }
	  locator_set_index = p[0];

	  pool_get (lcm->mapping_pool, m);
	  memset (m, 0, sizeof *m);
	  m->locator_set_index = locator_set_index;
	  m->local = 1;
	  m->nsh_set = 1;
	  lcm->nsh_map_index = m - lcm->mapping_pool;

	  if (~0 == vnet_lisp_gpe_add_nsh_iface (lgm))
	    return -1;
	}
    }
  else
    {
      if (lcm->nsh_map_index != (u32) ~ 0)
	{
	  /* remove NSH mapping */
	  pool_put_index (lcm->mapping_pool, lcm->nsh_map_index);
	  lcm->nsh_map_index = ~0;
	  vnet_lisp_gpe_del_nsh_iface (lgm);
	}
    }
  return 0;
}

int
vnet_lisp_pitr_set_locator_set (u8 * locator_set_name, u8 is_add)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 locator_set_index = ~0;
  mapping_t *m;
  uword *p;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  p = hash_get_mem (lcm->locator_set_index_by_name, locator_set_name);
  if (!p)
    {
      clib_warning ("locator-set %v doesn't exist", locator_set_name);
      return -1;
    }
  locator_set_index = p[0];

  if (is_add)
    {
      pool_get (lcm->mapping_pool, m);
      m->locator_set_index = locator_set_index;
      m->local = 1;
      m->pitr_set = 1;
      lcm->pitr_map_index = m - lcm->mapping_pool;
    }
  else
    {
      /* remove pitr mapping */
      pool_put_index (lcm->mapping_pool, lcm->pitr_map_index);
      lcm->pitr_map_index = ~0;
    }
  return 0;
}

int
vnet_lisp_map_register_fallback_threshold_set (u32 value)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  if (0 == value)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  lcm->max_expired_map_registers = value;
  return 0;
}

u32
vnet_lisp_map_register_fallback_threshold_get (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->max_expired_map_registers;
}

/**
 * Configure Proxy-ETR
 *
 * @param ip PETR's IP address
 * @param is_add Flag that indicates if this is an addition or removal
 *
 * return 0 on success
 */
int
vnet_lisp_use_petr (ip_address_t * ip, u8 is_add)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 ls_index = ~0;
  mapping_t *m;
  vnet_lisp_add_del_locator_set_args_t _ls_args, *ls_args = &_ls_args;
  locator_t loc;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  memset (ls_args, 0, sizeof (*ls_args));

  if (is_add)
    {
      /* Create dummy petr locator-set */
      memset (&loc, 0, sizeof (loc));
      gid_address_from_ip (&loc.address, ip);
      loc.priority = 1;
      loc.state = loc.weight = 1;
      loc.local = 0;

      ls_args->is_add = 1;
      ls_args->index = ~0;
      vec_add1 (ls_args->locators, loc);
      vnet_lisp_add_del_locator_set (ls_args, &ls_index);

      /* Add petr mapping */
      pool_get (lcm->mapping_pool, m);
      m->locator_set_index = ls_index;
      lcm->petr_map_index = m - lcm->mapping_pool;

      /* Enable use-petr */
      lcm->flags |= LISP_FLAG_USE_PETR;
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->petr_map_index);

      /* Remove petr locator */
      ls_args->is_add = 0;
      ls_args->index = m->locator_set_index;
      vnet_lisp_add_del_locator_set (ls_args, 0);

      /* Remove petr mapping */
      pool_put_index (lcm->mapping_pool, lcm->petr_map_index);

      /* Disable use-petr */
      lcm->flags &= ~LISP_FLAG_USE_PETR;
      lcm->petr_map_index = ~0;
    }
  return 0;
}

/* cleans locator to locator-set data and removes locators not part of
 * any locator-set */
static void
clean_locator_to_locator_set (lisp_cp_main_t * lcm, u32 lsi)
{
  u32 i, j, *loc_indexp, *ls_indexp, **ls_indexes, *to_be_deleted = 0;
  locator_set_t *ls = pool_elt_at_index (lcm->locator_set_pool, lsi);
  for (i = 0; i < vec_len (ls->locator_indices); i++)
    {
      loc_indexp = vec_elt_at_index (ls->locator_indices, i);
      ls_indexes = vec_elt_at_index (lcm->locator_to_locator_sets,
				     loc_indexp[0]);
      for (j = 0; j < vec_len (ls_indexes[0]); j++)
	{
	  ls_indexp = vec_elt_at_index (ls_indexes[0], j);
	  if (ls_indexp[0] == lsi)
	    break;
	}

      /* delete index for removed locator-set */
      vec_del1 (ls_indexes[0], j);

      /* delete locator if it's part of no locator-set */
      if (vec_len (ls_indexes[0]) == 0)
	{
	  pool_put_index (lcm->locator_pool, loc_indexp[0]);
	  vec_add1 (to_be_deleted, i);
	}
    }

  if (to_be_deleted)
    {
      for (i = 0; i < vec_len (to_be_deleted); i++)
	{
	  loc_indexp = vec_elt_at_index (to_be_deleted, i);
	  vec_del1 (ls->locator_indices, loc_indexp[0]);
	}
      vec_free (to_be_deleted);
    }
}

static inline uword *
get_locator_set_index (vnet_lisp_add_del_locator_set_args_t * a, uword * p)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  ASSERT (a != NULL);
  ASSERT (p != NULL);

  /* find locator-set */
  if (a->local)
    {
      ASSERT (a->name);
      p = hash_get_mem (lcm->locator_set_index_by_name, a->name);
    }
  else
    {
      *p = a->index;
    }

  return p;
}

static inline int
is_locator_in_locator_set (lisp_cp_main_t * lcm, locator_set_t * ls,
			   locator_t * loc)
{
  locator_t *itloc;
  u32 *locit;

  ASSERT (ls != NULL);
  ASSERT (loc != NULL);

  vec_foreach (locit, ls->locator_indices)
  {
    itloc = pool_elt_at_index (lcm->locator_pool, locit[0]);
    if ((ls->local && itloc->sw_if_index == loc->sw_if_index) ||
	(!ls->local && !gid_address_cmp (&itloc->address, &loc->address)))
      {
	clib_warning ("Duplicate locator");
	return VNET_API_ERROR_VALUE_EXIST;
      }
  }

  return 0;
}

static void
update_adjacencies_by_map_index (lisp_cp_main_t * lcm,
				 u32 mapping_index, u8 remove_only)
{
  fwd_entry_t *fwd;
  mapping_t *map;
  uword *fei = 0, *rmts_idxp = 0;
  u32 **rmts = 0, *remote_idxp = 0, *rmts_copy = 0;
  vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
  memset (a, 0, sizeof (*a));

  map = pool_elt_at_index (lcm->mapping_pool, mapping_index);

  if (map->local)
    {
      rmts_idxp = hash_get (lcm->lcl_to_rmt_adjs_by_lcl_idx, mapping_index);
      if (rmts_idxp)
	{
	  rmts =
	    pool_elt_at_index (lcm->lcl_to_rmt_adjacencies, rmts_idxp[0]);
	  rmts_copy = vec_dup (rmts[0]);

	  vec_foreach (remote_idxp, rmts_copy)
	  {
	    fei = hash_get (lcm->fwd_entry_by_mapping_index, remote_idxp[0]);
	    if (!fei)
	      continue;

	    fwd = pool_elt_at_index (lcm->fwd_entry_pool, fei[0]);
	    a->is_add = 0;
	    gid_address_copy (&a->leid, &fwd->leid);
	    gid_address_copy (&a->reid, &fwd->reid);
	    vnet_lisp_add_del_adjacency (a);

	    if (!remove_only)
	      {
		a->is_add = 1;
		vnet_lisp_add_del_adjacency (a);
	      }
	  }
	  vec_free (rmts_copy);
	}
    }
  else
    {
      fei = hash_get (lcm->fwd_entry_by_mapping_index, mapping_index);
      if (!fei)
	return;

      fwd = pool_elt_at_index (lcm->fwd_entry_pool, fei[0]);
      a->is_add = 0;
      gid_address_copy (&a->leid, &fwd->leid);
      gid_address_copy (&a->reid, &fwd->reid);
      vnet_lisp_add_del_adjacency (a);

      if (!remove_only)
	{
	  a->is_add = 1;
	  vnet_lisp_add_del_adjacency (a);
	}
    }
}

static void
update_fwd_entries_by_locator_set (lisp_cp_main_t * lcm,
				   u32 ls_index, u8 remove_only)
{
  u32 i, *map_indexp;
  u32 **eid_indexes;

  if (vec_len (lcm->locator_set_to_eids) <= ls_index)
    return;

  eid_indexes = vec_elt_at_index (lcm->locator_set_to_eids, ls_index);

  for (i = 0; i < vec_len (eid_indexes[0]); i++)
    {
      map_indexp = vec_elt_at_index (eid_indexes[0], i);
      update_adjacencies_by_map_index (lcm, map_indexp[0], remove_only);
    }
}

static inline void
remove_locator_from_locator_set (locator_set_t * ls, u32 * locit,
				 u32 ls_index, u32 loc_id)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 **ls_indexes = NULL;

  ASSERT (ls != NULL);
  ASSERT (locit != NULL);

  ls_indexes = vec_elt_at_index (lcm->locator_to_locator_sets, locit[0]);
  pool_put_index (lcm->locator_pool, locit[0]);
  vec_del1 (ls->locator_indices, loc_id);
  vec_del1 (ls_indexes[0], ls_index);
}

int
vnet_lisp_add_del_locator (vnet_lisp_add_del_locator_set_args_t * a,
			   locator_set_t * ls, u32 * ls_result)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_t *loc = NULL, *itloc = NULL;
  uword _p = (u32) ~ 0, *p = &_p;
  u32 loc_index = ~0, ls_index = ~0, *locit = NULL, **ls_indexes = NULL;
  u32 loc_id = ~0;
  int ret = 0;

  ASSERT (a != NULL);

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  p = get_locator_set_index (a, p);
  if (!p)
    {
      clib_warning ("locator-set %v doesn't exist", a->name);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (ls == 0)
    {
      ls = pool_elt_at_index (lcm->locator_set_pool, p[0]);
      if (!ls)
	{
	  clib_warning ("locator-set %d to be overwritten doesn't exist!",
			p[0]);
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}
    }

  if (a->is_add)
    {
      if (ls_result)
	ls_result[0] = p[0];

      /* allocate locators */
      vec_foreach (itloc, a->locators)
      {
	ret = is_locator_in_locator_set (lcm, ls, itloc);
	if (0 != ret)
	  {
	    return ret;
	  }

	pool_get (lcm->locator_pool, loc);
	loc[0] = itloc[0];
	loc_index = loc - lcm->locator_pool;

	vec_add1 (ls->locator_indices, loc_index);

	vec_validate (lcm->locator_to_locator_sets, loc_index);
	ls_indexes = vec_elt_at_index (lcm->locator_to_locator_sets,
				       loc_index);
	vec_add1 (ls_indexes[0], p[0]);
      }
    }
  else
    {
      ls_index = p[0];
      u8 removed;

      vec_foreach (itloc, a->locators)
      {
	removed = 0;
	loc_id = 0;
	vec_foreach (locit, ls->locator_indices)
	{
	  loc = pool_elt_at_index (lcm->locator_pool, locit[0]);

	  if (loc->local && loc->sw_if_index == itloc->sw_if_index)
	    {
	      removed = 1;
	      remove_locator_from_locator_set (ls, locit, ls_index, loc_id);
	    }
	  if (0 == loc->local &&
	      !gid_address_cmp (&loc->address, &itloc->address))
	    {
	      removed = 1;
	      remove_locator_from_locator_set (ls, locit, ls_index, loc_id);
	    }

	  if (removed)
	    {
	      /* update fwd entries using this locator in DP */
	      update_fwd_entries_by_locator_set (lcm, ls_index,
						 vec_len (ls->locator_indices)
						 == 0);
	    }

	  loc_id++;
	}
      }
    }

  return 0;
}

int
vnet_lisp_add_del_locator_set (vnet_lisp_add_del_locator_set_args_t * a,
			       u32 * ls_result)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *ls;
  uword _p = (u32) ~ 0, *p = &_p;
  u32 ls_index;
  u32 **eid_indexes;
  int ret = 0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {
      p = get_locator_set_index (a, p);

      /* overwrite */
      if (p && p[0] != (u32) ~ 0)
	{
	  ls = pool_elt_at_index (lcm->locator_set_pool, p[0]);
	  if (!ls)
	    {
	      clib_warning ("locator-set %d to be overwritten doesn't exist!",
			    p[0]);
	      return -1;
	    }

	  /* clean locator to locator-set vectors and remove locators if
	   * they're not part of another locator-set */
	  clean_locator_to_locator_set (lcm, p[0]);

	  /* remove locator indices from locator set */
	  vec_free (ls->locator_indices);

	  ls_index = p[0];

	  if (ls_result)
	    ls_result[0] = p[0];
	}
      /* new locator-set */
      else
	{
	  pool_get (lcm->locator_set_pool, ls);
	  memset (ls, 0, sizeof (*ls));
	  ls_index = ls - lcm->locator_set_pool;

	  if (a->local)
	    {
	      ls->name = vec_dup (a->name);

	      if (!lcm->locator_set_index_by_name)
		lcm->locator_set_index_by_name = hash_create_vec (
								   /* size */
								   0,
								   sizeof
								   (ls->name
								    [0]),
								   sizeof
								   (uword));
	      hash_set_mem (lcm->locator_set_index_by_name, ls->name,
			    ls_index);

	      /* mark as local locator-set */
	      vec_add1 (lcm->local_locator_set_indexes, ls_index);
	    }
	  ls->local = a->local;
	  if (ls_result)
	    ls_result[0] = ls_index;
	}

      ret = vnet_lisp_add_del_locator (a, ls, NULL);
      if (0 != ret)
	{
	  return ret;
	}
    }
  else
    {
      p = get_locator_set_index (a, p);
      if (!p)
	{
	  clib_warning ("locator-set %v doesn't exists", a->name);
	  return -1;
	}

      ls = pool_elt_at_index (lcm->locator_set_pool, p[0]);
      if (!ls)
	{
	  clib_warning ("locator-set with index %d doesn't exists", p[0]);
	  return -1;
	}

      if (lcm->mreq_itr_rlocs == p[0])
	{
	  clib_warning ("Can't delete the locator-set used to constrain "
			"the itr-rlocs in map-requests!");
	  return -1;
	}

      if (vec_len (lcm->locator_set_to_eids) != 0)
	{
	  eid_indexes = vec_elt_at_index (lcm->locator_set_to_eids, p[0]);
	  if (vec_len (eid_indexes[0]) != 0)
	    {
	      clib_warning
		("Can't delete a locator that supports a mapping!");
	      return -1;
	    }
	}

      /* clean locator to locator-sets data */
      clean_locator_to_locator_set (lcm, p[0]);

      if (ls->local)
	{
	  u32 it, lsi;

	  vec_foreach_index (it, lcm->local_locator_set_indexes)
	  {
	    lsi = vec_elt (lcm->local_locator_set_indexes, it);
	    if (lsi == p[0])
	      {
		vec_del1 (lcm->local_locator_set_indexes, it);
		break;
	      }
	  }
	  hash_unset_mem (lcm->locator_set_index_by_name, ls->name);
	}
      vec_free (ls->name);
      vec_free (ls->locator_indices);
      pool_put (lcm->locator_set_pool, ls);
    }
  return 0;
}

int
vnet_lisp_rloc_probe_enable_disable (u8 is_enable)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  lcm->rloc_probing = is_enable;
  return 0;
}

int
vnet_lisp_map_register_enable_disable (u8 is_enable)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  lcm->map_registering = is_enable;
  return 0;
}

static void
lisp_cp_register_dst_port (vlib_main_t * vm)
{
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp,
			 lisp_cp_input_node.index, 1 /* is_ip4 */ );
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp6,
			 lisp_cp_input_node.index, 0 /* is_ip4 */ );
}

static void
lisp_cp_unregister_dst_port (vlib_main_t * vm)
{
  udp_unregister_dst_port (vm, UDP_DST_PORT_lisp_cp, 0 /* is_ip4 */ );
  udp_unregister_dst_port (vm, UDP_DST_PORT_lisp_cp6, 1 /* is_ip4 */ );
}

/**
 * lisp_cp_enable_l2_l3_ifaces
 *
 * Enable all l2 and l3 ifaces
 */
static void
lisp_cp_enable_l2_l3_ifaces (lisp_cp_main_t * lcm, u8 with_default_route)
{
  u32 vni, dp_table;

  /* *INDENT-OFF* */
  hash_foreach(vni, dp_table, lcm->table_id_by_vni, ({
    dp_add_del_iface(lcm, vni, /* is_l2 */ 0, /* is_add */1,
                     with_default_route);
  }));
  hash_foreach(vni, dp_table, lcm->bd_id_by_vni, ({
    dp_add_del_iface(lcm, vni, /* is_l2 */ 1, 1,
                     with_default_route);
  }));
  /* *INDENT-ON* */
}

static void
lisp_cp_disable_l2_l3_ifaces (lisp_cp_main_t * lcm)
{
  u32 **rmts;

  /* clear interface table */
  hash_free (lcm->fwd_entry_by_mapping_index);
  pool_free (lcm->fwd_entry_pool);
  /* Clear state tracking rmt-lcl fwd entries */
  /* *INDENT-OFF* */
  pool_foreach(rmts, lcm->lcl_to_rmt_adjacencies,
  {
    vec_free(rmts[0]);
  });
  /* *INDENT-ON* */
  hash_free (lcm->lcl_to_rmt_adjs_by_lcl_idx);
  pool_free (lcm->lcl_to_rmt_adjacencies);
}

clib_error_t *
vnet_lisp_enable_disable (u8 is_enable)
{
  clib_error_t *error = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;

  a->is_en = is_enable;
  error = vnet_lisp_gpe_enable_disable (a);
  if (error)
    {
      return clib_error_return (0, "failed to %s data-plane!",
				a->is_en ? "enable" : "disable");
    }

  /* decide what to do based on mode */

  if (lcm->flags & LISP_FLAG_XTR_MODE)
    {
      if (is_enable)
	{
	  lisp_cp_register_dst_port (lcm->vlib_main);
	  lisp_cp_enable_l2_l3_ifaces (lcm, 1 /* with_default_route */ );
	}
      else
	{
	  lisp_cp_unregister_dst_port (lcm->vlib_main);
	  lisp_cp_disable_l2_l3_ifaces (lcm);
	}
    }

  if (lcm->flags & LISP_FLAG_PETR_MODE)
    {
      /* if in xTR mode, the LISP ports were already (un)registered above */
      if (!(lcm->flags & LISP_FLAG_XTR_MODE))
	{
	  if (is_enable)
	    lisp_cp_register_dst_port (lcm->vlib_main);
	  else
	    lisp_cp_unregister_dst_port (lcm->vlib_main);
	}
    }

  if (lcm->flags & LISP_FLAG_PITR_MODE)
    {
      if (is_enable)
	{
	  /* install interfaces, but no default routes */
	  lisp_cp_enable_l2_l3_ifaces (lcm, 0 /* with_default_route */ );
	}
      else
	{
	  lisp_cp_disable_l2_l3_ifaces (lcm);
	}
    }

  /* update global flag */
  lcm->is_enabled = is_enable;

  return 0;
}

u8
vnet_lisp_enable_disable_status (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->is_enabled;
}

int
vnet_lisp_add_del_map_resolver (vnet_lisp_add_del_map_resolver_args_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 i;
  lisp_msmr_t _mr, *mr = &_mr;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {

      if (get_map_resolver (&a->address))
	{
	  clib_warning ("map-resolver %U already exists!", format_ip_address,
			&a->address);
	  return -1;
	}

      memset (mr, 0, sizeof (*mr));
      ip_address_copy (&mr->address, &a->address);
      vec_add1 (lcm->map_resolvers, *mr);

      if (vec_len (lcm->map_resolvers) == 1)
	lcm->do_map_resolver_election = 1;
    }
  else
    {
      for (i = 0; i < vec_len (lcm->map_resolvers); i++)
	{
	  mr = vec_elt_at_index (lcm->map_resolvers, i);
	  if (!ip_address_cmp (&mr->address, &a->address))
	    {
	      if (!ip_address_cmp (&mr->address, &lcm->active_map_resolver))
		lcm->do_map_resolver_election = 1;

	      vec_del1 (lcm->map_resolvers, i);
	      break;
	    }
	}
    }
  return 0;
}

int
vnet_lisp_map_register_set_ttl (u32 ttl)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lcm->map_register_ttl = ttl;
  return 0;
}

u32
vnet_lisp_map_register_get_ttl (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->map_register_ttl;
}

int
vnet_lisp_add_del_mreq_itr_rlocs (vnet_lisp_add_del_mreq_itr_rloc_args_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  uword *p = 0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {
      p = hash_get_mem (lcm->locator_set_index_by_name, a->locator_set_name);
      if (!p)
	{
	  clib_warning ("locator-set %v doesn't exist", a->locator_set_name);
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}

      lcm->mreq_itr_rlocs = p[0];
    }
  else
    {
      lcm->mreq_itr_rlocs = ~0;
    }

  return 0;
}

/* Statistics (not really errors) */
#define foreach_lisp_cp_lookup_error           \
_(DROP, "drop")                                \
_(MAP_REQUESTS_SENT, "map-request sent")       \
_(ARP_REPLY_TX, "ARP replies sent")            \
_(NDP_NEIGHBOR_ADVERTISEMENT_TX,               \
  "neighbor advertisement sent")

static char *lisp_cp_lookup_error_strings[] = {
#define _(sym,string) string,
  foreach_lisp_cp_lookup_error
#undef _
};

typedef enum
{
#define _(sym,str) LISP_CP_LOOKUP_ERROR_##sym,
  foreach_lisp_cp_lookup_error
#undef _
    LISP_CP_LOOKUP_N_ERROR,
} lisp_cp_lookup_error_t;

typedef enum
{
  LISP_CP_LOOKUP_NEXT_DROP,
  LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX,
  LISP_CP_LOOKUP_N_NEXT,
} lisp_cp_lookup_next_t;

typedef struct
{
  gid_address_t dst_eid;
  ip_address_t map_resolver_ip;
} lisp_cp_lookup_trace_t;

u8 *
format_lisp_cp_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_cp_lookup_trace_t *t = va_arg (*args, lisp_cp_lookup_trace_t *);

  s = format (s, "LISP-CP-LOOKUP: map-resolver: %U destination eid %U",
	      format_ip_address, &t->map_resolver_ip, format_gid_address,
	      &t->dst_eid);
  return s;
}

int
get_mr_and_local_iface_ip (lisp_cp_main_t * lcm, ip_address_t * mr_ip,
			   ip_address_t * sloc)
{
  lisp_msmr_t *mrit;
  ip_address_t *a;

  if (vec_len (lcm->map_resolvers) == 0)
    {
      clib_warning ("No map-resolver configured");
      return 0;
    }

  /* find the first mr ip we have a route to and the ip of the
   * iface that has a route to it */
  vec_foreach (mrit, lcm->map_resolvers)
  {
    a = &mrit->address;
    if (0 != ip_fib_get_first_egress_ip_for_dst (lcm, a, sloc))
      {
	ip_address_copy (mr_ip, a);

	/* also update globals */
	return 1;
      }
  }

  clib_warning ("Can't find map-resolver and local interface ip!");
  return 0;
}

static gid_address_t *
build_itr_rloc_list (lisp_cp_main_t * lcm, locator_set_t * loc_set)
{
  void *addr;
  u32 i;
  locator_t *loc;
  u32 *loc_indexp;
  ip_interface_address_t *ia = 0;
  gid_address_t gid_data, *gid = &gid_data;
  gid_address_t *rlocs = 0;
  ip_prefix_t *ippref = &gid_address_ippref (gid);
  ip_address_t *rloc = &ip_prefix_addr (ippref);

  memset (gid, 0, sizeof (gid[0]));
  gid_address_type (gid) = GID_ADDR_IP_PREFIX;
  for (i = 0; i < vec_len (loc_set->locator_indices); i++)
    {
      loc_indexp = vec_elt_at_index (loc_set->locator_indices, i);
      loc = pool_elt_at_index (lcm->locator_pool, loc_indexp[0]);

      /* Add ipv4 locators first TODO sort them */

      /* *INDENT-OFF* */
      foreach_ip_interface_address (&lcm->im4->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
	addr = ip_interface_address_get_address (&lcm->im4->lookup_main, ia);
	ip_address_set (rloc, addr, IP4);
        ip_prefix_len (ippref) = 32;
        ip_prefix_normalize (ippref);
        vec_add1 (rlocs, gid[0]);
      }));

      /* Add ipv6 locators */
      foreach_ip_interface_address (&lcm->im6->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
        addr = ip_interface_address_get_address (&lcm->im6->lookup_main, ia);
        ip_address_set (rloc, addr, IP6);
        ip_prefix_len (ippref) = 128;
        ip_prefix_normalize (ippref);
        vec_add1 (rlocs, gid[0]);
      }));
      /* *INDENT-ON* */

    }
  return rlocs;
}

static vlib_buffer_t *
build_map_request (lisp_cp_main_t * lcm, gid_address_t * deid,
		   ip_address_t * sloc, ip_address_t * rloc,
		   gid_address_t * itr_rlocs, u64 * nonce_res, u32 * bi_res)
{
  vlib_buffer_t *b;
  u32 bi;
  vlib_main_t *vm = lcm->vlib_main;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer for Map-Request!");
      return 0;
    }

  b = vlib_get_buffer (vm, bi);

  /* leave some space for the encap headers */
  vlib_buffer_make_headroom (b, MAX_LISP_MSG_ENCAP_LEN);

  /* put lisp msg */
  lisp_msg_put_mreq (lcm, b, NULL, deid, itr_rlocs, 0 /* smr invoked */ ,
		     1 /* rloc probe */ , nonce_res);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, sloc,
		       rloc, 1);

  bi_res[0] = bi;

  return b;
}

static vlib_buffer_t *
build_encapsulated_map_request (lisp_cp_main_t * lcm,
				gid_address_t * seid, gid_address_t * deid,
				locator_set_t * loc_set, ip_address_t * mr_ip,
				ip_address_t * sloc, u8 is_smr_invoked,
				u64 * nonce_res, u32 * bi_res)
{
  vlib_buffer_t *b;
  u32 bi;
  gid_address_t *rlocs = 0;
  vlib_main_t *vm = lcm->vlib_main;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer for Map-Request!");
      return 0;
    }

  b = vlib_get_buffer (vm, bi);
  b->flags = 0;

  /* leave some space for the encap headers */
  vlib_buffer_make_headroom (b, MAX_LISP_MSG_ENCAP_LEN);

  /* get rlocs */
  rlocs = build_itr_rloc_list (lcm, loc_set);

  if (MR_MODE_SRC_DST == lcm->map_request_mode
      && GID_ADDR_SRC_DST != gid_address_type (deid))
    {
      gid_address_t sd;
      memset (&sd, 0, sizeof (sd));
      build_src_dst (&sd, seid, deid);
      lisp_msg_put_mreq (lcm, b, seid, &sd, rlocs, is_smr_invoked,
			 0 /* rloc probe */ , nonce_res);
    }
  else
    {
      /* put lisp msg */
      lisp_msg_put_mreq (lcm, b, seid, deid, rlocs, is_smr_invoked,
			 0 /* rloc probe */ , nonce_res);
    }

  /* push ecm: udp-ip-lisp */
  lisp_msg_push_ecm (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, seid, deid);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, sloc,
		       mr_ip, 1);

  bi_res[0] = bi;

  vec_free (rlocs);
  return b;
}

static void
reset_pending_mr_counters (pending_map_request_t * r)
{
  r->time_to_expire = PENDING_MREQ_EXPIRATION_TIME;
  r->retries_num = 0;
}

#define foreach_msmr \
  _(server) \
  _(resolver)

#define _(name) \
static int                                                              \
elect_map_ ## name (lisp_cp_main_t * lcm)                               \
{                                                                       \
  lisp_msmr_t *mr;                                                      \
  vec_foreach (mr, lcm->map_ ## name ## s)                              \
  {                                                                     \
    if (!mr->is_down)                                                   \
      {                                                                 \
	ip_address_copy (&lcm->active_map_ ##name, &mr->address);       \
	lcm->do_map_ ## name ## _election = 0;                          \
	return 1;                                                       \
      }                                                                 \
  }                                                                     \
  return 0;                                                             \
}
foreach_msmr
#undef _
  static void
free_map_register_records (mapping_t * maps)
{
  mapping_t *map;
  vec_foreach (map, maps) vec_free (map->locators);

  vec_free (maps);
}

static void
add_locators (lisp_cp_main_t * lcm, mapping_t * m, u32 locator_set_index,
	      ip_address_t * probed_loc)
{
  u32 *li;
  locator_t *loc, new;
  ip_interface_address_t *ia = 0;
  void *addr;
  ip_address_t *new_ip = &gid_address_ip (&new.address);

  m->locators = 0;
  locator_set_t *ls = pool_elt_at_index (lcm->locator_set_pool,
					 locator_set_index);
  vec_foreach (li, ls->locator_indices)
  {
    loc = pool_elt_at_index (lcm->locator_pool, li[0]);
    new = loc[0];
    if (loc->local)
      {
          /* *INDENT-OFF* */
          foreach_ip_interface_address (&lcm->im4->lookup_main, ia,
                                        loc->sw_if_index, 1 /* unnumbered */,
          ({
            addr = ip_interface_address_get_address (&lcm->im4->lookup_main,
                                                     ia);
            ip_address_set (new_ip, addr, IP4);
          }));

          /* Add ipv6 locators */
          foreach_ip_interface_address (&lcm->im6->lookup_main, ia,
                                        loc->sw_if_index, 1 /* unnumbered */,
          ({
            addr = ip_interface_address_get_address (&lcm->im6->lookup_main,
                                                     ia);
            ip_address_set (new_ip, addr, IP6);
          }));
          /* *INDENT-ON* */

	if (probed_loc && ip_address_cmp (probed_loc, new_ip) == 0)
	  new.probed = 1;
      }
    vec_add1 (m->locators, new);
  }
}

static mapping_t *
build_map_register_record_list (lisp_cp_main_t * lcm)
{
  mapping_t *recs = 0, rec, *m;

  /* *INDENT-OFF* */
  pool_foreach(m, lcm->mapping_pool,
  {
    /* for now build only local mappings */
    if (!m->local)
      continue;

    rec = m[0];
    add_locators (lcm, &rec, m->locator_set_index, NULL);
    vec_add1 (recs, rec);
  });
  /* *INDENT-ON* */

  return recs;
}

static int
update_map_register_auth_data (map_register_hdr_t * map_reg_hdr,
			       lisp_key_type_t key_id, u8 * key,
			       u16 auth_data_len, u32 msg_len)
{
  MREG_KEY_ID (map_reg_hdr) = clib_host_to_net_u16 (key_id);
  MREG_AUTH_DATA_LEN (map_reg_hdr) = clib_host_to_net_u16 (auth_data_len);

  unsigned char *result = HMAC (get_encrypt_fcn (key_id), key, vec_len (key),
				(unsigned char *) map_reg_hdr, msg_len, NULL,
				NULL);
  clib_memcpy (MREG_DATA (map_reg_hdr), result, auth_data_len);

  return 0;
}

static vlib_buffer_t *
build_map_register (lisp_cp_main_t * lcm, ip_address_t * sloc,
		    ip_address_t * ms_ip, u64 * nonce_res, u8 want_map_notif,
		    mapping_t * records, lisp_key_type_t key_id, u8 * key,
		    u32 * bi_res)
{
  void *map_reg_hdr;
  vlib_buffer_t *b;
  u32 bi, auth_data_len = 0, msg_len = 0;
  vlib_main_t *vm = lcm->vlib_main;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer for Map-Register!");
      return 0;
    }

  b = vlib_get_buffer (vm, bi);

  /* leave some space for the encap headers */
  vlib_buffer_make_headroom (b, MAX_LISP_MSG_ENCAP_LEN);

  auth_data_len = auth_data_len_by_key_id (key_id);
  map_reg_hdr = lisp_msg_put_map_register (b, records, want_map_notif,
					   auth_data_len, nonce_res,
					   &msg_len);

  update_map_register_auth_data (map_reg_hdr, key_id, key, auth_data_len,
				 msg_len);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, sloc,
		       ms_ip, 1);

  bi_res[0] = bi;
  return b;
}

#define _(name) \
static int                                                              \
get_egress_map_ ##name## _ip (lisp_cp_main_t * lcm, ip_address_t * ip)  \
{                                                                       \
  lisp_msmr_t *mr;                                                      \
  while (lcm->do_map_ ## name ## _election                              \
	 | (0 == ip_fib_get_first_egress_ip_for_dst                     \
            (lcm, &lcm->active_map_ ##name, ip)))                       \
    {                                                                   \
      if (0 == elect_map_ ## name (lcm))                                \
	/* all map resolvers/servers are down */                        \
	{                                                               \
	  /* restart MR/MS checking by marking all of them up */        \
	  vec_foreach (mr, lcm->map_ ## name ## s) mr->is_down = 0;     \
	  return -1;                                                    \
	}                                                               \
    }                                                                   \
  return 0;                                                             \
}

foreach_msmr
#undef _
/* CP output statistics */
#define foreach_lisp_cp_output_error                  \
_(MAP_REGISTERS_SENT, "map-registers sent")           \
_(MAP_REQUESTS_SENT, "map-requests sent")             \
_(RLOC_PROBES_SENT, "rloc-probes sent")
static char *lisp_cp_output_error_strings[] = {
#define _(sym,string) string,
  foreach_lisp_cp_output_error
#undef _
};

typedef enum
{
#define _(sym,str) LISP_CP_OUTPUT_ERROR_##sym,
  foreach_lisp_cp_output_error
#undef _
    LISP_CP_OUTPUT_N_ERROR,
} lisp_cp_output_error_t;

static uword
lisp_cp_output (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * from_frame)
{
  return 0;
}

/* dummy node used only for statistics */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_output_node) = {
  .function = lisp_cp_output,
  .name = "lisp-cp-output",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_OUTPUT_N_ERROR,
  .error_strings = lisp_cp_output_error_strings,

  .n_next_nodes = LISP_CP_INPUT_N_NEXT,

  .next_nodes = {
      [LISP_CP_INPUT_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

static int
send_rloc_probe (lisp_cp_main_t * lcm, gid_address_t * deid,
		 u32 local_locator_set_index, ip_address_t * sloc,
		 ip_address_t * rloc)
{
  locator_set_t *ls;
  u32 bi;
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u64 nonce = 0;
  u32 next_index, *to_next;
  gid_address_t *itr_rlocs;

  ls = pool_elt_at_index (lcm->locator_set_pool, local_locator_set_index);
  itr_rlocs = build_itr_rloc_list (lcm, ls);

  b = build_map_request (lcm, deid, sloc, rloc, itr_rlocs, &nonce, &bi);
  vec_free (itr_rlocs);
  if (!b)
    return -1;

  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;

  next_index = (ip_addr_version (rloc) == IP4) ?
    ip4_lookup_node.index : ip6_lookup_node.index;

  f = vlib_get_frame_to_node (lcm->vlib_main, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (lcm->vlib_main, next_index, f);

  return 0;
}

static int
send_rloc_probes (lisp_cp_main_t * lcm)
{
  u8 lprio = 0;
  mapping_t *lm;
  fwd_entry_t *e;
  locator_pair_t *lp;
  u32 si, rloc_probes_sent = 0;

  /* *INDENT-OFF* */
  pool_foreach (e, lcm->fwd_entry_pool,
  {
    if (vec_len (e->locator_pairs) == 0)
      continue;

    si = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &e->leid);
    if (~0 == si)
      {
        clib_warning ("internal error: cannot find local eid %U in "
                      "map-cache!", format_gid_address, &e->leid);
        continue;
      }
    lm = pool_elt_at_index (lcm->mapping_pool, si);

    /* get the best (lowest) priority */
    lprio = e->locator_pairs[0].priority;

    /* send rloc-probe for pair(s) with the best remote locator priority */
    vec_foreach (lp, e->locator_pairs)
      {
        if (lp->priority != lprio)
          break;

        /* get first remote locator */
        send_rloc_probe (lcm, &e->reid, lm->locator_set_index, &lp->lcl_loc,
                         &lp->rmt_loc);
        rloc_probes_sent++;
      }
  });
  /* *INDENT-ON* */

  vlib_node_increment_counter (vlib_get_main (), lisp_cp_output_node.index,
			       LISP_CP_OUTPUT_ERROR_RLOC_PROBES_SENT,
			       rloc_probes_sent);
  return 0;
}

static int
send_map_register (lisp_cp_main_t * lcm, u8 want_map_notif)
{
  pending_map_register_t *pmr;
  u32 bi, map_registers_sent = 0;
  vlib_buffer_t *b;
  ip_address_t sloc;
  vlib_frame_t *f;
  u64 nonce = 0;
  u32 next_index, *to_next;
  mapping_t *records, *r, *group, *k;

  if (get_egress_map_server_ip (lcm, &sloc) < 0)
    return -1;

  records = build_map_register_record_list (lcm);
  if (!records)
    return -1;

  vec_foreach (r, records)
  {
    u8 *key = r->key;
    u8 key_id = r->key_id;

    if (!key)
      continue;			/* no secret key -> map-register cannot be sent */

    group = 0;
    vec_add1 (group, r[0]);

    /* group mappings that share common key */
    for (k = r + 1; k < vec_end (records); k++)
      {
	if (k->key_id != r->key_id)
	  continue;

	if (vec_is_equal (k->key, r->key))
	  {
	    vec_add1 (group, k[0]);
	    k->key = 0;		/* don't process this mapping again */
	  }
      }

    b = build_map_register (lcm, &sloc, &lcm->active_map_server, &nonce,
			    want_map_notif, group, key_id, key, &bi);
    vec_free (group);
    if (!b)
      continue;

    vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;

    next_index = (ip_addr_version (&lcm->active_map_server) == IP4) ?
      ip4_lookup_node.index : ip6_lookup_node.index;

    f = vlib_get_frame_to_node (lcm->vlib_main, next_index);

    /* Enqueue the packet */
    to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (lcm->vlib_main, next_index, f);
    map_registers_sent++;

    pool_get (lcm->pending_map_registers_pool, pmr);
    memset (pmr, 0, sizeof (*pmr));
    pmr->time_to_expire = PENDING_MREG_EXPIRATION_TIME;
    hash_set (lcm->map_register_messages_by_nonce, nonce,
	      pmr - lcm->pending_map_registers_pool);
  }
  free_map_register_records (records);

  vlib_node_increment_counter (vlib_get_main (), lisp_cp_output_node.index,
			       LISP_CP_OUTPUT_ERROR_MAP_REGISTERS_SENT,
			       map_registers_sent);

  return 0;
}

#define send_encapsulated_map_request(lcm, seid, deid, smr) \
  _send_encapsulated_map_request(lcm, seid, deid, smr, 0)

#define resend_encapsulated_map_request(lcm, seid, deid, smr) \
  _send_encapsulated_map_request(lcm, seid, deid, smr, 1)

static int
_send_encapsulated_map_request (lisp_cp_main_t * lcm,
				gid_address_t * seid, gid_address_t * deid,
				u8 is_smr_invoked, u8 is_resend)
{
  u32 next_index, bi = 0, *to_next, map_index;
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u64 nonce = 0;
  locator_set_t *loc_set;
  mapping_t *map;
  pending_map_request_t *pmr, *duplicate_pmr = 0;
  ip_address_t sloc;
  u32 ls_index;

  /* if there is already a pending request remember it */

  /* *INDENT-OFF* */
  pool_foreach(pmr, lcm->pending_map_requests_pool,
  ({
    if (!gid_address_cmp (&pmr->src, seid)
        && !gid_address_cmp (&pmr->dst, deid))
      {
        duplicate_pmr = pmr;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (!is_resend && duplicate_pmr)
    {
      /* don't send the request if there is a pending map request already */
      return 0;
    }

  u8 pitr_mode = lcm->flags & LISP_FLAG_PITR_MODE;

  /* get locator-set for seid */
  if (!pitr_mode && gid_address_type (deid) != GID_ADDR_NSH)
    {
      map_index = gid_dictionary_lookup (&lcm->mapping_index_by_gid, seid);
      if (map_index == ~0)
	{
	  clib_warning ("No local mapping found in eid-table for %U!",
			format_gid_address, seid);
	  return -1;
	}

      map = pool_elt_at_index (lcm->mapping_pool, map_index);

      if (!map->local)
	{
	  clib_warning
	    ("Mapping found for src eid %U is not marked as local!",
	     format_gid_address, seid);
	  return -1;
	}
      ls_index = map->locator_set_index;
    }
  else
    {
      if (pitr_mode)
	{
	  if (lcm->pitr_map_index != ~0)
	    {
	      map =
		pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
	      ls_index = map->locator_set_index;
	    }
	  else
	    {
	      return -1;
	    }
	}
      else
	{
	  if (lcm->nsh_map_index == (u32) ~ 0)
	    {
	      clib_warning ("No locator-set defined for NSH!");
	      return -1;
	    }
	  else
	    {
	      map = pool_elt_at_index (lcm->mapping_pool, lcm->nsh_map_index);
	      ls_index = map->locator_set_index;
	    }
	}
    }

  /* overwrite locator set if map-request itr-rlocs configured */
  if (~0 != lcm->mreq_itr_rlocs)
    {
      ls_index = lcm->mreq_itr_rlocs;
    }

  loc_set = pool_elt_at_index (lcm->locator_set_pool, ls_index);

  if (get_egress_map_resolver_ip (lcm, &sloc) < 0)
    {
      if (duplicate_pmr)
	duplicate_pmr->to_be_removed = 1;
      return -1;
    }

  /* build the encapsulated map request */
  b = build_encapsulated_map_request (lcm, seid, deid, loc_set,
				      &lcm->active_map_resolver,
				      &sloc, is_smr_invoked, &nonce, &bi);

  if (!b)
    return -1;

  /* set fib index to default and lookup node */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;
  next_index = (ip_addr_version (&lcm->active_map_resolver) == IP4) ?
    ip4_lookup_node.index : ip6_lookup_node.index;

  f = vlib_get_frame_to_node (lcm->vlib_main, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (lcm->vlib_main, next_index, f);

  vlib_node_increment_counter (vlib_get_main (), lisp_cp_output_node.index,
			       LISP_CP_OUTPUT_ERROR_MAP_REQUESTS_SENT, 1);

  if (duplicate_pmr)
    /* if there is a pending request already update it */
    {
      if (clib_fifo_elts (duplicate_pmr->nonces) >= PENDING_MREQ_QUEUE_LEN)
	{
	  /* remove the oldest nonce */
	  u64 CLIB_UNUSED (tmp), *nonce_del;
	  nonce_del = clib_fifo_head (duplicate_pmr->nonces);
	  hash_unset (lcm->pending_map_requests_by_nonce, nonce_del[0]);
	  clib_fifo_sub1 (duplicate_pmr->nonces, tmp);
	}

      clib_fifo_add1 (duplicate_pmr->nonces, nonce);
      hash_set (lcm->pending_map_requests_by_nonce, nonce,
		duplicate_pmr - lcm->pending_map_requests_pool);
    }
  else
    {
      /* add map-request to pending requests table */
      pool_get (lcm->pending_map_requests_pool, pmr);
      memset (pmr, 0, sizeof (*pmr));
      gid_address_copy (&pmr->src, seid);
      gid_address_copy (&pmr->dst, deid);
      clib_fifo_add1 (pmr->nonces, nonce);
      pmr->is_smr_invoked = is_smr_invoked;
      reset_pending_mr_counters (pmr);
      hash_set (lcm->pending_map_requests_by_nonce, nonce,
		pmr - lcm->pending_map_requests_pool);
    }

  return 0;
}

static void
get_src_and_dst_ip (void *hdr, ip_address_t * src, ip_address_t * dst)
{
  ip4_header_t *ip4 = hdr;
  ip6_header_t *ip6;

  if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
    {
      ip_address_set (src, &ip4->src_address, IP4);
      ip_address_set (dst, &ip4->dst_address, IP4);
    }
  else
    {
      ip6 = hdr;
      ip_address_set (src, &ip6->src_address, IP6);
      ip_address_set (dst, &ip6->dst_address, IP6);
    }
}

static u32
lisp_get_vni_from_buffer_ip (lisp_cp_main_t * lcm, vlib_buffer_t * b,
			     u8 version)
{
  uword *vnip;
  u32 vni = ~0, table_id = ~0;

  table_id = fib_table_get_table_id_for_sw_if_index ((version ==
						      IP4 ? FIB_PROTOCOL_IP4 :
						      FIB_PROTOCOL_IP6),
						     vnet_buffer
						     (b)->sw_if_index
						     [VLIB_RX]);

  vnip = hash_get (lcm->vni_by_table_id, table_id);
  if (vnip)
    vni = vnip[0];
  else
    clib_warning ("vrf %d is not mapped to any vni!", table_id);

  return vni;
}

always_inline u32
lisp_get_bd_from_buffer_eth (vlib_buffer_t * b)
{
  u32 sw_if_index0;

  l2input_main_t *l2im = &l2input_main;
  l2_input_config_t *config;
  l2_bridge_domain_t *bd_config;

  sw_if_index0 = vnet_buffer (b)->sw_if_index[VLIB_RX];
  config = vec_elt_at_index (l2im->configs, sw_if_index0);
  bd_config = vec_elt_at_index (l2im->bd_configs, config->bd_index);

  return bd_config->bd_id;
}

always_inline u32
lisp_get_vni_from_buffer_eth (lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  uword *vnip;
  u32 vni = ~0;
  u32 bd = lisp_get_bd_from_buffer_eth (b);

  vnip = hash_get (lcm->vni_by_bd_id, bd);
  if (vnip)
    vni = vnip[0];
  else
    clib_warning ("bridge domain %d is not mapped to any vni!", bd);

  return vni;
}

void
get_src_and_dst_eids_from_buffer (lisp_cp_main_t * lcm, vlib_buffer_t * b,
				  gid_address_t * src, gid_address_t * dst,
				  u16 type)
{
  ethernet_header_t *eh;
  u32 vni = 0;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *opt;

  memset (src, 0, sizeof (*src));
  memset (dst, 0, sizeof (*dst));

  gid_address_type (dst) = GID_ADDR_NO_ADDRESS;
  gid_address_type (src) = GID_ADDR_NO_ADDRESS;

  if (LISP_AFI_IP == type || LISP_AFI_IP6 == type)
    {
      ip4_header_t *ip;
      u8 version, preflen;

      gid_address_type (src) = GID_ADDR_IP_PREFIX;
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;

      ip = vlib_buffer_get_current (b);
      get_src_and_dst_ip (ip, &gid_address_ip (src), &gid_address_ip (dst));

      version = gid_address_ip_version (src);
      preflen = ip_address_max_len (version);
      gid_address_ippref_len (src) = preflen;
      gid_address_ippref_len (dst) = preflen;

      vni = lisp_get_vni_from_buffer_ip (lcm, b, version);
      gid_address_vni (dst) = vni;
      gid_address_vni (src) = vni;
    }
  else if (LISP_AFI_MAC == type)
    {
      ethernet_arp_header_t *ah;

      eh = vlib_buffer_get_current (b);

      if (clib_net_to_host_u16 (eh->type) == ETHERNET_TYPE_ARP)
	{
	  ah = (ethernet_arp_header_t *) (((u8 *) eh) + sizeof (*eh));
	  gid_address_type (dst) = GID_ADDR_ARP;

	  if (clib_net_to_host_u16 (ah->opcode)
	      != ETHERNET_ARP_OPCODE_request)
	    {
	      memset (&gid_address_arp_ndp_ip (dst), 0,
		      sizeof (ip_address_t));
	      ip_addr_version (&gid_address_arp_ndp_ip (dst)) = IP4;
	      gid_address_arp_ndp_bd (dst) = ~0;
	      return;
	    }

	  gid_address_arp_bd (dst) = lisp_get_bd_from_buffer_eth (b);
	  clib_memcpy (&gid_address_arp_ip4 (dst),
		       &ah->ip4_over_ethernet[1].ip4, 4);
	}
      else
	{
	  if (clib_net_to_host_u16 (eh->type) == ETHERNET_TYPE_IP6)
	    {
	      ip6_header_t *ip;
	      ip = (ip6_header_t *) (eh + 1);

	      if (IP_PROTOCOL_ICMP6 == ip->protocol)
		{
		  icmp6_neighbor_solicitation_or_advertisement_header_t *ndh;
		  ndh = ip6_next_header (ip);
		  if (ndh->icmp.type == ICMP6_neighbor_solicitation)
		    {
		      gid_address_type (dst) = GID_ADDR_NDP;

		      /* check that source link layer address option is present */
		      opt = (void *) (ndh + 1);
		      if ((opt->header.type !=
			   ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address)
			  || (opt->header.n_data_u64s != 1))
			{
			  memset (&gid_address_arp_ndp_ip (dst), 0,
				  sizeof (ip_address_t));
			  ip_addr_version (&gid_address_arp_ndp_ip (dst)) =
			    IP6;
			  gid_address_arp_ndp_bd (dst) = ~0;
			  gid_address_type (src) = GID_ADDR_NO_ADDRESS;
			  return;
			}

		      gid_address_ndp_bd (dst) =
			lisp_get_bd_from_buffer_eth (b);
		      ip_address_set (&gid_address_arp_ndp_ip (dst),
				      &ndh->target_address, IP6);
		      return;
		    }
		}
	    }

	  gid_address_type (src) = GID_ADDR_MAC;
	  gid_address_type (dst) = GID_ADDR_MAC;
	  mac_copy (&gid_address_mac (src), eh->src_address);
	  mac_copy (&gid_address_mac (dst), eh->dst_address);

	  /* get vni */
	  vni = lisp_get_vni_from_buffer_eth (lcm, b);

	  gid_address_vni (dst) = vni;
	  gid_address_vni (src) = vni;
	}
    }
  else if (LISP_AFI_LCAF == type)
    {
      lisp_nsh_hdr_t *nh;
      eh = vlib_buffer_get_current (b);

      if (clib_net_to_host_u16 (eh->type) == ETHERNET_TYPE_NSH)
	{
	  nh = (lisp_nsh_hdr_t *) (((u8 *) eh) + sizeof (*eh));
	  u32 spi = clib_net_to_host_u32 (nh->spi_si << 8);
	  u8 si = (u8) clib_net_to_host_u32 (nh->spi_si);
	  gid_address_nsh_spi (dst) = spi;
	  gid_address_nsh_si (dst) = si;

	  gid_address_type (dst) = GID_ADDR_NSH;
	  gid_address_type (src) = GID_ADDR_NSH;
	}
    }
}

static uword
lisp_cp_lookup_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, int overlay)
{
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *opt;
  u32 *from, *to_next, di, si;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 next_index;
  uword n_left_from, n_left_to_next;
  vnet_main_t *vnm = vnet_get_main ();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0, sw_if_index0, next0;
	  u64 mac0;
	  vlib_buffer_t *b0;
	  gid_address_t src, dst;
	  ethernet_arp_header_t *arp0;
	  ethernet_header_t *eth0;
	  vnet_hw_interface_t *hw_if0;
	  ethernet_header_t *eh0;
	  icmp6_neighbor_solicitation_or_advertisement_header_t *ndh;
	  ip6_header_t *ip0;

	  pi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = pi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, pi0);

	  /* src/dst eid pair */
	  get_src_and_dst_eids_from_buffer (lcm, b0, &src, &dst, overlay);

	  if (gid_address_type (&dst) == GID_ADDR_ARP)
	    {
	      mac0 = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &dst);
	      if (GID_LOOKUP_MISS_L2 == mac0)
		goto drop;

	      /* send ARP reply */
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	      hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	      eth0 = vlib_buffer_get_current (b0);
	      arp0 = (ethernet_arp_header_t *) (((u8 *) eth0)
						+ sizeof (*eth0));
	      arp0->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
	      arp0->ip4_over_ethernet[1] = arp0->ip4_over_ethernet[0];
	      clib_memcpy (arp0->ip4_over_ethernet[0].ethernet,
			   (u8 *) & mac0, 6);
	      clib_memcpy (&arp0->ip4_over_ethernet[0].ip4,
			   &gid_address_arp_ip4 (&dst), 4);

	      /* Hardware must be ethernet-like. */
	      ASSERT (vec_len (hw_if0->hw_address) == 6);

	      clib_memcpy (eth0->dst_address, eth0->src_address, 6);
	      clib_memcpy (eth0->src_address, hw_if0->hw_address, 6);

	      b0->error = node->errors[LISP_CP_LOOKUP_ERROR_ARP_REPLY_TX];
	      next0 = LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX;
	      goto enqueue;
	    }
	  else if (gid_address_type (&dst) == GID_ADDR_NDP)
	    {
	      mac0 = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &dst);
	      if (GID_LOOKUP_MISS_L2 == mac0)
		goto drop;

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	      eh0 = vlib_buffer_get_current (b0);
	      ip0 = (ip6_header_t *) (eh0 + 1);
	      ndh = ip6_next_header (ip0);
	      int bogus_length;
	      ip0->dst_address = ip0->src_address;
	      ip0->src_address = ndh->target_address;
	      ip0->hop_limit = 255;
	      opt = (void *) (ndh + 1);
	      opt->header.type =
		ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
	      clib_memcpy (opt->ethernet_address, (u8 *) & mac0, 6);
	      ndh->icmp.type = ICMP6_neighbor_advertisement;
	      ndh->advertisement_flags = clib_host_to_net_u32
		(ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED |
		 ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);
	      ndh->icmp.checksum = 0;
	      ndh->icmp.checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0,
						   &bogus_length);
	      clib_memcpy (eh0->dst_address, eh0->src_address, 6);
	      clib_memcpy (eh0->src_address, (u8 *) & mac0, 6);
	      b0->error =
		node->errors
		[LISP_CP_LOOKUP_ERROR_NDP_NEIGHBOR_ADVERTISEMENT_TX];
	      next0 = LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX;
	      goto enqueue;
	    }

	  /* if we have remote mapping for destination already in map-cache
	     add forwarding tunnel directly. If not send a map-request */
	  di = gid_dictionary_sd_lookup (&lcm->mapping_index_by_gid, &dst,
					 &src);
	  if (~0 != di)
	    {
	      mapping_t *m = vec_elt_at_index (lcm->mapping_pool, di);
	      /* send a map-request also in case of negative mapping entry
	         with corresponding action */
	      if (m->action == LISP_SEND_MAP_REQUEST)
		{
		  /* send map-request */
		  queue_map_request (&src, &dst, 0 /* smr_invoked */ ,
				     0 /* is_resend */ );
		}
	      else
		{
		  if (GID_ADDR_NSH != gid_address_type (&dst))
		    {
		      si = gid_dictionary_lookup (&lcm->mapping_index_by_gid,
						  &src);
		    }
		  else
		    si = lcm->nsh_map_index;

		  if (~0 != si)
		    {
		      dp_add_fwd_entry_from_mt (si, di);
		    }
		}
	    }
	  else
	    {
	      /* send map-request */
	      queue_map_request (&src, &dst, 0 /* smr_invoked */ ,
				 0 /* is_resend */ );
	    }

	drop:
	  b0->error = node->errors[LISP_CP_LOOKUP_ERROR_DROP];
	  next0 = LISP_CP_LOOKUP_NEXT_DROP;
	enqueue:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lisp_cp_lookup_trace_t *tr = vlib_add_trace (vm, node, b0,
							   sizeof (*tr));

	      memset (tr, 0, sizeof (*tr));
	      gid_address_copy (&tr->dst_eid, &dst);
	      ip_address_copy (&tr->map_resolver_ip,
			       &lcm->active_map_resolver);
	    }
	  gid_address_free (&dst);
	  gid_address_free (&src);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
lisp_cp_lookup_ip4 (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return (lisp_cp_lookup_inline (vm, node, from_frame, LISP_AFI_IP));
}

static uword
lisp_cp_lookup_ip6 (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return (lisp_cp_lookup_inline (vm, node, from_frame, LISP_AFI_IP6));
}

static uword
lisp_cp_lookup_l2 (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return (lisp_cp_lookup_inline (vm, node, from_frame, LISP_AFI_MAC));
}

static uword
lisp_cp_lookup_nsh (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  /* TODO decide if NSH should be propagated as LCAF or not */
  return (lisp_cp_lookup_inline (vm, node, from_frame, LISP_AFI_LCAF));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_lookup_ip4_node) = {
  .function = lisp_cp_lookup_ip4,
  .name = "lisp-cp-lookup-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_LOOKUP_N_ERROR,
  .error_strings = lisp_cp_lookup_error_strings,

  .n_next_nodes = LISP_CP_LOOKUP_N_NEXT,

  .next_nodes = {
      [LISP_CP_LOOKUP_NEXT_DROP] = "error-drop",
      [LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_lookup_ip6_node) = {
  .function = lisp_cp_lookup_ip6,
  .name = "lisp-cp-lookup-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_LOOKUP_N_ERROR,
  .error_strings = lisp_cp_lookup_error_strings,

  .n_next_nodes = LISP_CP_LOOKUP_N_NEXT,

  .next_nodes = {
      [LISP_CP_LOOKUP_NEXT_DROP] = "error-drop",
      [LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_lookup_l2_node) = {
  .function = lisp_cp_lookup_l2,
  .name = "lisp-cp-lookup-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_LOOKUP_N_ERROR,
  .error_strings = lisp_cp_lookup_error_strings,

  .n_next_nodes = LISP_CP_LOOKUP_N_NEXT,

  .next_nodes = {
      [LISP_CP_LOOKUP_NEXT_DROP] = "error-drop",
      [LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_lookup_nsh_node) = {
  .function = lisp_cp_lookup_nsh,
  .name = "lisp-cp-lookup-nsh",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_LOOKUP_N_ERROR,
  .error_strings = lisp_cp_lookup_error_strings,

  .n_next_nodes = LISP_CP_LOOKUP_N_NEXT,

  .next_nodes = {
      [LISP_CP_LOOKUP_NEXT_DROP] = "error-drop",
      [LISP_CP_LOOKUP_NEXT_ARP_NDP_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

/* lisp_cp_input statistics */
#define foreach_lisp_cp_input_error                               \
_(DROP, "drop")                                                   \
_(RLOC_PROBE_REQ_RECEIVED, "rloc-probe requests received")        \
_(RLOC_PROBE_REP_RECEIVED, "rloc-probe replies received")         \
_(MAP_NOTIFIES_RECEIVED, "map-notifies received")                 \
_(MAP_REPLIES_RECEIVED, "map-replies received")

static char *lisp_cp_input_error_strings[] = {
#define _(sym,string) string,
  foreach_lisp_cp_input_error
#undef _
};

typedef enum
{
#define _(sym,str) LISP_CP_INPUT_ERROR_##sym,
  foreach_lisp_cp_input_error
#undef _
    LISP_CP_INPUT_N_ERROR,
} lisp_cp_input_error_t;

typedef struct
{
  gid_address_t dst_eid;
  ip4_address_t map_resolver_ip;
} lisp_cp_input_trace_t;

u8 *
format_lisp_cp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (lisp_cp_input_trace_t * t) =
    va_arg (*args, lisp_cp_input_trace_t *);

  s = format (s, "LISP-CP-INPUT: TODO");
  return s;
}

static void
remove_expired_mapping (lisp_cp_main_t * lcm, u32 mi)
{
  mapping_t *m;
  vnet_lisp_add_del_adjacency_args_t _adj_args, *adj_args = &_adj_args;
  memset (adj_args, 0, sizeof (adj_args[0]));

  m = pool_elt_at_index (lcm->mapping_pool, mi);

  gid_address_copy (&adj_args->reid, &m->eid);
  adj_args->is_add = 0;
  if (vnet_lisp_add_del_adjacency (adj_args))
    clib_warning ("failed to del adjacency!");

  vnet_lisp_del_mapping (&m->eid, NULL);
  mapping_delete_timer (lcm, mi);
}

static void
mapping_start_expiration_timer (lisp_cp_main_t * lcm, u32 mi,
				f64 expiration_time)
{
  mapping_t *m;
  u64 now = clib_cpu_time_now ();
  u64 cpu_cps = lcm->vlib_main->clib_time.clocks_per_second;
  u64 exp_clock_time = now + expiration_time * cpu_cps;

  m = pool_elt_at_index (lcm->mapping_pool, mi);

  m->timer_set = 1;
  timing_wheel_insert (&lcm->wheel, exp_clock_time, mi);
}

static void
process_expired_mapping (lisp_cp_main_t * lcm, u32 mi)
{
  int rv;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  mapping_t *m = pool_elt_at_index (lcm->mapping_pool, mi);
  uword *fei;
  fwd_entry_t *fe;
  vlib_counter_t c;
  u8 have_stats = 0;

  if (m->delete_after_expiration)
    {
      remove_expired_mapping (lcm, mi);
      return;
    }

  fei = hash_get (lcm->fwd_entry_by_mapping_index, mi);
  if (!fei)
    return;

  fe = pool_elt_at_index (lcm->fwd_entry_pool, fei[0]);

  memset (a, 0, sizeof (*a));
  a->rmt_eid = fe->reid;
  if (fe->is_src_dst)
    a->lcl_eid = fe->leid;
  a->vni = gid_address_vni (&fe->reid);

  rv = vnet_lisp_gpe_get_fwd_stats (a, &c);
  if (0 == rv)
    have_stats = 1;

  if (m->almost_expired)
    {
      m->almost_expired = 0;	/* reset flag */
      if (have_stats)
	{
	  if (m->packets != c.packets)
	    {
	      /* mapping is in use, re-fetch */
	      map_request_args_t mr_args;
	      memset (&mr_args, 0, sizeof (mr_args));
	      mr_args.seid = fe->leid;
	      mr_args.deid = fe->reid;

	      send_map_request_thread_fn (&mr_args);
	    }
	  else
	    remove_expired_mapping (lcm, mi);
	}
      else
	remove_expired_mapping (lcm, mi);
    }
  else
    {
      m->almost_expired = 1;
      mapping_start_expiration_timer (lcm, mi, TIME_UNTIL_REFETCH_OR_DELETE);

      if (have_stats)
	/* save counter */
	m->packets = c.packets;
      else
	m->delete_after_expiration = 1;
    }
}

static void
map_records_arg_free (map_records_arg_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  vec_foreach (m, a->mappings)
  {
    vec_free (m->locators);
    gid_address_free (&m->eid);
  }
  pool_put (lcm->map_records_args_pool[vlib_get_thread_index ()], a);
}

void *
process_map_reply (map_records_arg_t * a)
{
  mapping_t *m;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u32 dst_map_index = 0;
  pending_map_request_t *pmr;
  u64 *noncep;
  uword *pmr_index;
  u8 is_changed = 0;

  if (a->is_rloc_probe)
    goto done;

  /* Check pending requests table and nonce */
  pmr_index = hash_get (lcm->pending_map_requests_by_nonce, a->nonce);
  if (!pmr_index)
    {
      clib_warning ("No pending map-request entry with nonce %lu!", a->nonce);
      goto done;
    }
  pmr = pool_elt_at_index (lcm->pending_map_requests_pool, pmr_index[0]);

  vec_foreach (m, a->mappings)
  {
    vnet_lisp_add_del_mapping_args_t _m_args, *m_args = &_m_args;
    memset (m_args, 0, sizeof (m_args[0]));
    gid_address_copy (&m_args->eid, &m->eid);
    m_args->action = m->action;
    m_args->authoritative = m->authoritative;
    m_args->ttl = m->ttl;
    m_args->is_static = 0;

    /* insert/update mappings cache */
    vnet_lisp_add_mapping (m_args, m->locators, &dst_map_index, &is_changed);

    if (dst_map_index == (u32) ~ 0)
      continue;

    if (is_changed)
      {
	/* try to program forwarding only if mapping saved or updated */
	vnet_lisp_add_del_adjacency_args_t _adj_args, *adj_args = &_adj_args;
	memset (adj_args, 0, sizeof (adj_args[0]));

	gid_address_copy (&adj_args->leid, &pmr->src);
	gid_address_copy (&adj_args->reid, &m->eid);
	adj_args->is_add = 1;

	if (vnet_lisp_add_del_adjacency (adj_args))
	  clib_warning ("failed to add adjacency!");
      }

    if ((u32) ~ 0 != m->ttl)
      mapping_start_expiration_timer (lcm, dst_map_index,
				      (m->ttl == 0) ? 0 : MAPPING_TIMEOUT);
  }

  /* remove pending map request entry */

  /* *INDENT-OFF* */
  clib_fifo_foreach (noncep, pmr->nonces, ({
    hash_unset(lcm->pending_map_requests_by_nonce, noncep[0]);
  }));
  /* *INDENT-ON* */

  clib_fifo_free (pmr->nonces);
  pool_put (lcm->pending_map_requests_pool, pmr);

done:
  a->is_free = 1;
  return 0;
}

static int
is_auth_data_valid (map_notify_hdr_t * h, u32 msg_len,
		    lisp_key_type_t key_id, u8 * key)
{
  u8 *auth_data = 0;
  u16 auth_data_len;
  int result;

  auth_data_len = auth_data_len_by_key_id (key_id);
  if ((u16) ~ 0 == auth_data_len)
    {
      clib_warning ("invalid length for key_id %d!", key_id);
      return 0;
    }

  /* save auth data */
  vec_validate (auth_data, auth_data_len - 1);
  clib_memcpy (auth_data, MNOTIFY_DATA (h), auth_data_len);

  /* clear auth data */
  memset (MNOTIFY_DATA (h), 0, auth_data_len);

  /* get hash of the message */
  unsigned char *code = HMAC (get_encrypt_fcn (key_id), key, vec_len (key),
			      (unsigned char *) h, msg_len, NULL, NULL);

  result = memcmp (code, auth_data, auth_data_len);

  vec_free (auth_data);

  return !result;
}

static void
process_map_notify (map_records_arg_t * a)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  uword *pmr_index;

  pmr_index = hash_get (lcm->map_register_messages_by_nonce, a->nonce);
  if (!pmr_index)
    {
      clib_warning ("No pending map-register entry with nonce %lu!",
		    a->nonce);
      return;
    }

  a->is_free = 1;
  pool_put_index (lcm->pending_map_registers_pool, pmr_index[0]);
  hash_unset (lcm->map_register_messages_by_nonce, a->nonce);

  /* reset map-notify counter */
  lcm->expired_map_registers = 0;
}

static mapping_t *
get_mapping (lisp_cp_main_t * lcm, gid_address_t * e)
{
  u32 mi;

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, e);
  if (~0 == mi)
    {
      clib_warning ("eid %U not found in map-cache!", unformat_gid_address,
		    e);
      return 0;
    }
  return pool_elt_at_index (lcm->mapping_pool, mi);
}

/**
 * When map-notify is received it is necessary that all EIDs in the record
 * list share common key. The key is then used to verify authentication
 * data in map-notify message.
 */
static int
map_record_integrity_check (lisp_cp_main_t * lcm, mapping_t * maps,
			    u32 key_id, u8 ** key_out)
{
  u32 i, len = vec_len (maps);
  mapping_t *m;

  /* get key of the first mapping */
  m = get_mapping (lcm, &maps[0].eid);
  if (!m || !m->key)
    return -1;

  key_out[0] = m->key;

  for (i = 1; i < len; i++)
    {
      m = get_mapping (lcm, &maps[i].eid);
      if (!m || !m->key)
	return -1;

      if (key_id != m->key_id || vec_cmp (m->key, key_out[0]))
	{
	  clib_warning ("keys does not match! %v, %v", key_out[0], m->key);
	  return -1;
	}
    }
  return 0;
}

static int
parse_map_records (vlib_buffer_t * b, map_records_arg_t * a, u8 count)
{
  locator_t *locators = 0;
  u32 i, len;
  gid_address_t deid;
  mapping_t m;
  locator_t *loc;

  memset (&m, 0, sizeof (m));

  /* parse record eid */
  for (i = 0; i < count; i++)
    {
      locators = 0;
      len = lisp_msg_parse_mapping_record (b, &deid, &locators, NULL);
      if (len == ~0)
	{
	  clib_warning ("Failed to parse mapping record!");
	  vec_foreach (loc, locators) locator_free (loc);
	  vec_free (locators);
	  return -1;
	}

      m.locators = locators;
      gid_address_copy (&m.eid, &deid);
      vec_add1 (a->mappings, m);
    }

  return 0;
}

static map_records_arg_t *
map_record_args_get ()
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  map_records_arg_t *rec;

  /* Cleanup first */
  /* *INDENT-OFF* */
  pool_foreach (rec, lcm->map_records_args_pool[vlib_get_thread_index()], ({
    if (rec->is_free)
      map_records_arg_free (rec);
  }));
  /* *INDENT-ON* */

  pool_get (lcm->map_records_args_pool[vlib_get_thread_index ()], rec);
  return rec;
}

static map_records_arg_t *
parse_map_notify (vlib_buffer_t * b)
{
  int rc = 0;
  map_notify_hdr_t *mnotif_hdr;
  lisp_key_type_t key_id;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u8 *key = 0;
  gid_address_t deid;
  u16 auth_data_len = 0;
  u8 record_count;
  map_records_arg_t *a;

  a = map_record_args_get ();
  memset (a, 0, sizeof (*a));
  mnotif_hdr = vlib_buffer_get_current (b);
  vlib_buffer_pull (b, sizeof (*mnotif_hdr));
  memset (&deid, 0, sizeof (deid));

  a->nonce = MNOTIFY_NONCE (mnotif_hdr);
  key_id = clib_net_to_host_u16 (MNOTIFY_KEY_ID (mnotif_hdr));
  auth_data_len = auth_data_len_by_key_id (key_id);

  /* advance buffer by authentication data */
  vlib_buffer_pull (b, auth_data_len);

  record_count = MNOTIFY_REC_COUNT (mnotif_hdr);
  rc = parse_map_records (b, a, record_count);
  if (rc != 0)
    {
      map_records_arg_free (a);
      return 0;
    }

  rc = map_record_integrity_check (lcm, a->mappings, key_id, &key);
  if (rc != 0)
    {
      map_records_arg_free (a);
      return 0;
    }

  /* verify authentication data */
  if (!is_auth_data_valid (mnotif_hdr, vlib_buffer_get_tail (b)
			   - (u8 *) mnotif_hdr, key_id, key))
    {
      clib_warning ("Map-notify auth data verification failed for nonce "
		    "0x%lx!", a->nonce);
      map_records_arg_free (a);
      return 0;
    }
  return a;
}

static vlib_buffer_t *
build_map_reply (lisp_cp_main_t * lcm, ip_address_t * sloc,
		 ip_address_t * dst, u64 nonce, u8 probe_bit,
		 mapping_t * records, u16 dst_port, u32 * bi_res)
{
  vlib_buffer_t *b;
  u32 bi;
  vlib_main_t *vm = lcm->vlib_main;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer for Map-Register!");
      return 0;
    }

  b = vlib_get_buffer (vm, bi);

  /* leave some space for the encap headers */
  vlib_buffer_make_headroom (b, MAX_LISP_MSG_ENCAP_LEN);

  lisp_msg_put_map_reply (b, records, nonce, probe_bit);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, dst_port, sloc, dst, 1);

  bi_res[0] = bi;
  return b;
}

static int
send_map_reply (lisp_cp_main_t * lcm, u32 mi, ip_address_t * dst,
		u8 probe_bit, u64 nonce, u16 dst_port,
		ip_address_t * probed_loc)
{
  ip_address_t src;
  u32 bi;
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u32 next_index, *to_next;
  mapping_t *records = 0, *m;

  m = pool_elt_at_index (lcm->mapping_pool, mi);
  if (!m)
    return -1;

  vec_add1 (records, m[0]);
  add_locators (lcm, &records[0], m->locator_set_index, probed_loc);
  memset (&src, 0, sizeof (src));

  if (!ip_fib_get_first_egress_ip_for_dst (lcm, dst, &src))
    {
      clib_warning ("can't find interface address for %U", format_ip_address,
		    dst);
      return -1;
    }

  b = build_map_reply (lcm, &src, dst, nonce, probe_bit, records, dst_port,
		       &bi);
  if (!b)
    return -1;
  free_map_register_records (records);

  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;
  next_index = (ip_addr_version (&lcm->active_map_resolver) == IP4) ?
    ip4_lookup_node.index : ip6_lookup_node.index;

  f = vlib_get_frame_to_node (lcm->vlib_main, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (lcm->vlib_main, next_index, f);
  return 0;
}

static void
find_ip_header (vlib_buffer_t * b, u8 ** ip_hdr)
{
  const i32 start = vnet_buffer (b)->l3_hdr_offset;
  if (start < 0 && start < -sizeof (b->pre_data))
    {
      *ip_hdr = 0;
      return;
    }

  *ip_hdr = b->data + start;
  if ((u8 *) * ip_hdr > (u8 *) vlib_buffer_get_current (b))
    *ip_hdr = 0;
}

void
process_map_request (vlib_main_t * vm, vlib_node_runtime_t * node,
		     lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  u8 *ip_hdr = 0;
  ip_address_t *dst_loc = 0, probed_loc, src_loc;
  mapping_t m;
  map_request_hdr_t *mreq_hdr;
  gid_address_t src, dst;
  u64 nonce;
  u32 i, len = 0, rloc_probe_recv = 0;
  gid_address_t *itr_rlocs = 0;

  mreq_hdr = vlib_buffer_get_current (b);
  if (!MREQ_SMR (mreq_hdr) && !MREQ_RLOC_PROBE (mreq_hdr))
    {
      clib_warning
	("Only SMR Map-Requests and RLOC probe supported for now!");
      return;
    }

  vlib_buffer_pull (b, sizeof (*mreq_hdr));
  nonce = MREQ_NONCE (mreq_hdr);

  /* parse src eid */
  len = lisp_msg_parse_addr (b, &src);
  if (len == ~0)
    return;

  len = lisp_msg_parse_itr_rlocs (b, &itr_rlocs,
				  MREQ_ITR_RLOC_COUNT (mreq_hdr) + 1);
  if (len == ~0)
    goto done;

  /* parse eid records and send SMR-invoked map-requests */
  for (i = 0; i < MREQ_REC_COUNT (mreq_hdr); i++)
    {
      memset (&dst, 0, sizeof (dst));
      len = lisp_msg_parse_eid_rec (b, &dst);
      if (len == ~0)
	{
	  clib_warning ("Can't parse map-request EID-record");
	  goto done;
	}

      if (MREQ_SMR (mreq_hdr))
	{
	  /* send SMR-invoked map-requests */
	  queue_map_request (&dst, &src, 1 /* invoked */ , 0 /* resend */ );
	}
      else if (MREQ_RLOC_PROBE (mreq_hdr))
	{
	  find_ip_header (b, &ip_hdr);
	  if (!ip_hdr)
	    {
	      clib_warning ("Cannot find the IP header!");
	      goto done;
	    }
	  rloc_probe_recv++;
	  memset (&m, 0, sizeof (m));
	  u32 mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &dst);

	  // TODO: select best locator; for now use the first one
	  dst_loc = &gid_address_ip (&itr_rlocs[0]);

	  /* get src/dst IP addresses */
	  get_src_and_dst_ip (ip_hdr, &src_loc, &probed_loc);

	  // TODO get source port from buffer
	  u16 src_port = LISP_CONTROL_PORT;

	  send_map_reply (lcm, mi, dst_loc, 1 /* probe-bit */ , nonce,
			  src_port, &probed_loc);
	}
    }

done:
  vlib_node_increment_counter (vm, node->node_index,
			       LISP_CP_INPUT_ERROR_RLOC_PROBE_REQ_RECEIVED,
			       rloc_probe_recv);
  vec_free (itr_rlocs);
}

map_records_arg_t *
parse_map_reply (vlib_buffer_t * b)
{
  locator_t probed;
  gid_address_t deid;
  void *h;
  u32 i, len = 0;
  mapping_t m;
  map_reply_hdr_t *mrep_hdr;
  map_records_arg_t *a;

  a = map_record_args_get ();
  memset (a, 0, sizeof (*a));

  locator_t *locators;

  mrep_hdr = vlib_buffer_get_current (b);
  a->nonce = MREP_NONCE (mrep_hdr);
  a->is_rloc_probe = MREP_RLOC_PROBE (mrep_hdr);
  if (!vlib_buffer_has_space (b, sizeof (*mrep_hdr)))
    {
      clib_mem_free (a);
      return 0;
    }
  vlib_buffer_pull (b, sizeof (*mrep_hdr));

  for (i = 0; i < MREP_REC_COUNT (mrep_hdr); i++)
    {
      memset (&m, 0, sizeof (m));
      locators = 0;
      h = vlib_buffer_get_current (b);

      m.ttl = clib_net_to_host_u32 (MAP_REC_TTL (h));
      m.action = MAP_REC_ACTION (h);
      m.authoritative = MAP_REC_AUTH (h);

      len = lisp_msg_parse_mapping_record (b, &deid, &locators, &probed);
      if (len == ~0)
	{
	  clib_warning ("Failed to parse mapping record!");
	  map_records_arg_free (a);
	  return 0;
	}

      m.locators = locators;
      gid_address_copy (&m.eid, &deid);
      vec_add1 (a->mappings, m);
    }
  return a;
}

static void
queue_map_reply_for_processing (map_records_arg_t * a)
{
  vl_api_rpc_call_main_thread (process_map_reply, (u8 *) a, sizeof (*a));
}

static void
queue_map_notify_for_processing (map_records_arg_t * a)
{
  vl_api_rpc_call_main_thread (process_map_notify, (u8 *) a, sizeof (a[0]));
}

static uword
lisp_cp_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next_drop, rloc_probe_rep_recv = 0,
    map_notifies_recv = 0;
  lisp_msg_type_e type;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  map_records_arg_t *a;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;


  while (n_left_from > 0)
    {
      u32 n_left_to_next_drop;

      vlib_get_next_frame (vm, node, LISP_CP_INPUT_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);
      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = bi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  type = lisp_msg_type (vlib_buffer_get_current (b0));
	  switch (type)
	    {
	    case LISP_MAP_REPLY:
	      a = parse_map_reply (b0);
	      if (a)
		{
		  if (a->is_rloc_probe)
		    rloc_probe_rep_recv++;
		  queue_map_reply_for_processing (a);
		}
	      break;
	    case LISP_MAP_REQUEST:
	      process_map_request (vm, node, lcm, b0);
	      break;
	    case LISP_MAP_NOTIFY:
	      a = parse_map_notify (b0);
	      if (a)
		{
		  map_notifies_recv++;
		  queue_map_notify_for_processing (a);
		}
	      break;
	    default:
	      clib_warning ("Unsupported LISP message type %d", type);
	      break;
	    }

	  b0->error = node->errors[LISP_CP_INPUT_ERROR_DROP];

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {

	    }
	}

      vlib_put_next_frame (vm, node, LISP_CP_INPUT_NEXT_DROP,
			   n_left_to_next_drop);
    }
  vlib_node_increment_counter (vm, node->node_index,
			       LISP_CP_INPUT_ERROR_RLOC_PROBE_REP_RECEIVED,
			       rloc_probe_rep_recv);
  vlib_node_increment_counter (vm, node->node_index,
			       LISP_CP_INPUT_ERROR_MAP_NOTIFIES_RECEIVED,
			       map_notifies_recv);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_cp_input_node) = {
  .function = lisp_cp_input,
  .name = "lisp-cp-input",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_INPUT_N_ERROR,
  .error_strings = lisp_cp_input_error_strings,

  .n_next_nodes = LISP_CP_INPUT_N_NEXT,

  .next_nodes = {
      [LISP_CP_INPUT_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

clib_error_t *
lisp_cp_init (vlib_main_t * vm)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  clib_error_t *error = 0;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  if ((error = vlib_call_init_function (vm, lisp_gpe_init)))
    return error;

  lcm->im4 = &ip4_main;
  lcm->im6 = &ip6_main;
  lcm->vlib_main = vm;
  lcm->vnet_main = vnet_get_main ();
  lcm->mreq_itr_rlocs = ~0;
  lcm->flags = 0;
  lcm->pitr_map_index = ~0;
  lcm->petr_map_index = ~0;
  memset (&lcm->active_map_resolver, 0, sizeof (lcm->active_map_resolver));
  memset (&lcm->active_map_server, 0, sizeof (lcm->active_map_server));

  gid_dictionary_init (&lcm->mapping_index_by_gid);
  lcm->do_map_resolver_election = 1;
  lcm->do_map_server_election = 1;
  lcm->map_request_mode = MR_MODE_DST_ONLY;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (lcm->map_records_args_pool, num_threads - 1);

  /* default vrf mapped to vni 0 */
  hash_set (lcm->table_id_by_vni, 0, 0);
  hash_set (lcm->vni_by_table_id, 0, 0);

  lisp_cp_register_dst_port (vm);

  u64 now = clib_cpu_time_now ();
  timing_wheel_init (&lcm->wheel, now, vm->clib_time.clocks_per_second);
  lcm->nsh_map_index = ~0;
  lcm->map_register_ttl = MAP_REGISTER_DEFAULT_TTL;
  lcm->max_expired_map_registers = MAX_EXPIRED_MAP_REGISTERS_DEFAULT;
  lcm->expired_map_registers = 0;
  lcm->transport_protocol = LISP_TRANSPORT_PROTOCOL_UDP;
  lcm->flags |= LISP_FLAG_XTR_MODE;
  return 0;
}

static int
lisp_stats_api_fill (lisp_cp_main_t * lcm, lisp_gpe_main_t * lgm,
		     lisp_api_stats_t * stat, lisp_stats_key_t * key,
		     u32 stats_index)
{
  vlib_counter_t v;
  vlib_combined_counter_main_t *cm = &lgm->counters;
  lisp_gpe_fwd_entry_key_t fwd_key;
  const lisp_gpe_tunnel_t *lgt;
  fwd_entry_t *fe;

  memset (stat, 0, sizeof (*stat));
  memset (&fwd_key, 0, sizeof (fwd_key));

  fe = pool_elt_at_index (lcm->fwd_entry_pool, key->fwd_entry_index);
  ASSERT (fe != 0);

  gid_to_dp_address (&fe->reid, &stat->deid);
  gid_to_dp_address (&fe->leid, &stat->seid);
  stat->vni = gid_address_vni (&fe->reid);

  lgt = lisp_gpe_tunnel_get (key->tunnel_index);
  stat->loc_rloc = lgt->key->lcl;
  stat->rmt_rloc = lgt->key->rmt;

  vlib_get_combined_counter (cm, stats_index, &v);
  stat->counters = v;
  return 1;
}

lisp_api_stats_t *
vnet_lisp_get_stats (void)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_api_stats_t *stats = 0, stat;
  lisp_stats_key_t *key;
  u32 index;

  /* *INDENT-OFF* */
  hash_foreach_mem (key, index, lgm->lisp_stats_index_by_key,
  {
    if (lisp_stats_api_fill (lcm, lgm, &stat, key, index))
      vec_add1 (stats, stat);
  });
  /* *INDENT-ON* */

  return stats;
}

static void *
send_map_request_thread_fn (void *arg)
{
  map_request_args_t *a = arg;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (a->is_resend)
    resend_encapsulated_map_request (lcm, &a->seid, &a->deid, a->smr_invoked);
  else
    send_encapsulated_map_request (lcm, &a->seid, &a->deid, a->smr_invoked);

  return 0;
}

static int
queue_map_request (gid_address_t * seid, gid_address_t * deid,
		   u8 smr_invoked, u8 is_resend)
{
  map_request_args_t a;

  a.is_resend = is_resend;
  gid_address_copy (&a.seid, seid);
  gid_address_copy (&a.deid, deid);
  a.smr_invoked = smr_invoked;

  vl_api_rpc_call_main_thread (send_map_request_thread_fn,
			       (u8 *) & a, sizeof (a));
  return 0;
}

/**
 * Take an action with a pending map request depending on expiration time
 * and re-try counters.
 */
static void
update_pending_request (pending_map_request_t * r, f64 dt)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *mr;

  if (r->time_to_expire - dt < 0)
    /* it's time to decide what to do with this pending request */
    {
      if (r->retries_num >= NUMBER_OF_RETRIES)
	/* too many retries -> assume current map resolver is not available */
	{
	  mr = get_map_resolver (&lcm->active_map_resolver);
	  if (!mr)
	    {
	      clib_warning ("Map resolver %U not found - probably deleted "
			    "by the user recently.", format_ip_address,
			    &lcm->active_map_resolver);
	    }
	  else
	    {
	      clib_warning ("map resolver %U is unreachable, ignoring",
			    format_ip_address, &lcm->active_map_resolver);

	      /* mark current map resolver unavailable so it won't be
	       * selected next time */
	      mr->is_down = 1;
	      mr->last_update = vlib_time_now (lcm->vlib_main);
	    }

	  reset_pending_mr_counters (r);
	  elect_map_resolver (lcm);

	  /* try to find a next eligible map resolver and re-send */
	  queue_map_request (&r->src, &r->dst, r->is_smr_invoked,
			     1 /* resend */ );
	}
      else
	{
	  /* try again */
	  queue_map_request (&r->src, &r->dst, r->is_smr_invoked,
			     1 /* resend */ );
	  r->retries_num++;
	  r->time_to_expire = PENDING_MREQ_EXPIRATION_TIME;
	}
    }
  else
    r->time_to_expire -= dt;
}

static void
remove_dead_pending_map_requests (lisp_cp_main_t * lcm)
{
  u64 *nonce;
  pending_map_request_t *pmr;
  u32 *to_be_removed = 0, *pmr_index;

  /* *INDENT-OFF* */
  pool_foreach (pmr, lcm->pending_map_requests_pool,
  ({
    if (pmr->to_be_removed)
      {
        clib_fifo_foreach (nonce, pmr->nonces, ({
          hash_unset (lcm->pending_map_requests_by_nonce, nonce[0]);
        }));

        vec_add1 (to_be_removed, pmr - lcm->pending_map_requests_pool);
      }
  }));
  /* *INDENT-ON* */

  vec_foreach (pmr_index, to_be_removed)
    pool_put_index (lcm->pending_map_requests_pool, pmr_index[0]);

  vec_free (to_be_removed);
}

static void
update_rloc_probing (lisp_cp_main_t * lcm, f64 dt)
{
  static f64 time_left = RLOC_PROBING_INTERVAL;

  if (!lcm->is_enabled || !lcm->rloc_probing)
    return;

  time_left -= dt;
  if (time_left <= 0)
    {
      time_left = RLOC_PROBING_INTERVAL;
      send_rloc_probes (lcm);
    }
}

static int
update_pending_map_register (pending_map_register_t * r, f64 dt, u8 * del_all)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  lisp_msmr_t *ms;
  del_all[0] = 0;

  r->time_to_expire -= dt;

  if (r->time_to_expire < 0)
    {
      lcm->expired_map_registers++;

      if (lcm->expired_map_registers >= lcm->max_expired_map_registers)
	{
	  ms = get_map_server (&lcm->active_map_server);
	  if (!ms)
	    {
	      clib_warning ("Map server %U not found - probably deleted "
			    "by the user recently.", format_ip_address,
			    &lcm->active_map_server);
	    }
	  else
	    {
	      clib_warning ("map server %U is unreachable, ignoring",
			    format_ip_address, &lcm->active_map_server);

	      /* mark current map server unavailable so it won't be
	       * elected next time */
	      ms->is_down = 1;
	      ms->last_update = vlib_time_now (lcm->vlib_main);
	    }

	  elect_map_server (lcm);

	  /* indication for deleting all pending map registers */
	  del_all[0] = 1;
	  lcm->expired_map_registers = 0;
	  return 0;
	}
      else
	{
	  /* delete pending map register */
	  return 0;
	}
    }
  return 1;
}

static void
update_map_register (lisp_cp_main_t * lcm, f64 dt)
{
  u32 *to_be_removed = 0, *pmr_index;
  static f64 time_left = QUICK_MAP_REGISTER_INTERVAL;
  static u64 mreg_sent_counter = 0;

  pending_map_register_t *pmr;
  u8 del_all = 0;

  if (!lcm->is_enabled || !lcm->map_registering)
    return;

  /* *INDENT-OFF* */
  pool_foreach (pmr, lcm->pending_map_registers_pool,
  ({
    if (!update_pending_map_register (pmr, dt, &del_all))
    {
      if (del_all)
        break;
      vec_add1 (to_be_removed, pmr - lcm->pending_map_registers_pool);
    }
  }));
  /* *INDENT-ON* */

  if (del_all)
    {
      /* delete all pending map register messages so they won't
       * trigger another map server election.. */
      pool_free (lcm->pending_map_registers_pool);
      hash_free (lcm->map_register_messages_by_nonce);

      /* ..and trigger registration against next map server (if any) */
      time_left = 0;
    }
  else
    {
      vec_foreach (pmr_index, to_be_removed)
	pool_put_index (lcm->pending_map_registers_pool, pmr_index[0]);
    }

  vec_free (to_be_removed);

  time_left -= dt;
  if (time_left <= 0)
    {
      if (mreg_sent_counter >= QUICK_MAP_REGISTER_MSG_COUNT)
	time_left = MAP_REGISTER_INTERVAL;
      else
	{
	  mreg_sent_counter++;
	  time_left = QUICK_MAP_REGISTER_INTERVAL;
	}
      send_map_register (lcm, 1 /* want map notify */ );
    }
}

static uword
send_map_resolver_service (vlib_main_t * vm,
			   vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  u32 *expired = 0;
  f64 period = 2.0;
  pending_map_request_t *pmr;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, period);

      /* currently no signals are expected - just wait for clock */
      (void) vlib_process_get_events (vm, 0);

      /* *INDENT-OFF* */
      pool_foreach (pmr, lcm->pending_map_requests_pool,
      ({
        if (!pmr->to_be_removed)
          update_pending_request (pmr, period);
      }));
      /* *INDENT-ON* */

      remove_dead_pending_map_requests (lcm);

      update_map_register (lcm, period);
      update_rloc_probing (lcm, period);

      u64 now = clib_cpu_time_now ();

      expired = timing_wheel_advance (&lcm->wheel, now, expired, 0);
      if (vec_len (expired) > 0)
	{
	  u32 *mi = 0;
	  vec_foreach (mi, expired)
	  {
	    process_expired_mapping (lcm, mi[0]);
	  }
	  _vec_len (expired) = 0;
	}
    }

  /* unreachable */
  return 0;
}

vnet_api_error_t
vnet_lisp_stats_enable_disable (u8 enable)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (vnet_lisp_enable_disable_status () == 0)
    return VNET_API_ERROR_LISP_DISABLED;

  if (enable)
    lcm->flags |= LISP_FLAG_STATS_ENABLED;
  else
    lcm->flags &= ~LISP_FLAG_STATS_ENABLED;

  return 0;
}

u8
vnet_lisp_stats_enable_disable_state (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (vnet_lisp_enable_disable_status () == 0)
    return VNET_API_ERROR_LISP_DISABLED;

  return lcm->flags & LISP_FLAG_STATS_ENABLED;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_retry_service_node,static) = {
    .function = send_map_resolver_service,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "lisp-retry-service",
    .process_log2_n_stack_bytes = 16,
};
/* *INDENT-ON* */

u32
vnet_lisp_set_transport_protocol (u8 protocol)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (protocol < LISP_TRANSPORT_PROTOCOL_UDP ||
      protocol > LISP_TRANSPORT_PROTOCOL_API)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  lcm->transport_protocol = protocol;
  return 0;
}

lisp_transport_protocol_t
vnet_lisp_get_transport_protocol (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return lcm->transport_protocol;
}

int
vnet_lisp_enable_disable_xtr_mode (u8 is_enabled)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u8 pitr_mode = lcm->flags & LISP_FLAG_PITR_MODE;
  u8 xtr_mode = lcm->flags & LISP_FLAG_XTR_MODE;
  u8 petr_mode = lcm->flags & LISP_FLAG_PETR_MODE;

  if (pitr_mode && is_enabled)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  if (is_enabled && xtr_mode)
    return 0;
  if (!is_enabled && !xtr_mode)
    return 0;

  if (is_enabled)
    {
      if (!petr_mode)
	{
	  lisp_cp_register_dst_port (lcm->vlib_main);
	}
      lisp_cp_enable_l2_l3_ifaces (lcm, 1 /* with_default_route */ );
      lcm->flags |= LISP_FLAG_XTR_MODE;
    }
  else
    {
      if (!petr_mode)
	{
	  lisp_cp_unregister_dst_port (lcm->vlib_main);
	}
      lisp_cp_disable_l2_l3_ifaces (lcm);
      lcm->flags &= ~LISP_FLAG_XTR_MODE;
    }
  return 0;
}

int
vnet_lisp_enable_disable_pitr_mode (u8 is_enabled)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u8 xtr_mode = lcm->flags & LISP_FLAG_XTR_MODE;
  u8 pitr_mode = lcm->flags & LISP_FLAG_PITR_MODE;

  if (xtr_mode && is_enabled)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_enabled && pitr_mode)
    return 0;
  if (!is_enabled && !pitr_mode)
    return 0;

  if (is_enabled)
    {
      /* create iface, no default route */
      lisp_cp_enable_l2_l3_ifaces (lcm, 0 /* with_default_route */ );
      lcm->flags |= LISP_FLAG_PITR_MODE;
    }
  else
    {
      lisp_cp_disable_l2_l3_ifaces (lcm);
      lcm->flags &= ~LISP_FLAG_PITR_MODE;
    }
  return 0;
}

int
vnet_lisp_enable_disable_petr_mode (u8 is_enabled)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  u8 xtr_mode = lcm->flags & LISP_FLAG_XTR_MODE;
  u8 petr_mode = lcm->flags & LISP_FLAG_PETR_MODE;

  if (is_enabled && petr_mode)
    return 0;
  if (!is_enabled && !petr_mode)
    return 0;

  if (is_enabled)
    {
      if (!xtr_mode)
	{
	  lisp_cp_register_dst_port (lcm->vlib_main);
	}
      lcm->flags |= LISP_FLAG_PETR_MODE;
    }
  else
    {
      if (!xtr_mode)
	{
	  lisp_cp_unregister_dst_port (lcm->vlib_main);
	}
      lcm->flags &= ~LISP_FLAG_PETR_MODE;
    }
  return 0;
}

u8
vnet_lisp_get_xtr_mode (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return (lcm->flags & LISP_FLAG_XTR_MODE);
}

u8
vnet_lisp_get_pitr_mode (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return (lcm->flags & LISP_FLAG_PITR_MODE);
}

u8
vnet_lisp_get_petr_mode (void)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  return (lcm->flags & LISP_FLAG_PETR_MODE);
}

VLIB_INIT_FUNCTION (lisp_cp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
