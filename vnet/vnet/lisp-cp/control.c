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

#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-cp/packets.h>
#include <vnet/lisp-cp/lisp_msg_serdes.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

ip_interface_address_t *
ip_interface_get_first_interface_address (ip_lookup_main_t *lm, u32 sw_if_index,
                                          u8 loop)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t * swif = vnet_get_sw_interface (vnm, sw_if_index);
  if (loop && swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
    sw_if_index = swif->unnumbered_sw_if_index;
  u32 ia =
      (vec_len((lm)->if_address_pool_index_by_sw_if_index) > (sw_if_index)) ?
          vec_elt((lm)->if_address_pool_index_by_sw_if_index, (sw_if_index)) :
          (u32) ~0;
  return pool_elt_at_index((lm)->if_address_pool, ia);
}

void *
ip_interface_get_first_address (ip_lookup_main_t * lm, u32 sw_if_index,
                                u8 version)
{
  ip_interface_address_t * ia;

  ia = ip_interface_get_first_interface_address (lm, sw_if_index, 1);
  if (!ia)
    return 0;
  return ip_interface_address_get_address (lm, ia);
}

int
ip_interface_get_first_ip_address (lisp_cp_main_t * lcm, u32 sw_if_index,
                                   u8 version, ip_address_t * result)
{
  ip_lookup_main_t * lm;
  void * addr;

  lm = (version == IP4) ? &lcm->im4->lookup_main : &lcm->im6->lookup_main;
  addr = ip_interface_get_first_address (lm, sw_if_index, version);
  if (!addr)
    return 0;

  ip_address_set (result, addr, version);
  return 1;
}

static u32
ip_fib_lookup_with_table (lisp_cp_main_t * lcm, u32 fib_index,
                          ip_address_t * dst)
{
  if (ip_addr_version (dst) == IP4)
      return ip4_fib_lookup_with_table (lcm->im4, fib_index, &ip_addr_v4(dst),
                                        0);
  else
      return ip6_fib_lookup_with_table (lcm->im6, fib_index, &ip_addr_v6(dst));
}

u32
ip_fib_get_egress_iface_for_dst_with_lm (lisp_cp_main_t * lcm,
                                         ip_address_t * dst,
                                         ip_lookup_main_t * lm)
{
  u32 adj_index;
  ip_adjacency_t * adj;

  adj_index = ip_fib_lookup_with_table (lcm, 0, dst);
  adj = ip_get_adjacency (lm, adj_index);

  if (adj == 0)
    return ~0;

  /* we only want outgoing routes */
  if (adj->lookup_next_index != IP_LOOKUP_NEXT_ARP
      && adj->lookup_next_index != IP_LOOKUP_NEXT_REWRITE)
    return ~0;

  return adj->rewrite_header.sw_if_index;
}

/**
 * Find the sw_if_index of the interface that would be used to egress towards
 * dst.
 */
u32
ip_fib_get_egress_iface_for_dst (lisp_cp_main_t * lcm, ip_address_t * dst)
{
  ip_lookup_main_t * lm;

  lm = ip_addr_version (dst) == IP4 ?
      &lcm->im4->lookup_main : &lcm->im6->lookup_main;

  return ip_fib_get_egress_iface_for_dst_with_lm (lcm, dst, lm);
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
  ip_lookup_main_t * lm;
  void * addr = 0;
  u8 ipver;

  ASSERT(result != 0);

  ipver = ip_addr_version(dst);

  lm = (ipver == IP4) ? &lcm->im4->lookup_main : &lcm->im6->lookup_main;
  si = ip_fib_get_egress_iface_for_dst_with_lm (lcm, dst, lm);

  if ((u32) ~0 == si)
    return 0;

  /* find the first ip address */
  addr = ip_interface_get_first_address (lm, si, ipver);
  if (0 == addr)
    return 0;

  ip_address_set (result, addr, ipver);
  return 1;
}

static int
dp_add_del_iface (lisp_cp_main_t * lcm, u32 vni, u8 is_add)
{
  uword * table_id, * intf;
  vnet_lisp_gpe_add_del_iface_args_t _ai, *ai = &_ai;

  table_id = hash_get(lcm->table_id_by_vni, vni);

  if (!table_id)
    {
      clib_warning ("vni %d not associated to a vrf!", vni);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  intf = hash_get(lcm->dp_intf_by_vni, vni);

  /* enable/disable data-plane interface */
  if (is_add)
    {
      /* create interface or update refcount */
      if (!intf)
        {
          ai->is_add = 1;
          ai->vni = vni;
          ai->table_id = table_id[0];
          vnet_lisp_gpe_add_del_iface (ai, 0);

          /* counts the number of eids in a vni that use the interface */
          hash_set(lcm->dp_intf_by_vni, vni, 1);
        }
    }
  else
    {
      if (intf == 0)
        {
          clib_warning("interface for vni %d doesn't exist!", vni);
          return VNET_API_ERROR_INVALID_VALUE;
        }

      ai->is_add = 0;
      ai->vni = vni;
      ai->table_id = table_id[0];
      vnet_lisp_gpe_add_del_iface (ai, 0);
      hash_unset(lcm->dp_intf_by_vni, vni);
    }

  return 0;
}

static void
dp_del_fwd_entry (lisp_cp_main_t * lcm, u32 src_map_index, u32 dst_map_index)
{
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, * a = &_a;
  fwd_entry_t * fe = 0;
  uword * feip = 0;
  memset(a, 0, sizeof(*a));

  feip = hash_get(lcm->fwd_entry_by_mapping_index, dst_map_index);
  if (!feip)
    return;

  fe = pool_elt_at_index(lcm->fwd_entry_pool, feip[0]);

  /* delete dp fwd entry */
  u32 sw_if_index;
  a->is_add = 0;
  a->dlocator = fe->dst_loc;
  a->slocator = fe->src_loc;
  a->vni = gid_address_vni(&a->deid);
  gid_address_copy(&a->deid, &fe->deid);

  vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);

  /* delete entry in fwd table */
  hash_unset(lcm->fwd_entry_by_mapping_index, dst_map_index);
  pool_put(lcm->fwd_entry_pool, fe);
}

/**
 * Finds first remote locator with best (lowest) priority that has a local
 * peer locator with an underlying route to it.
 *
 */
static u32
get_locator_pair (lisp_cp_main_t* lcm, mapping_t * lcl_map, mapping_t * rmt_map,
                  ip_address_t * lcl_loc, ip_address_t * rmt_loc)
{
  u32 i, minp = ~0, limitp = 0, li, check_index = 0, done = 0, esi;
  locator_set_t * rmt_ls, * lcl_ls;
  ip_address_t _lcl, * lcl = &_lcl;
  locator_t * l, * rmt = 0;
  uword * checked = 0;

  rmt_ls = pool_elt_at_index(lcm->locator_set_pool, rmt_map->locator_set_index);
  lcl_ls = pool_elt_at_index(lcm->locator_set_pool, lcl_map->locator_set_index);

  if (!rmt_ls || vec_len(rmt_ls->locator_indices) == 0)
    return 0;

  while (!done)
    {
      rmt = 0;

      /* find unvisited remote locator with best priority */
      for (i = 0; i < vec_len(rmt_ls->locator_indices); i++)
        {
          if (0 != hash_get(checked, i))
            continue;

          li = vec_elt(rmt_ls->locator_indices, i);
          l = pool_elt_at_index(lcm->locator_pool, li);

          /* we don't support non-IP locators for now */
          if (gid_address_type(&l->address) != GID_ADDR_IP_PREFIX)
            continue;

          if (l->priority < minp && l->priority >= limitp)
            {
              minp = l->priority;
              rmt = l;
              check_index = i;
            }
        }
      /* check if a local locator with a route to remote locator exists */
      if (rmt != 0)
        {
          esi = ip_fib_get_egress_iface_for_dst (
              lcm, &gid_address_ip(&rmt->address));
          if ((u32) ~0 == esi)
            continue;

          for (i = 0; i < vec_len(lcl_ls->locator_indices); i++)
            {
              li = vec_elt (lcl_ls->locator_indices, i);
              locator_t * sl = pool_elt_at_index (lcm->locator_pool, li);

              /* found local locator */
              if (sl->sw_if_index == esi)
                {
                  if (0 == ip_interface_get_first_ip_address (lcm,
                             sl->sw_if_index,
                             gid_address_ip_version(&rmt->address), lcl))
                    continue;

                  ip_address_copy(rmt_loc, &gid_address_ip(&rmt->address));
                  ip_address_copy(lcl_loc, lcl);
                  done = 2;
                }
            }

          /* skip this remote locator in next searches */
          limitp = minp;
          hash_set(checked, check_index, 1);
        }
      else
        done = 1;
    }
  hash_free(checked);
  return (done == 2) ? 1 : 0;
}

static void
dp_add_fwd_entry (lisp_cp_main_t* lcm, u32 src_map_index, u32 dst_map_index)
{
  mapping_t * src_map, * dst_map;
  u32 sw_if_index;
  uword * feip = 0, * tidp;
  fwd_entry_t* fe;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, * a = &_a;

  memset (a, 0, sizeof(*a));

  /* remove entry if it already exists */
  feip = hash_get (lcm->fwd_entry_by_mapping_index, dst_map_index);
  if (feip)
    dp_del_fwd_entry (lcm, src_map_index, dst_map_index);

  src_map = pool_elt_at_index (lcm->mapping_pool, src_map_index);
  dst_map = pool_elt_at_index (lcm->mapping_pool, dst_map_index);

  gid_address_copy (&a->deid, &dst_map->eid);
  a->vni = gid_address_vni(&a->deid);

  tidp = hash_get(lcm->table_id_by_vni, a->vni);
  if (!tidp)
    {
      clib_warning("vni %d not associated to a vrf!", a->vni);
      return;
    }
  a->table_id = tidp[0];

  /* insert data plane forwarding entry */
  a->is_add = 1;

  /* find best locator pair that 1) verifies LISP policy 2) are connected */
  if (0 == get_locator_pair (lcm, src_map, dst_map, &a->slocator, &a->dlocator))
    {
      /* negative entry */
      a->is_negative = 1;
      a->action = dst_map->action;
    }

  /* TODO remove */
  u8 ipver = ip_prefix_version(&gid_address_ippref(&a->deid));
  a->decap_next_index = (ipver == IP4) ?
          LISP_GPE_INPUT_NEXT_IP4_INPUT : LISP_GPE_INPUT_NEXT_IP6_INPUT;

  vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);

  /* add tunnel to fwd entry table XXX check return value from DP insertion */
  pool_get (lcm->fwd_entry_pool, fe);
  fe->dst_loc = a->dlocator;
  fe->src_loc = a->slocator;
  gid_address_copy (&fe->deid, &a->deid);
  hash_set (lcm->fwd_entry_by_mapping_index, dst_map_index,
            fe - lcm->fwd_entry_pool);
}

/**
 * Add/remove mapping to/from map-cache. Overwriting not allowed.
 */
int
vnet_lisp_map_cache_add_del (vnet_lisp_add_del_mapping_args_t * a,
                             u32 * map_index_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  u32 mi, * map_indexp, map_index, i;
  mapping_t * m, * old_map;
  u32 ** eid_indexes;

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &a->eid);
  old_map = mi != ~0 ? pool_elt_at_index (lcm->mapping_pool, mi) : 0;
  if (a->is_add)
    {
      /* TODO check if overwriting and take appropriate actions */
      if (mi != GID_LOOKUP_MISS && !gid_address_cmp (&old_map->eid,
                                                     &a->eid))
        {
          clib_warning ("eid %U found in the eid-table", format_gid_address,
                       &a->eid);
          return VNET_API_ERROR_VALUE_EXIST;
        }

      pool_get(lcm->mapping_pool, m);
      gid_address_copy (&m->eid, &a->eid);
      m->locator_set_index = a->locator_set_index;
      m->ttl = a->ttl;
      m->action = a->action;
      m->local = a->local;

      map_index = m - lcm->mapping_pool;
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, &a->eid, map_index,
                              1);

      if (pool_is_free_index(lcm->locator_set_pool, a->locator_set_index))
        {
          clib_warning("Locator set with index %d doesn't exist",
                       a->locator_set_index);
          return VNET_API_ERROR_INVALID_VALUE;
        }

      /* add eid to list of eids supported by locator-set */
      vec_validate (lcm->locator_set_to_eids, a->locator_set_index);
      eid_indexes = vec_elt_at_index(lcm->locator_set_to_eids,
                                     a->locator_set_index);
      vec_add1(eid_indexes[0], map_index);

      if (a->local)
        {
          /* mark as local */
          vec_add1(lcm->local_mappings_indexes, map_index);
        }
      map_index_result[0] = map_index;
    }
  else
    {
      if (mi == GID_LOOKUP_MISS)
        {
          clib_warning("eid %U not found in the eid-table", format_gid_address,
                       &a->eid);
          return VNET_API_ERROR_INVALID_VALUE;
        }

      /* clear locator-set to eids binding */
      eid_indexes = vec_elt_at_index(lcm->locator_set_to_eids,
                                     a->locator_set_index);
      for (i = 0; i < vec_len(eid_indexes[0]); i++)
        {
          map_indexp = vec_elt_at_index(eid_indexes[0], i);
          if (map_indexp[0] == mi)
              break;
        }
      vec_del1(eid_indexes[0], i);

      /* remove local mark if needed */
      m = pool_elt_at_index(lcm->mapping_pool, mi);
      if (m->local)
        {
          u32 k, * lm_indexp;
          for (k = 0; k < vec_len(lcm->local_mappings_indexes); k++)
            {
              lm_indexp = vec_elt_at_index(lcm->local_mappings_indexes, k);
              if (lm_indexp[0] == mi)
                break;
            }
          vec_del1(lcm->local_mappings_indexes, k);
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
  uword * table_id;
  u32 vni;

  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  vni = gid_address_vni(&a->eid);
  table_id = hash_get(lcm->table_id_by_vni, vni);

  if (!table_id)
    {
      clib_warning ("vni %d not associated to a vrf!", vni);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* store/remove mapping from map-cache */
  return vnet_lisp_map_cache_add_del (a, map_index_result);
}

static clib_error_t *
lisp_add_del_local_eid_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  gid_address_t eid;
  ip_prefix_t * prefp = &gid_address_ippref(&eid);
  u8 * mac = gid_address_mac(&eid);
  gid_address_t * eids = 0;
  clib_error_t * error = 0;
  u8 * locator_set_name = 0;
  u32 locator_set_index = 0, map_index = 0;
  uword * p;
  vnet_lisp_add_del_mapping_args_t _a, * a = &_a;
  int rv = 0;
  u32 vni = 0;

  memset (&eid, 0, sizeof (eid));
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "vni %d", &vni))
        gid_address_vni (&eid) = vni;
      else if (unformat (line_input, "eid %U", unformat_ip_prefix, prefp))
        {
          gid_address_type (&eid) = GID_ADDR_IP_PREFIX;
          vec_add1(eids, eid);
        }
      else if (unformat (line_input, "eid %U", unformat_mac_address, mac))
        {
          gid_address_type (&eid) = GID_ADDR_MAC;
          vec_add1(eids, eid);
        }
      else if (unformat (line_input, "locator-set %_%v%_", &locator_set_name))
        {
          p = hash_get_mem(lcm->locator_set_index_by_name, locator_set_name);
          if (!p)
            {
              error = clib_error_return(0, "locator-set %s doesn't exist",
                                        locator_set_name);
              goto done;
            }
          locator_set_index = p[0];
        }
      else
        {
          error = unformat_parse_error(line_input);
          goto done;
        }
    }
  /* XXX treat batch configuration */

  a->eid = eid;
  a->is_add = is_add;
  a->locator_set_index = locator_set_index;
  a->local = 1;

  rv = vnet_lisp_add_del_local_mapping (a, &map_index);
  if (0 != rv)
   {
      error = clib_error_return(0, "failed to %s local mapping!",
                                is_add ? "add" : "delete");
   }
 done:
  vec_free(eids);
  if (locator_set_name)
    vec_free (locator_set_name);
  gid_address_free (&a->eid);
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_local_eid_command) = {
    .path = "lisp eid-table",
    .short_help = "lisp eid-table add/del [vni <vni>] eid <eid> "
      "locator-set <locator-set>",
    .function = lisp_add_del_local_eid_command_fn,
};

int
vnet_lisp_eid_table_map (u32 vni, u32 vrf, u8 is_add)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  uword * table_id, * vnip;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return -1;
    }

  if (vni == 0 || vrf == 0)
    {
      clib_warning ("can't add/del default vni-vrf mapping!");
      return -1;
    }

  table_id = hash_get (lcm->table_id_by_vni, vni);
  vnip = hash_get (lcm->vni_by_table_id, vrf);

  if (is_add)
    {
      if (table_id || vnip)
        {
          clib_warning ("vni %d or vrf %d already used in any vrf/vni "
                        "mapping!", vni, vrf);
          return -1;
        }
      hash_set (lcm->table_id_by_vni, vni, vrf);
      hash_set (lcm->vni_by_table_id, vrf, vni);

      /* create dp iface */
      dp_add_del_iface (lcm, vni, 1);
    }
  else
    {
      if (!table_id || !vnip)
        {
          clib_warning ("vni %d or vrf %d not used in any vrf/vni! "
                        "mapping!", vni, vrf);
          return -1;
        }
      hash_unset (lcm->table_id_by_vni, vni);
      hash_unset (lcm->vni_by_table_id, vrf);

      /* remove dp iface */
      dp_add_del_iface (lcm, vni, 0);
    }
  return 0;
}

static clib_error_t *
lisp_eid_table_map_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  u8 is_add = 1;
  u32 vni = 0, vrf = 0;
  unformat_input_t _line_input, * line_input = &_line_input;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "vni %d", &vni))
        ;
      else if (unformat (line_input, "vrf %d", &vrf))
        ;
      else
        {
          return unformat_parse_error (line_input);
        }
    }
  vnet_lisp_eid_table_map (vni, vrf, is_add);
  return 0;
}

VLIB_CLI_COMMAND (lisp_eid_table_map_command) = {
    .path = "lisp eid-table map",
    .short_help = "lisp eid-table map [del] vni <vni> vrf <vrf>",
    .function = lisp_eid_table_map_command_fn,
};


/* return 0 if the two locator sets are identical 1 otherwise */
static u8
compare_locators (lisp_cp_main_t *lcm, u32 * old_ls_indexes,
                  locator_t * new_locators)
{
  u32 i, old_li;
  locator_t * old_loc, * new_loc;

  if (vec_len (old_ls_indexes) != vec_len(new_locators))
    return 1;

  for (i = 0; i < vec_len(new_locators); i++)
    {
      old_li = vec_elt(old_ls_indexes, i);
      old_loc = pool_elt_at_index(lcm->locator_pool, old_li);

      new_loc = vec_elt_at_index(new_locators, i);

      if (locator_cmp (old_loc, new_loc))
        return 1;
    }
  return 0;
}

/**
 * Adds/removes/updates mapping. Does not program forwarding.
 *
 * @param deid destination EID
 * @param rlocs vector of remote locators
 * @param action action for negative map-reply
 * @param is_add add mapping if non-zero, delete otherwise
 * @return return code
 */
int
vnet_lisp_add_del_mapping (gid_address_t * deid, locator_t * rlocs, u8 action,
                           u8 authoritative, u32 ttl, u8 is_add,
                           u32 * res_map_index)
{
  vnet_lisp_add_del_mapping_args_t _m_args, * m_args = &_m_args;
  vnet_lisp_add_del_locator_set_args_t _ls_args, * ls_args = &_ls_args;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  u32 mi, ls_index = 0, dst_map_index;
  mapping_t * old_map;

  if (vnet_lisp_enable_disable_status() == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (res_map_index)
    res_map_index[0] = ~0;

  memset (m_args, 0, sizeof (m_args[0]));
  memset (ls_args, 0, sizeof (ls_args[0]));

  ls_args->locators = rlocs;

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, deid);
  old_map = ((u32) ~0 != mi) ? pool_elt_at_index(lcm->mapping_pool, mi) : 0;

  if (is_add)
    {
      /* overwrite: if mapping already exists, decide if locators should be
       * updated and be done */
      if (old_map && gid_address_cmp (&old_map->eid, deid) == 0)
        {
          locator_set_t * old_ls;

          /* update mapping attributes */
          old_map->action = action;
          old_map->authoritative = authoritative;
          old_map->ttl = ttl;

          old_ls = pool_elt_at_index(lcm->locator_set_pool,
                                     old_map->locator_set_index);
          if (compare_locators (lcm, old_ls->locator_indices,
                                ls_args->locators))
            {
              /* set locator-set index to overwrite */
              ls_args->is_add = 1;
              ls_args->index = old_map->locator_set_index;
              vnet_lisp_add_del_locator_set (ls_args, 0);
              if (res_map_index)
                res_map_index[0] = mi;
            }
        }
      /* new mapping */
      else
        {
          ls_args->is_add = 1;
          ls_args->index = ~0;

          vnet_lisp_add_del_locator_set (ls_args, &ls_index);

          /* add mapping */
          gid_address_copy (&m_args->eid, deid);
          m_args->is_add = 1;
          m_args->action = action;
          m_args->locator_set_index = ls_index;
          vnet_lisp_map_cache_add_del (m_args, &dst_map_index);

          if (res_map_index)
            res_map_index[0] = dst_map_index;
        }
    }
  else
    {
      if (old_map == 0 || gid_address_cmp (&old_map->eid, deid) != 0)
        {
          clib_warning("cannot delete mapping for eid %U", format_gid_address,
                       deid);
          return -1;
        }

      m_args->is_add = 0;
      gid_address_copy (&m_args->eid, deid);
      m_args->locator_set_index = old_map->locator_set_index;

      /* delete mapping associated from map-cache */
      vnet_lisp_map_cache_add_del (m_args, 0);

      ls_args->is_add = 0;
      ls_args->index = old_map->locator_set_index;
      /* delete locator set */
      vnet_lisp_add_del_locator_set (ls_args, 0);
    }

  /* success */
  return 0;
}

int
vnet_lisp_clear_all_remote_adjacencies (void)
{
  int rv = 0;
  u32 mi, * map_indices = 0, * map_indexp;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  vnet_lisp_add_del_mapping_args_t _dm_args, * dm_args = &_dm_args;
  vnet_lisp_add_del_locator_set_args_t _ls, * ls = &_ls;

  pool_foreach_index (mi, lcm->mapping_pool,
    ({
      vec_add1 (map_indices, mi);
    }));

  vec_foreach (map_indexp, map_indices)
    {
      mapping_t * map = pool_elt_at_index (lcm->mapping_pool, map_indexp[0]);
      if (!map->local)
        {
          dp_del_fwd_entry (lcm, 0, map_indexp[0]);

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
 * Adds remote mapping and sets it as adjacency for local eid or removes
 * forwarding entry associated to remote mapping. Note that for now adjacencies
 * are not stored, they only result in forwarding entries being created.
 */
int
vnet_lisp_add_del_adjacency (gid_address_t * deid, gid_address_t * seid,
                             locator_t * rlocs, u8 action, u8 authoritative,
                             u32 ttl, u8 is_add)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  u32 src_map_index, dst_map_index = ~0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  /* insert/update mappings cache */
  vnet_lisp_add_del_mapping (deid, rlocs, action, authoritative, ttl, is_add,
                             &dst_map_index);

  /* TODO check if src/dst */

  /* check if source eid has an associated mapping. If pitr mode is on, just
   * use the pitr's mapping */
  src_map_index = lcm->lisp_pitr ? lcm->pitr_map_index :
          gid_dictionary_lookup (&lcm->mapping_index_by_gid, seid);


  if (GID_LOOKUP_MISS == src_map_index)
    {
      clib_warning("seid %d not found. Cannot program forwarding!",
                   format_gid_address, seid);

      return -1;
    }

  if (is_add)
    {
      /* update forwarding if a destination mapping index was found */
      if ((u32) ~0 != dst_map_index)
        dp_add_fwd_entry (lcm, src_map_index, dst_map_index);
    }
  else
    dp_del_fwd_entry (lcm, 0, dst_map_index);

  return 0;
}

/**
 * Handler for add/del remote mapping CLI.
 *
 * @param vm vlib context
 * @param input input from user
 * @param cmd cmd
 * @return pointer to clib error structure
 */
static clib_error_t *
lisp_add_del_remote_mapping_command_fn (vlib_main_t * vm,
                                        unformat_input_t * input,
                                        vlib_cli_command_t * cmd)
{
  clib_error_t * error = 0;
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1, del_all = 0;
  locator_t rloc, * rlocs = 0;
  ip_prefix_t * deid_ippref, * seid_ippref;
  gid_address_t seid, deid;
  u8 * dmac = gid_address_mac (&deid);
  u8 * smac = gid_address_mac (&seid);
  u8 deid_set = 0, seid_set = 0;
  u8 * s = 0;
  u32 vni, action = ~0;
  int rv;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset(&deid, 0, sizeof(deid));
  memset(&seid, 0, sizeof(seid));
  memset(&rloc, 0, sizeof(rloc));

  seid_ippref = &gid_address_ippref(&seid);
  deid_ippref = &gid_address_ippref(&deid);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del-all"))
        del_all = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "add"))
        ;
      else if (unformat (line_input, "deid %U",
                         unformat_ip_prefix, deid_ippref))
        {
          gid_address_type (&deid) = GID_ADDR_IP_PREFIX;
          deid_set = 1;
        }
      else if (unformat (line_input, "deid %U",
                         unformat_mac_address, dmac))
        {
          gid_address_type (&deid) = GID_ADDR_MAC;
          deid_set = 1;
        }
      else if (unformat (line_input, "vni %u", &vni))
        {
          gid_address_vni (&seid) = vni;
          gid_address_vni (&deid) = vni;
        }
      else if (unformat (line_input, "seid %U",
                         unformat_ip_prefix, seid_ippref))
        {
          gid_address_type (&seid) = GID_ADDR_IP_PREFIX;
          seid_set = 1;
        }
      else if (unformat (line_input, "seid %U",
                         unformat_mac_address, smac))
        {
          gid_address_type (&seid) = GID_ADDR_MAC;
          seid_set = 1;
        }
      else if (unformat (line_input, "rloc %U", unformat_ip_address, &rloc.address))
        vec_add1 (rlocs, rloc);
      else if (unformat (line_input, "action %s", &s))
        {
          if (!strcmp ((char *)s, "no-action"))
            action = ACTION_NONE;
          if (!strcmp ((char *)s, "natively-forward"))
            action = ACTION_NATIVELY_FORWARDED;
          if (!strcmp ((char *)s, "send-map-request"))
            action = ACTION_SEND_MAP_REQUEST;
          else if (!strcmp ((char *)s, "drop"))
            action = ACTION_DROP;
          else
            {
              clib_warning ("invalid action: '%s'", s);
              goto done;
            }
        }
      else
        {
          clib_warning ("parse error");
          goto done;
        }
    }

  if (!del_all)
    {
      if (!deid_set)
        {
          clib_warning ("missing deid!");
          goto done;
        }

      if (GID_ADDR_IP_PREFIX == gid_address_type (&deid))
        {
          /* if seid not set, make sure the ip version is the same as that
           * of the deid. This ensures the seid to be configured will be
           * either 0/0 or ::/0 */
          if (!seid_set)
            ip_prefix_version(seid_ippref) = ip_prefix_version(deid_ippref);

          if (is_add &&
              (ip_prefix_version (deid_ippref)
               != ip_prefix_version(seid_ippref)))
            {
              clib_warning ("source and destination EIDs are not"
                            " in the same IP family!");
              goto done;
            }
        }

      if (is_add && (~0 == action)
          && 0 == vec_len (rlocs))
        {
          clib_warning ("no action set for negative map-reply!");
          goto done;
        }
    }
  else
    {
      vnet_lisp_clear_all_remote_adjacencies ();
      goto done;
    }

  /* TODO build src/dst with seid*/

  /* if it's a delete, clean forwarding */
  if (!is_add)
    {
      lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
      u32 di = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &deid);
      if (di != (u32) ~0)
        dp_del_fwd_entry (lcm, 0, di);
    }

  /* add as static remote mapping, i.e., not authoritative and infinite ttl */
  rv = vnet_lisp_add_del_mapping (&deid, rlocs, action, 0, ~0, is_add, 0);

  if (rv)
    clib_warning("failed to %s remote mapping!", is_add ? "add" : "delete");

done:
  unformat_free (line_input);
  if (s)
    vec_free (s);
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_remote_mapping_command) = {
    .path = "lisp remote-mapping",
    .short_help = "lisp remote-mapping add|del [del-all] vni <vni>"
     "deid <dest-eid> seid <src-eid> [action <no-action|natively-forward|"
     "send-map-request|drop>] rloc <dst-locator> [rloc <dst-locator> ... ]",
    .function = lisp_add_del_remote_mapping_command_fn,
};

static clib_error_t *
lisp_show_map_resolvers_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  ip_address_t * addr;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();

  vec_foreach (addr, lcm->map_resolvers)
    {
      vlib_cli_output (vm, "%U", format_ip_address, addr);
    }
  return 0;
}

VLIB_CLI_COMMAND (lisp_show_map_resolvers_command) = {
    .path = "show lisp map-resolvers",
    .short_help = "show lisp map-resolvers",
    .function = lisp_show_map_resolvers_command_fn,
};

int
vnet_lisp_pitr_set_locator_set (u8 * locator_set_name, u8 is_add)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  u32 locator_set_index = ~0;
  mapping_t * m;
  uword * p;

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
      lcm->pitr_map_index = m - lcm->mapping_pool;

      /* enable pitr mode */
      lcm->lisp_pitr = 1;
    }
  else
    {
      /* remove pitr mapping */
      pool_put_index (lcm->mapping_pool, lcm->pitr_map_index);

      /* disable pitr mode */
      lcm->lisp_pitr = 0;
    }
  return 0;
}

static clib_error_t *
lisp_pitr_set_locator_set_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  u8 locator_name_set = 0;
  u8 * locator_set_name = 0;
  u8 is_add = 1;
  unformat_input_t _line_input, * line_input = &_line_input;
  clib_error_t * error = 0;
  int rv = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ls %_%v%_", &locator_set_name))
        locator_name_set = 1;
      else if (unformat (line_input, "disable"))
        is_add = 0;
      else
        return clib_error_return (0, "parse error");
    }

  if (!locator_name_set)
    {
      clib_warning ("No locator set specified!");
      goto done;
    }
  rv = vnet_lisp_pitr_set_locator_set (locator_set_name, is_add);
  if (0 != rv)
    {
      error = clib_error_return(0, "failed to %s pitr!",
                                is_add ? "add" : "delete");
    }

done:
  if (locator_set_name)
    vec_free (locator_set_name);
  return error;
}

VLIB_CLI_COMMAND (lisp_pitr_set_locator_set_command) = {
    .path = "lisp pitr",
    .short_help = "lisp pitr [disable] ls <locator-set-name>",
    .function = lisp_pitr_set_locator_set_command_fn,
};


static u8 *
format_eid_entry (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  lisp_cp_main_t * lcm = va_arg (*args, lisp_cp_main_t *);
  gid_address_t * gid = va_arg (*args, gid_address_t *);
  locator_set_t * ls = va_arg (*args, locator_set_t *);
  u32 * loc_index;
  u8 first_line = 1;
  u8 * loc;

  u8 * type = ls->local ? format(0, "local(%s)", ls->name)
                        : format(0, "remote");

  if (vec_len (ls->locator_indices) == 0)
    {
      s = format (s, "%-35U%-20s", format_gid_address, gid, type);
    }
  else
    {
      vec_foreach (loc_index, ls->locator_indices)
        {
          locator_t * l = pool_elt_at_index (lcm->locator_pool, loc_index[0]);
          if (l->local)
            loc = format (0, "%U", format_vnet_sw_if_index_name, vnm,
                          l->sw_if_index);
          else
            loc = format (0, "%U", format_ip_address,
                          &gid_address_ip (&l->address));

          if (first_line)
            {
              s = format (s, "%-35U%-20s%-v\n", format_gid_address,
                          gid, type, loc);
              first_line = 0;
            }
          else
            s = format (s, "%55s%v\n", "", loc);
        }
    }
  return s;
}

static clib_error_t *
lisp_show_eid_table_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  mapping_t * mapit;

  vlib_cli_output (vm, "%-35s%-20s%-s", "EID", "type", "locators");
  pool_foreach (mapit, lcm->mapping_pool,
  ({
    locator_set_t * ls = pool_elt_at_index (lcm->locator_set_pool,
                                            mapit->locator_set_index);
    vlib_cli_output (vm, "%U", format_eid_entry, lcm->vnet_main,
                     lcm, &mapit->eid, ls);
  }));

  return 0;
}

VLIB_CLI_COMMAND (lisp_cp_show_eid_table_command) = {
    .path = "show lisp eid-table",
    .short_help = "Shows EID table",
    .function = lisp_show_eid_table_command_fn,
};

/* cleans locator to locator-set data and removes locators not part of
 * any locator-set */
static void
clean_locator_to_locator_set (lisp_cp_main_t * lcm, u32 lsi)
{
  u32 i, j, *loc_indexp, *ls_indexp, **ls_indexes, *to_be_deleted = 0;
  locator_set_t * ls = pool_elt_at_index(lcm->locator_set_pool, lsi);
  for (i = 0; i < vec_len(ls->locator_indices); i++)
    {
      loc_indexp = vec_elt_at_index(ls->locator_indices, i);
      ls_indexes = vec_elt_at_index(lcm->locator_to_locator_sets,
                                    loc_indexp[0]);
      for (j = 0; j < vec_len(ls_indexes[0]); j++)
        {
          ls_indexp = vec_elt_at_index(ls_indexes[0], j);
          if (ls_indexp[0] == lsi)
            break;
        }

      /* delete index for removed locator-set*/
      vec_del1(ls_indexes[0], j);

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
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();

  ASSERT(a != NULL);
  ASSERT(p != NULL);

  /* find locator-set */
  if (a->local)
    {
      p = hash_get_mem(lcm->locator_set_index_by_name, a->name);
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
  locator_t * itloc;
  u32 * locit;

  ASSERT(ls != NULL);
  ASSERT(loc != NULL);

  vec_foreach(locit, ls->locator_indices)
    {
      itloc = pool_elt_at_index(lcm->locator_pool, locit[0]);
      if (itloc->sw_if_index == loc->sw_if_index ||
          !gid_address_cmp(&itloc->address, &loc->address))
        {
          clib_warning("Duplicate locator");
          return VNET_API_ERROR_VALUE_EXIST;
        }
    }

  return 0;
}

static inline void
remove_locator_from_locator_set (locator_set_t * ls, u32 * locit, u32 ls_index,
                                 u32 loc_id)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  u32 ** ls_indexes = NULL;

  ASSERT(ls != NULL);
  ASSERT(locit != NULL);

  ls_indexes = vec_elt_at_index(lcm->locator_to_locator_sets,
                                locit[0]);
  pool_put_index(lcm->locator_pool, locit[0]);
  vec_del1(ls->locator_indices, loc_id);
  vec_del1(ls_indexes[0], ls_index);
}

int
vnet_lisp_add_del_locator (vnet_lisp_add_del_locator_set_args_t * a,
                           locator_set_t * ls, u32 * ls_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_t * loc = NULL, *itloc = NULL;
  uword _p = (u32)~0, * p = &_p;
  u32 loc_index = ~0, ls_index = ~0, * locit = NULL, ** ls_indexes = NULL;
  u32 loc_id = ~0;
  int ret = 0;

  ASSERT(a != NULL);

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  p = get_locator_set_index(a, p);
  if (!p)
    {
      clib_warning("locator-set %v doesn't exist", a->name);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (ls == 0)
    {
      ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
      if (!ls)
        {
          clib_warning("locator-set %d to be overwritten doesn't exist!",
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
            ret = is_locator_in_locator_set(lcm, ls, itloc);
            if (0 != ret)
              {
                return ret;
              }

            pool_get(lcm->locator_pool, loc);
            loc[0] = itloc[0];
            loc_index = loc - lcm->locator_pool;

            vec_add1(ls->locator_indices, loc_index);

            vec_validate (lcm->locator_to_locator_sets, loc_index);
            ls_indexes = vec_elt_at_index(lcm->locator_to_locator_sets,
                                          loc_index);
            vec_add1(ls_indexes[0], ls_index);
          }
      }
    else
      {
        ls_index = p[0];

        itloc = a->locators;
        loc_id = 0;
        vec_foreach (locit, ls->locator_indices)
          {
            loc = pool_elt_at_index(lcm->locator_pool, locit[0]);

            if (loc->local && loc->sw_if_index == itloc->sw_if_index)
              {
                remove_locator_from_locator_set(ls, locit,
                                                ls_index, loc_id);
              }
            if (0 == loc->local &&
                !gid_address_cmp(&loc->address, &itloc->address))
              {
                remove_locator_from_locator_set(ls, locit,
                                                ls_index, loc_id);
              }

            loc_id++;
          }
      }

  return 0;
}

int
vnet_lisp_add_del_locator_set (vnet_lisp_add_del_locator_set_args_t * a,
                               u32 * ls_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_set_t * ls;
  uword _p = (u32)~0, * p = &_p;
  u32 ls_index;
  u32 ** eid_indexes;
  int ret = 0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {
      p = get_locator_set_index(a, p);

      /* overwrite */
      if (p && p[0] != (u32)~0)
        {
          ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
          if (!ls)
            {
              clib_warning("locator-set %d to be overwritten doesn't exist!",
                           p[0]);
              return -1;
            }

          /* clean locator to locator-set vectors and remove locators if
           * they're not part of another locator-set */
          clean_locator_to_locator_set (lcm, p[0]);

          /* remove locator indices from locator set */
          vec_free(ls->locator_indices);

          ls_index = p[0];

          if (ls_result)
            ls_result[0] = p[0];
        }
      /* new locator-set */
      else
        {
          pool_get(lcm->locator_set_pool, ls);
          memset(ls, 0, sizeof(*ls));
          ls_index = ls - lcm->locator_set_pool;

          if (a->local)
            {
              ls->name = vec_dup(a->name);

              if (!lcm->locator_set_index_by_name)
                lcm->locator_set_index_by_name = hash_create_vec(
                    /* size */0, sizeof(ls->name[0]), sizeof(uword));
              hash_set_mem(lcm->locator_set_index_by_name, ls->name, ls_index);

              /* mark as local locator-set */
              vec_add1(lcm->local_locator_set_indexes, ls_index);
            }
          ls->local = a->local;
          if (ls_result)
            ls_result[0] = ls_index;
        }

      ret = vnet_lisp_add_del_locator(a, ls, NULL);
      if (0 != ret)
        {
          return ret;
        }
    }
  else
    {
      p = get_locator_set_index(a, p);
      if (!p)
        {
          clib_warning("locator-set %v doesn't exists", a->name);
          return -1;
        }

      ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
      if (!ls)
        {
          clib_warning("locator-set with index %d doesn't exists", p[0]);
          return -1;
        }

      if (lcm->mreq_itr_rlocs == p[0])
        {
          clib_warning ("Can't delete the locator-set used to constrain "
                        "the itr-rlocs in map-requests!");
          return -1;
        }

      if (vec_len(lcm->locator_set_to_eids) != 0)
      {
          eid_indexes = vec_elt_at_index(lcm->locator_set_to_eids, p[0]);
          if (vec_len(eid_indexes[0]) != 0)
          {
              clib_warning ("Can't delete a locator that supports a mapping!");
              return -1;
          }
      }

      /* clean locator to locator-sets data */
      clean_locator_to_locator_set (lcm, p[0]);

      if (ls->local)
        {
          u32 it, lsi;

          vec_foreach_index(it, lcm->local_locator_set_indexes)
          {
            lsi = vec_elt(lcm->local_locator_set_indexes, it);
            if (lsi == p[0])
              {
                vec_del1(lcm->local_locator_set_indexes, it);
                break;
              }
          }
          hash_unset_mem(lcm->locator_set_index_by_name, ls->name);
        }
      vec_free(ls->name);
      vec_free(ls->locator_indices);
      pool_put(lcm->locator_set_pool, ls);
    }
  return 0;
}

clib_error_t *
vnet_lisp_enable_disable (u8 is_enable)
{
  u32 vni, table_id;
  clib_error_t * error = 0;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  vnet_lisp_gpe_enable_disable_args_t _a, * a = &_a;

  a->is_en = is_enable;
  error = vnet_lisp_gpe_enable_disable (a);
  if (error)
    {
      return clib_error_return (0, "failed to %s data-plane!",
                                a->is_en ? "enable" : "disable");
    }

  if (is_enable)
    {
      /* enable all ifaces */
      hash_foreach(vni, table_id, lcm->table_id_by_vni, ({
        dp_add_del_iface(lcm, vni, 1);
      }));
    }
  else
    {
      /* clear refcount table */
      hash_free (lcm->dp_intf_by_vni);
      hash_free (lcm->fwd_entry_by_mapping_index);
      pool_free (lcm->fwd_entry_pool);
    }

  /* update global flag */
  lcm->is_enabled = is_enable;

  return 0;
}

static clib_error_t *
lisp_enable_disable_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_enabled = 0;
  u8 is_set = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
        {
          is_set = 1;
          is_enabled = 1;
        }
      else if (unformat (line_input, "disable"))
        is_set = 1;
      else
        {
          return clib_error_return (0, "parse error: '%U'",
                                   format_unformat_error, line_input);
        }
    }

  if (!is_set)
      return clib_error_return (0, "state not set");

  return vnet_lisp_enable_disable (is_enabled);
}

VLIB_CLI_COMMAND (lisp_cp_enable_disable_command) = {
    .path = "lisp",
    .short_help = "lisp [enable|disable]",
    .function = lisp_enable_disable_command_fn,
};

u8
vnet_lisp_enable_disable_status (void)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  return lcm->is_enabled;
}

static u8 *
format_lisp_status (u8 * s, va_list * args)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();
  return format (s, "%s", lcm->is_enabled ? "enabled" : "disabled");
}

static clib_error_t *
lisp_show_status_command_fn (vlib_main_t * vm, unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  u8 * msg = 0;
  msg = format (msg, "feature: %U\ngpe: %U\n",
                format_lisp_status, format_vnet_lisp_gpe_status);
  vlib_cli_output (vm, "%v", msg);
  vec_free (msg);
  return 0;
}

VLIB_CLI_COMMAND (lisp_show_status_command) = {
    .path = "show lisp status",
    .short_help = "show lisp status",
    .function = lisp_show_status_command_fn,
};

static clib_error_t *
lisp_show_eid_table_map_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  hash_pair_t * p;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();

  vlib_cli_output (vm, "%=10s%=10s", "VNI", "VRF");
  hash_foreach_pair (p, lcm->table_id_by_vni,
    {
      vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
    });
  return 0;
}

VLIB_CLI_COMMAND (lisp_show_eid_table_map_command) = {
    .path = "show lisp eid-table map",
    .short_help = "show lisp eid-table vni to vrf mappings",
    .function = lisp_show_eid_table_map_command_fn,
};

static clib_error_t *
lisp_add_del_locator_set_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                     vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  vnet_main_t * vnm = lgm->vnet_main;
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  clib_error_t * error = 0;
  u8 * locator_set_name = 0;
  locator_t locator, * locators = 0;
  vnet_lisp_add_del_locator_set_args_t _a, * a = &_a;
  u32 ls_index = 0;
  int rv = 0;

  memset(&locator, 0, sizeof(locator));
  memset(a, 0, sizeof(a[0]));

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %_%v%_", &locator_set_name))
        is_add = 1;
      else if (unformat (line_input, "del %_%v%_", &locator_set_name))
        is_add = 0;
      else if (unformat (line_input, "iface %U p %d w %d",
                         unformat_vnet_sw_interface, vnm, &locator.sw_if_index,
                         &locator.priority, &locator.weight))
        {
          locator.local = 1;
          vec_add1(locators, locator);
        }
      else
        {
          error = unformat_parse_error(line_input);
          goto done;
        }
    }

  a->name = locator_set_name;
  a->locators = locators;
  a->is_add = is_add;
  a->local = 1;

  rv = vnet_lisp_add_del_locator_set(a, &ls_index);
  if (0 != rv)
    {
      error = clib_error_return(0, "failed to %s locator-set!",
                                is_add ? "add" : "delete");
    }

 done:
  vec_free(locators);
  if (locator_set_name)
    vec_free (locator_set_name);
  return error;
}

VLIB_CLI_COMMAND (lisp_cp_add_del_locator_set_command) = {
    .path = "lisp locator-set",
    .short_help = "lisp locator-set add/del <name> [iface <iface-name> "
        "p <priority> w <weight>]",
    .function = lisp_add_del_locator_set_command_fn,
};

static clib_error_t *
lisp_add_del_locator_in_set_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                     vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  vnet_main_t * vnm = lgm->vnet_main;
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  clib_error_t * error = 0;
  u8 * locator_set_name = 0;
  u8 locator_set_name_set = 0;
  locator_t locator, * locators = 0;
  vnet_lisp_add_del_locator_set_args_t _a, * a = &_a;
  u32 ls_index = 0;

  memset(&locator, 0, sizeof(locator));
  memset(a, 0, sizeof(a[0]));

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat(line_input, "locator-set %_%v%_", &locator_set_name))
        locator_set_name_set = 1;
      else if (unformat (line_input, "iface %U p %d w %d",
                         unformat_vnet_sw_interface, vnm, &locator.sw_if_index,
                         &locator.priority, &locator.weight))
        {
          locator.local = 1;
          vec_add1(locators, locator);
        }
      else
        {
          error = unformat_parse_error(line_input);
          goto done;
        }
    }

  if (!locator_set_name_set)
    {
      error = clib_error_return(0, "locator_set name not set!");
      goto done;
  }

  a->name = locator_set_name;
  a->locators = locators;
  a->is_add = is_add;
  a->local = 1;

  vnet_lisp_add_del_locator(a, 0, &ls_index);

 done:
  vec_free(locators);
  vec_free (locator_set_name);
  return error;
}

VLIB_CLI_COMMAND (lisp_cp_add_del_locator_in_set_command) = {
    .path = "lisp locator",
    .short_help = "lisp locator add/del locator-set <name> iface <iface-name> "
                  "p <priority> w <weight>",
    .function = lisp_add_del_locator_in_set_command_fn,
};

static clib_error_t *
lisp_cp_show_locator_sets_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  locator_set_t * lsit;
  locator_t * loc;
  u32 * locit;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();

  vlib_cli_output (vm, "%=20s%=16s%=16s%=16s", "Locator-set", "Locator",
                   "Priority", "Weight");
  pool_foreach (lsit, lcm->locator_set_pool,
  ({
    u8 * msg = 0;
    int next_line = 0;
    msg = format (msg, "%=16v", lsit->name);
    vec_foreach (locit, lsit->locator_indices)
      {
        if (next_line)
          {
            msg = format (msg, "%16s", " ");
          }
        loc = pool_elt_at_index (lcm->locator_pool, locit[0]);
        if (loc->local)
          msg = format (msg, "%16d%16d%16d\n", loc->sw_if_index, loc->priority,
                        loc->weight);
        else
          msg = format (msg, "%16U%16d%16d\n", format_ip_address,
                        gid_address_ip(&loc->address), loc->priority,
                        loc->weight);
        next_line = 1;
      }
    vlib_cli_output (vm, "%v", msg);
    vec_free (msg);
  }));
  return 0;
}

VLIB_CLI_COMMAND (lisp_cp_show_locator_sets_command) = {
    .path = "show lisp locator-set",
    .short_help = "Shows locator-sets",
    .function = lisp_cp_show_locator_sets_command_fn,
};

int
vnet_lisp_add_del_map_resolver (vnet_lisp_add_del_map_resolver_args_t * a)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  ip_address_t * addr;
  u32 i;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {
      vec_foreach(addr, lcm->map_resolvers)
        {
          if (!ip_address_cmp (addr, &a->address))
            {
              clib_warning("map-resolver %U already exists!", format_ip_address,
                           &a->address);
              return -1;
            }
        }
      vec_add1(lcm->map_resolvers, a->address);
    }
  else
    {
      for (i = 0; i < vec_len(lcm->map_resolvers); i++)
        {
          addr = vec_elt_at_index(lcm->map_resolvers, i);
          if (!ip_address_cmp (addr, &a->address))
            {
              vec_delete(lcm->map_resolvers, 1, i);
              break;
            }
        }
    }
  return 0;
}

static clib_error_t *
lisp_add_del_map_resolver_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip_address_t ip_addr;
  clib_error_t * error = 0;
  int rv = 0;
  vnet_lisp_add_del_map_resolver_args_t _a, * a = &_a;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "%U", unformat_ip_address, &ip_addr))
        ;
      else
        {
          error = unformat_parse_error(line_input);
          goto done;
        }
    }
  a->is_add = is_add;
  a->address = ip_addr;
  rv = vnet_lisp_add_del_map_resolver (a);
  if (0 != rv)
    {
      error = clib_error_return(0, "failed to %s map-resolver!",
                                is_add ? "add" : "delete");
    }

 done:
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_map_resolver_command) = {
    .path = "lisp map-resolver",
    .short_help = "lisp map-resolver add/del <ip_address>",
    .function = lisp_add_del_map_resolver_command_fn,
};

int
vnet_lisp_add_del_mreq_itr_rlocs (vnet_lisp_add_del_mreq_itr_rloc_args_t * a)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  uword * p = 0;

  if (vnet_lisp_enable_disable_status () == 0)
    {
      clib_warning("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  if (a->is_add)
    {
      p = hash_get_mem(lcm->locator_set_index_by_name, a->locator_set_name);
      if (!p)
        {
          clib_warning("locator-set %v doesn't exist", a->locator_set_name);
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

static clib_error_t *
lisp_add_del_mreq_itr_rlocs_command_fn (vlib_main_t * vm,
                                        unformat_input_t * input,
                                        vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u8 * locator_set_name = 0;
  clib_error_t * error = 0;
  int rv = 0;
  vnet_lisp_add_del_mreq_itr_rloc_args_t _a, * a = &_a;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "add %s", &locator_set_name))
        is_add = 1;
      else
        {
          error = unformat_parse_error(line_input);
          goto done;
        }
    }

  a->is_add = is_add;
  a->locator_set_name = locator_set_name;
  rv = vnet_lisp_add_del_mreq_itr_rlocs (a);
  if (0 != rv)
    {
      error = clib_error_return(0, "failed to %s map-request itr-rlocs!",
                                is_add ? "add" : "delete");
    }

  vec_free(locator_set_name);

 done:
  return error;

}

VLIB_CLI_COMMAND (lisp_add_del_map_request_command) = {
    .path = "lisp map-request itr-rlocs",
    .short_help = "lisp map-request itr-rlocs add/del <locator_set_name>",
    .function = lisp_add_del_mreq_itr_rlocs_command_fn,
};

static clib_error_t *
lisp_show_mreq_itr_rlocs_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_set_t * loc_set;

  vlib_cli_output (vm, "%=20s", "itr-rlocs");

  if (~0 == lcm->mreq_itr_rlocs)
    {
      return 0;
    }

  loc_set = pool_elt_at_index (lcm->locator_set_pool, lcm->mreq_itr_rlocs);

  vlib_cli_output (vm, "%=20s", loc_set->name);

  return 0;
}

VLIB_CLI_COMMAND (lisp_show_map_request_command) = {
    .path = "show lisp map-request itr-rlocs",
    .short_help = "Shows map-request itr-rlocs",
    .function = lisp_show_mreq_itr_rlocs_command_fn,
};

/* Statistics (not really errors) */
#define foreach_lisp_cp_lookup_error           \
_(DROP, "drop")                                \
_(MAP_REQUESTS_SENT, "map-request sent")

static char * lisp_cp_lookup_error_strings[] = {
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
  LISP_CP_LOOKUP_NEXT_IP4_LOOKUP,
  LISP_CP_LOOKUP_NEXT_IP6_LOOKUP,
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
  lisp_cp_lookup_trace_t * t = va_arg (*args, lisp_cp_lookup_trace_t *);

  s = format (s, "LISP-CP-LOOKUP: map-resolver: %U destination eid %U",
              format_ip_address, &t->map_resolver_ip, format_gid_address,
              &t->dst_eid);
  return s;
}

int
get_mr_and_local_iface_ip (lisp_cp_main_t * lcm, ip_address_t * mr_ip,
                           ip_address_t * sloc)
{
  ip_address_t * mrit;

  if (vec_len(lcm->map_resolvers) == 0)
    {
      clib_warning("No map-resolver configured");
      return 0;
    }

  /* find the first mr ip we have a route to and the ip of the
   * iface that has a route to it */
  vec_foreach(mrit, lcm->map_resolvers)
    {
      if (0 != ip_fib_get_first_egress_ip_for_dst (lcm, mrit, sloc)) {
          ip_address_copy(mr_ip, mrit);
          return 1;
      }
    }

  clib_warning("Can't find map-resolver and local interface ip!");
  return 0;
}

static gid_address_t *
build_itr_rloc_list (lisp_cp_main_t * lcm, locator_set_t * loc_set)
{
  void * addr;
  u32 i;
  locator_t * loc;
  u32 * loc_indexp;
  ip_interface_address_t * ia = 0;
  gid_address_t gid_data, * gid = &gid_data;
  gid_address_t * rlocs = 0;
  ip_prefix_t * ippref = &gid_address_ippref (gid);
  ip_address_t * rloc = &ip_prefix_addr (ippref);

  memset (gid, 0, sizeof (gid[0]));
  gid_address_type (gid) = GID_ADDR_IP_PREFIX;
  for (i = 0; i < vec_len(loc_set->locator_indices); i++)
    {
      loc_indexp = vec_elt_at_index(loc_set->locator_indices, i);
      loc = pool_elt_at_index (lcm->locator_pool, loc_indexp[0]);

      /* Add ipv4 locators first TODO sort them */
      foreach_ip_interface_address (&lcm->im4->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
	addr = ip_interface_address_get_address (&lcm->im4->lookup_main, ia);
	ip_address_set (rloc, addr, IP4);
        ip_prefix_len (ippref) = 32;
        vec_add1 (rlocs, gid[0]);
      }));

      /* Add ipv6 locators */
      foreach_ip_interface_address (&lcm->im6->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
        addr = ip_interface_address_get_address (&lcm->im6->lookup_main, ia);
        ip_address_set (rloc, addr, IP6);
        ip_prefix_len (ippref) = 128;
        vec_add1 (rlocs, gid[0]);
      }));
    }
  return rlocs;
}

static vlib_buffer_t *
build_encapsulated_map_request (vlib_main_t * vm, lisp_cp_main_t *lcm,
                                gid_address_t * seid, gid_address_t * deid,
                                locator_set_t * loc_set, ip_address_t * mr_ip,
                                ip_address_t * sloc, u8 is_smr_invoked,
                                u64 *nonce_res, u32 * bi_res)
{
  vlib_buffer_t * b;
  u32 bi;
  gid_address_t * rlocs = 0;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Can't allocate buffer for Map-Request!");
      return 0;
    }

  b = vlib_get_buffer (vm, bi);

  /* leave some space for the encap headers */
  vlib_buffer_make_headroom (b, MAX_LISP_MSG_ENCAP_LEN);

  /* get rlocs */
  rlocs = build_itr_rloc_list (lcm, loc_set);

  /* put lisp msg */
  lisp_msg_put_mreq (lcm, b, seid, deid, rlocs, is_smr_invoked, nonce_res);

  /* push ecm: udp-ip-lisp */
  lisp_msg_push_ecm (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, seid, deid);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, sloc,
                       mr_ip);

  bi_res[0] = bi;

  vec_free(rlocs);
  return b;
}

static void
send_encapsulated_map_request (vlib_main_t * vm, lisp_cp_main_t *lcm,
                               gid_address_t * seid, gid_address_t * deid,
                               u8 is_smr_invoked)
{
  u32 next_index, bi = 0, * to_next, map_index;
  vlib_buffer_t * b;
  vlib_frame_t * f;
  u64 nonce = 0;
  locator_set_t * loc_set;
  mapping_t * map;
  pending_map_request_t * pmr;
  ip_address_t mr_ip, sloc;
  u32 ls_index;

  /* get locator-set for seid */
  if (!lcm->lisp_pitr)
    {
      map_index = gid_dictionary_lookup (&lcm->mapping_index_by_gid, seid);
      if (map_index == ~0)
        {
          clib_warning("No local mapping found in eid-table for %U!",
                       format_gid_address, seid);
          return;
        }

      map = pool_elt_at_index (lcm->mapping_pool, map_index);

      if (!map->local)
        {
          clib_warning("Mapping found for src eid %U is not marked as local!",
                       format_gid_address, seid);
          return;
        }
      ls_index = map->locator_set_index;
    }
  else
    {
      map_index = lcm->pitr_map_index;
      map = pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
      ls_index = map->locator_set_index;
    }

  /* overwrite locator set if map-request itr-rlocs configured */
  if (~0 != lcm->mreq_itr_rlocs)
    {
      ls_index = lcm->mreq_itr_rlocs;
    }

  loc_set = pool_elt_at_index (lcm->locator_set_pool, ls_index);

  /* get local iface ip to use in map-request */
  if (0 == get_mr_and_local_iface_ip (lcm, &mr_ip, &sloc))
    return;

  /* build the encapsulated map request */
  b = build_encapsulated_map_request (vm, lcm, seid, deid, loc_set, &mr_ip,
                                      &sloc, is_smr_invoked, &nonce, &bi);

  if (!b)
    return;

  /* set fib index to default and lookup node */
  vnet_buffer(b)->sw_if_index[VLIB_TX] = 0;
  next_index = (ip_addr_version(&mr_ip) == IP4) ?
      ip4_lookup_node.index : ip6_lookup_node.index;

  f = vlib_get_frame_to_node (vm, next_index);

  /* Enqueue the packet */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);

  /* add map-request to pending requests table */
  pool_get(lcm->pending_map_requests_pool, pmr);
  gid_address_copy (&pmr->src, seid);
  gid_address_copy (&pmr->dst, deid);
  hash_set(lcm->pending_map_requests_by_nonce, nonce,
           pmr - lcm->pending_map_requests_pool);
}

static void
get_src_and_dst (void *hdr, ip_address_t * src, ip_address_t *dst)
{
  ip4_header_t * ip4 = hdr;
  ip6_header_t * ip6;

  if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
    {
      ip_address_set(src, &ip4->src_address, IP4);
      ip_address_set(dst, &ip4->dst_address, IP4);
    }
  else
    {
      ip6 = hdr;
      ip_address_set(src, &ip6->src_address, IP6);
      ip_address_set(dst, &ip6->dst_address, IP6);
    }
}

static u32
lisp_get_vni_from_buffer (vlib_buffer_t * b, u8 version)
{
  uword * vnip;
  u32 vni = ~0, table_id = ~0, fib_index;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main ();

  if (version == IP4)
    {
      ip4_fib_t * fib;
      ip4_main_t * im4 = &ip4_main;
      fib_index = vec_elt (im4->fib_index_by_sw_if_index,
                           vnet_buffer (b)->sw_if_index[VLIB_RX]);
      fib = find_ip4_fib_by_table_index_or_id (im4, fib_index,
                                               IP4_ROUTE_FLAG_FIB_INDEX);
      table_id = fib->table_id;
    }
  else
    {
      ip6_fib_t * fib;
      ip6_main_t * im6 = &ip6_main;
      fib_index = vec_elt (im6->fib_index_by_sw_if_index,
                           vnet_buffer (b)->sw_if_index[VLIB_RX]);
      fib = find_ip6_fib_by_table_index_or_id (im6, fib_index,
                                               IP6_ROUTE_FLAG_FIB_INDEX);
      table_id = fib->table_id;
    }

  vnip = hash_get (lcm->vni_by_table_id, table_id);
  if (vnip)
    vni = vnip[0];
  else
    clib_warning ("vrf %d is not mapped to any vni!", table_id);

  return vni;
}

static uword
lisp_cp_lookup (vlib_main_t * vm, vlib_node_runtime_t * node,
              vlib_frame_t * from_frame)
{
  u32 * from, * to_next_drop, di, si;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main();
  u32 pkts_mapped = 0;
  uword n_left_from, n_left_to_next_drop;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, LISP_CP_LOOKUP_NEXT_DROP,
                           to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
        {
          u32 pi0, vni;
          vlib_buffer_t * p0;
          ip4_header_t * ip0;
          gid_address_t src, dst;
          ip_prefix_t * spref, * dpref;

          gid_address_type (&src) = GID_ADDR_IP_PREFIX;
          spref = &gid_address_ippref(&src);
          gid_address_type (&dst) = GID_ADDR_IP_PREFIX;
          dpref = &gid_address_ippref(&dst);

          pi0 = from[0];
          from += 1;
          n_left_from -= 1;
          to_next_drop[0] = pi0;
          to_next_drop += 1;
          n_left_to_next_drop -= 1;

          p0 = vlib_get_buffer (vm, pi0);
          p0->error = node->errors[LISP_CP_LOOKUP_ERROR_DROP];

          /* src/dst eid pair */
          ip0 = vlib_buffer_get_current (p0);
          get_src_and_dst (ip0, &ip_prefix_addr(spref), &ip_prefix_addr(dpref));
          ip_prefix_len(spref) = ip_address_max_len (ip_prefix_version(spref));
          ip_prefix_len(dpref) = ip_address_max_len (ip_prefix_version(dpref));

          vni = lisp_get_vni_from_buffer (p0, ip_prefix_version (spref));
          gid_address_vni (&dst) = vni;
          gid_address_vni (&src) = vni;

          /* if we have remote mapping for destination already in map-chache
             add forwarding tunnel directly. If not send a map-request */
          di = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &dst);
          if (~0 != di)
            {
              mapping_t * m =  vec_elt_at_index (lcm->mapping_pool, di);
              /* send a map-request also in case of negative mapping entry
                with corresponding action */
              if (m->action == ACTION_SEND_MAP_REQUEST)
                {
                  /* send map-request */
                  send_encapsulated_map_request (vm, lcm, &src, &dst, 0);
                  pkts_mapped++;
                }
              else
                {
                  si =  gid_dictionary_lookup (&lcm->mapping_index_by_gid,
                                               &src);
                  if (~0 != si)
                    {
                      dp_add_fwd_entry (lcm, si, di);
                    }
                }
            }
          else
            {
              /* send map-request */
              send_encapsulated_map_request (vm, lcm, &src, &dst, 0);
              pkts_mapped++;
            }

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_cp_lookup_trace_t *tr = vlib_add_trace (vm, node, p0,
                                                          sizeof(*tr));

              memset(tr, 0, sizeof(*tr));
              gid_address_copy (&tr->dst_eid, &dst);
              if (vec_len(lcm->map_resolvers) > 0)
                {
                  clib_memcpy (&tr->map_resolver_ip,
                               vec_elt_at_index(lcm->map_resolvers, 0),
                               sizeof(ip_address_t));
                }
            }
          gid_address_free (&dst);
          gid_address_free (&src);
        }

      vlib_put_next_frame (vm, node, LISP_CP_LOOKUP_NEXT_DROP, n_left_to_next_drop);
    }
  vlib_node_increment_counter (vm, node->node_index,
                               LISP_CP_LOOKUP_ERROR_MAP_REQUESTS_SENT,
                               pkts_mapped);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (lisp_cp_lookup_node) = {
  .function = lisp_cp_lookup,
  .name = "lisp-cp-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_lisp_cp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LISP_CP_LOOKUP_N_ERROR,
  .error_strings = lisp_cp_lookup_error_strings,

  .n_next_nodes = LISP_CP_LOOKUP_N_NEXT,

  .next_nodes = {
      [LISP_CP_LOOKUP_NEXT_DROP] = "error-drop",
      [LISP_CP_LOOKUP_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [LISP_CP_LOOKUP_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

/* lisp_cp_input statistics */
#define foreach_lisp_cp_input_error                     \
_(DROP, "drop")                                         \
_(MAP_REPLIES_RECEIVED, "map-replies received")

static char * lisp_cp_input_error_strings[] = {
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

typedef enum
{
  LISP_CP_INPUT_NEXT_DROP,
  LISP_CP_INPUT_N_NEXT,
} lisp_cp_input_next_t;

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
  CLIB_UNUSED(lisp_cp_input_trace_t * t) = va_arg (*args, lisp_cp_input_trace_t *);

  s = format (s, "LISP-CP-INPUT: TODO");
  return s;
}

void
process_map_reply (lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  u32 len = 0, i, ttl;
  void * h;
  pending_map_request_t * pmr;
  locator_t probed;
  map_reply_hdr_t * mrep_hdr;
  u64 nonce;
  gid_address_t deid;
  uword * pmr_index;
  u8 authoritative, action;
  locator_t * locators = 0, * loc;

  mrep_hdr = vlib_buffer_get_current (b);

  /* Check pending requests table and nonce */
  nonce = MREP_NONCE(mrep_hdr);
  pmr_index = hash_get(lcm->pending_map_requests_by_nonce, nonce);
  if (!pmr_index)
    {
      clib_warning("No pending map-request entry with nonce %lu!", nonce);
      return;
    }
  pmr = pool_elt_at_index(lcm->pending_map_requests_pool, pmr_index[0]);

  vlib_buffer_pull (b, sizeof(*mrep_hdr));

  for (i = 0; i < MREP_REC_COUNT(mrep_hdr); i++)
    {

      h = vlib_buffer_get_current (b);
      ttl = clib_net_to_host_u32 (MAP_REC_TTL(h));
      action = MAP_REC_ACTION(h);
      authoritative = MAP_REC_AUTH(h);

      len = lisp_msg_parse_mapping_record (b, &deid, &locators, &probed);
      if (len == ~0)
        {
          clib_warning ("Failed to parse mapping record!");
          vec_foreach (loc, locators)
            {
              locator_free (loc);
            }
          vec_free(locators);
          return;
        }

      vnet_lisp_add_del_adjacency (&deid, &pmr->src, locators, action,
                                   authoritative, ttl, 1);

      vec_free(locators);
    }

  /* remove pending map request entry */
  hash_unset(lcm->pending_map_requests_by_nonce, nonce);
  pool_put(lcm->pending_map_requests_pool, pmr);
}

void
process_map_request (vlib_main_t * vm, lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  map_request_hdr_t * mreq_hdr;
  gid_address_t src, dst;
//  u64 nonce;
  u32 i, len = 0;
  gid_address_t * itr_rlocs = 0, * rloc;

  mreq_hdr = vlib_buffer_get_current (b);
  vlib_buffer_pull (b, sizeof(*mreq_hdr));

//  nonce = MREQ_NONCE(mreq_hdr);

  if (!MREQ_SMR(mreq_hdr)) {
      clib_warning("Only SMR Map-Requests supported for now!");
      return;
  }

  /* parse src eid */
  len = lisp_msg_parse_addr (b, &src);
  if (len == ~0)
    return;

  /* for now we don't do anything with the itr's rlocs */
  len = lisp_msg_parse_itr_rlocs (b, &itr_rlocs, MREQ_ITR_RLOC_COUNT(mreq_hdr) + 1);
  if (len == ~0)
    return;

  /* TODO: RLOCs are currently unused, so free them for now */
  vec_foreach (rloc, itr_rlocs)
    {
      gid_address_free (rloc);
    }

  /* parse eid records and send SMR-invoked map-requests */
  for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++)
    {
      memset(&dst, 0, sizeof(dst));
      len = lisp_msg_parse_eid_rec (b, &dst);
      if (len == ~0)
        {
          clib_warning("Can't parse map-request EID-record");
          return;
        }
      /* send SMR-invoked map-requests */
      send_encapsulated_map_request (vm, lcm, &dst, &src, /* invoked */ 1);
    }
}

static uword
lisp_cp_input (vlib_main_t * vm, vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, * from, * to_next_drop;
  lisp_msg_type_e type;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();

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
          vlib_buffer_t * b0;

          bi0 = from[0];
          from += 1;
          n_left_from -= 1;
          to_next_drop[0] = bi0;
          to_next_drop += 1;
          n_left_to_next_drop -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          type = lisp_msg_type(vlib_buffer_get_current (b0));
          switch (type)
            {
            case LISP_MAP_REPLY:
              process_map_reply (lcm, b0);
              break;
            case LISP_MAP_REQUEST:
              process_map_request(vm, lcm, b0);
              break;
            default:
              clib_warning("Unsupported LISP message type %d", type);
              break;
            }

          b0->error = node->errors[LISP_CP_INPUT_ERROR_DROP];

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }
        }

      vlib_put_next_frame (vm, node, LISP_CP_INPUT_NEXT_DROP, n_left_to_next_drop);
    }
  return from_frame->n_vectors;
}

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

clib_error_t *
lisp_cp_init (vlib_main_t *vm)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  clib_error_t * error = 0;

  if ((error = vlib_call_init_function (vm, lisp_gpe_init)))
    return error;

  lcm->im4 = &ip4_main;
  lcm->im6 = &ip6_main;
  lcm->vlib_main = vm;
  lcm->vnet_main = vnet_get_main();
  lcm->mreq_itr_rlocs = ~0;
  lcm->lisp_pitr = 0;

  gid_dictionary_init (&lcm->mapping_index_by_gid);

  /* default vrf mapped to vni 0 */
  hash_set(lcm->table_id_by_vni, 0, 0);
  hash_set(lcm->vni_by_table_id, 0, 0);

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp,
                         lisp_cp_input_node.index, 1 /* is_ip4 */);
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp6,
                         lisp_cp_input_node.index, 0 /* is_ip4 */);

  return 0;
}

VLIB_INIT_FUNCTION(lisp_cp_init);
