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

/* Adds mapping to map-cache but does NOT program LISP forwarding */
int
vnet_lisp_add_del_mapping (vnet_lisp_add_del_mapping_args_t * a,
                           u32 * map_index_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  u32 mi, * map_indexp, map_index, i;
  mapping_t * m;
  u32 ** eid_indexes;

  mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &a->deid);
  if (a->is_add)
    {
      /* TODO check if overwriting and take appropriate actions */
      if (mi != GID_LOOKUP_MISS) {
          clib_warning("eid %U found in the eid-table", format_ip_address,
                       &a->deid);
          return VNET_API_ERROR_VALUE_EXIST;
      }

      pool_get(lcm->mapping_pool, m);
      m->eid = a->deid;
      m->locator_set_index = a->locator_set_index;
      m->ttl = a->ttl;
      m->local = a->local;

      map_index = m - lcm->mapping_pool;
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, &a->deid, map_index,
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

          /* XXX do something else? */
        }
      map_index_result[0] = map_index;
    }
  else
    {
      if (mi == GID_LOOKUP_MISS) {
          clib_warning("eid %U not found in the eid-table", format_ip_address,
                       &a->deid);
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
      else
        {
          /* remove tunnel ??? */
        }

      /* remove mapping from dictionary */
      gid_dictionary_add_del (&lcm->mapping_index_by_gid, &a->deid, 0, 0);
      pool_put_index (lcm->mapping_pool, mi);
    }

  return 0;
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
  gid_address_t * eids = 0;
  clib_error_t * error = 0;
  u8 * locator_set_name;
  u32 locator_set_index = 0, map_index = 0;
  uword * p;
  vnet_lisp_add_del_mapping_args_t _a, * a = &_a;

  gid_address_type (&eid) = IP_PREFIX;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "eid %U", unformat_ip_prefix, prefp))
        {
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
  a->deid = eid;
  a->is_add = is_add;
  a->locator_set_index = locator_set_index;
  a->local = 1;

  vnet_lisp_add_del_mapping (a, &map_index);
 done:
  vec_free(eids);
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_local_eid_command) = {
    .path = "lisp eid-table",
    .short_help = "lisp eid-table add/del eid <eid> locator-set <locator-set>",
    .function = lisp_add_del_local_eid_command_fn,
};

static clib_error_t *
lisp_show_local_eid_table_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  mapping_t * mapit;

  vlib_cli_output (vm, "%=20s%=16s", "EID", "Locator");
  pool_foreach (mapit, lcm->mapping_pool,
  ({
    u8 * msg = 0;
    locator_set_t * ls = pool_elt_at_index (lcm->locator_set_pool,
                                            mapit->locator_set_index);
    vlib_cli_output (vm, "%-16U%16v", format_gid_address, &mapit->eid,
                     ls->name);
    vec_free (msg);
  }));

  return 0;
}

VLIB_CLI_COMMAND (lisp_cp_show_local_eid_table_command) = {
    .path = "show lisp eid-table",
    .short_help = "Shows local EID table",
    .function = lisp_show_local_eid_table_command_fn,
};

/* cleans locator to locator-set data and removes locators not part of
 * any locator-set */
static void
clean_locator_to_locator_set (lisp_cp_main_t * lcm, u32 lsi)
{
  u32 i, j, *loc_indexp, *ls_indexp, **ls_indexes;
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
        pool_put_index(lcm->locator_pool, loc_indexp[0]);
    }
}
int
vnet_lisp_add_del_locator_set (vnet_lisp_add_del_locator_set_args_t * a,
                               u32 * ls_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_set_t * ls;
  locator_t * loc, * itloc;
  uword _p = (u32)~0, * p = &_p;
  u32 loc_index, ls_index, ** ls_indexes;
  u32 **eid_indexes;

  if (a->is_add)
    {
      /* check if overwrite */
      if (a->local)
        p = hash_get_mem(lcm->locator_set_index_by_name, a->name);
      else
        *p = a->index;

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

      /* allocate locators */
      vec_foreach (itloc, a->locators)
        {
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
      /* find locator-set */
      if (a->local)
        {
          p = hash_get_mem(lcm->locator_set_index_by_name, a->name);
          if (!p)
            {
              clib_warning("locator-set %v doesn't exists", a->name);
              return -1;
            }
        }
      else
        *p = a->index;

      ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
      if (!ls)
        {
          clib_warning("locator-set with index %d doesn't exists", p[0]);
          return -1;
        }
//      /* XXX what happens when a mapping is configured to use the loc-set ? */
//      if (vec_len (vec_elt_at_index(lcm->locator_set_to_eids, p[0])) != 0)
//        {
//          clib_warning ("Can't delete a locator that supports a mapping!");
//          return -1;
//        }

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
          vec_free(ls->name);
        }
      pool_put(lcm->locator_set_pool, ls);
    }
  return 0;
}

static inline
uword *vnet_lisp_get_locator(vnet_lisp_add_del_locator_set_args_t * a,
                             uword *p)
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

int
vnet_lisp_add_del_locator_set_name (vnet_lisp_add_del_locator_set_args_t * a,
                                    u32 * ls_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_set_t * ls;
  uword _p = (u32)~0, * p = &_p;
  u32 ls_index = ~0;
  u32 **eid_indexes = NULL;

  ASSERT(a != NULL);
  ASSERT(ls_result != NULL);

  p = vnet_lisp_get_locator(a, p);

  if (a->is_add)
    {
      /* overwrite */
      if (p && p[0] != (u32)~0)
        {
          ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
          if (!ls)
            {
              clib_warning("locator-set %d to be overwritten doesn't exist!",
                           p[0]);
              return VNET_API_ERROR_UNSPECIFIED;
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
	  ls->locator_indices = NULL;
          if (ls_result)
            ls_result[0] = ls_index;
        }
    }
  else
    {
       if (!p)
       {
           clib_warning("locator-set %v doesn't exists", a->name);
           return VNET_API_ERROR_INVALID_ARGUMENT;
       }

       ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
       if (!ls)
       {
           clib_warning("locator-set with index %d doesn't exists", p[0]);
           return VNET_API_ERROR_INVALID_ARGUMENT;
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
          vec_free(ls->name);
        }
      pool_put(lcm->locator_set_pool, ls);
    }
  return 0;
}

int
vnet_lisp_add_del_locator (vnet_lisp_add_del_locator_set_args_t *a,
                           u32 *ls_result)
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  locator_set_t *ls = NULL;
  locator_t *loc = NULL, *itloc = NULL;
  uword _p = (u32)~0, * p = &_p;
  u32 loc_index = ~0, ls_index = ~0, *locit = NULL, **ls_indexes = NULL;
  u32 i = ~0;

  ASSERT(a != NULL);
  ASSERT(ls_result != NULL);

  p = vnet_lisp_get_locator(a, p);
  if (!p) {
      clib_warning("locator-set %v doesn't exists", a->name);
      return VNET_API_ERROR_INVALID_ARGUMENT;
  }

  ls_index = p[0];

  if (a->is_add)
    {
        ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
        if (!ls)
        {
            clib_warning("locator-set %d to be overwritten doesn't exist!",
                         p[0]);
            return VNET_API_ERROR_INVALID_ARGUMENT;
        }

        if (ls_result)
            ls_result[0] = p[0];

      /* allocate locators */
      itloc = a->locators;
      pool_get(lcm->locator_pool, loc);
      loc[0] = itloc[0];
      loc_index = loc - lcm->locator_pool;

      vec_add1(ls->locator_indices, loc_index);

      vec_validate (lcm->locator_to_locator_sets, loc_index);
      ls_indexes = vec_elt_at_index(lcm->locator_to_locator_sets,
                                    loc_index);
      vec_add1(ls_indexes[0], ls_index);
    }
  else
    {
      ls = pool_elt_at_index(lcm->locator_set_pool, p[0]);
      if (!ls)
        {
          clib_warning("locator-set with index %d doesn't exists", p[0]);
          return VNET_API_ERROR_INVALID_ARGUMENT;
        }

      if (ls->local)
      {
          itloc = a->locators;
          i = 0;
          vec_foreach (locit, ls->locator_indices)
          {
              loc = pool_elt_at_index(lcm->locator_pool, locit[0]);
              if (loc->local && loc->sw_if_index == itloc->sw_if_index)
              {
                  ls_indexes = vec_elt_at_index(lcm->locator_to_locator_sets,
                                                locit[0]);
                  pool_put_index(lcm->locator_pool, locit[0]);
                  vec_del1(ls->locator_indices, i);
                  vec_del1(ls_indexes[0], ls_index);
              }
              i++;
          }
      }
    }
  return 0;
}

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

  vnet_lisp_add_del_locator_set(a, &ls_index);

 done:
  vec_free(locators);
  vec_free(locator_set_name);
  return error;
}

VLIB_CLI_COMMAND (lisp_cp_add_del_locator_set_command) = {
    .path = "lisp locator-set",
    .short_help = "lisp locator-set add/del <name> <iface-name> <priority> <weight>",
    .function = lisp_add_del_locator_set_command_fn,
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
    msg = format (msg, "%-16v", lsit->name);
    vec_foreach (locit, lsit->locator_indices)
      {
        loc = pool_elt_at_index (lcm->locator_pool, locit[0]);
        if (loc->local)
          msg = format (msg, "%16d%16d%16d", loc->sw_if_index, loc->priority,
                        loc->weight);
        else
          msg = format (msg, "%16U%16d%16d", format_gid_address, &loc->address,
                        loc->priority, loc->weight);
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
  vnet_lisp_add_del_map_resolver (a);

 done:
  return error;
}

VLIB_CLI_COMMAND (lisp_add_del_map_resolver_command) = {
    .path = "lisp map-resolver",
    .short_help = "lisp map-resolver add/del <ip_address>",
    .function = lisp_add_del_map_resolver_command_fn,
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
  ip4_address_t map_resolver_ip;
} lisp_cp_lookup_trace_t;

u8 *
format_lisp_cp_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_cp_lookup_trace_t * t = va_arg (*args, lisp_cp_lookup_trace_t *);

  s = format (s, "LISP-CP-LOOKUP: map-resolver: %U destination eid %U",
              format_ip4_address, &t->map_resolver_ip, format_gid_address,
              &t->dst_eid);
  return s;
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

void
get_local_iface_ip_for_dst (lisp_cp_main_t *lcm, ip_address_t * dst,
                            ip_address_t * sloc)
{
  u32 adj_index;
  ip_adjacency_t * adj;
  ip_interface_address_t * ia = 0;
  ip_lookup_main_t * lm = &lcm->im4->lookup_main;
  ip4_address_t * l4 = 0;
  ip6_address_t * l6 = 0;

  adj_index = ip_fib_lookup_with_table (lcm, 0, dst);
  adj = ip_get_adjacency (lm, adj_index);

  if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
    {
      ia = pool_elt_at_index(lm->if_address_pool, adj->if_address_index);
      if (ip_addr_version(dst) == IP4)
        {
          l4 = ip_interface_address_get_address (lm, ia);
        }
      else
        {
          l6 = ip_interface_address_get_address (lm, ia);
        }
    }
  else if (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE)
    {
      /* find sw_if_index in rewrite header */
      u32 sw_if_index = adj->rewrite_header.sw_if_index;

      /* find suitable address */
      if (ip_addr_version(dst) == IP4)
        {
          /* find the first ip address */
          foreach_ip_interface_address (&lcm->im4->lookup_main, ia,
                                        sw_if_index, 1 /* unnumbered */,
          ({
            l4 = ip_interface_address_get_address (&lcm->im4->lookup_main, ia);
            break;
          }));
        }
      else
        {
          /* find the first ip address */
          foreach_ip_interface_address (&lcm->im6->lookup_main, ia,
                                        sw_if_index, 1 /* unnumbered */,
          ({
            l6 = ip_interface_address_get_address (&lcm->im6->lookup_main, ia);
            break;
          }));
        }
    }
  else
    {
      clib_warning("Can't find local local interface ip for dst %U",
                   format_ip_address, dst);
      return;
    }

  if (l4)
    {
      ip_addr_v4(sloc).as_u32 = l4->as_u32;
      ip_addr_version(sloc) = IP4;
    }
  else if (l6)
    {
      memcpy (&ip_addr_v6(sloc), l6, sizeof(*l6));
      ip_addr_version(sloc) = IP6;
    }
  else
    {
      clib_warning("Can't find local interface addr for dst %U",
                   format_ip_address, dst);
    }
}


static ip_address_t *
build_itr_rloc_list (lisp_cp_main_t * lcm, locator_set_t * loc_set)
{
  ip4_address_t * l4;
  ip6_address_t * l6;
  u32 i;
  locator_t * loc;
  u32 * loc_indexp;
  ip_interface_address_t * ia = 0;
  ip_address_t * rlocs = 0;
  ip_address_t _rloc, * rloc = &_rloc;

  for (i = 0; i < vec_len(loc_set->locator_indices); i++)
    {
      loc_indexp = vec_elt_at_index(loc_set->locator_indices, i);
      loc = pool_elt_at_index (lcm->locator_pool, loc_indexp[0]);

      ip_addr_version(rloc) = IP4;
      /* Add ipv4 locators first TODO sort them */
      foreach_ip_interface_address (&lcm->im4->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
	l4 = ip_interface_address_get_address (&lcm->im4->lookup_main, ia);
  ip_addr_v4(rloc) = l4[0];
  vec_add1(rlocs, rloc[0]);
      }));

      ip_addr_version(rloc) = IP6;
      /* Add ipv6 locators */
      foreach_ip_interface_address (&lcm->im6->lookup_main, ia,
				    loc->sw_if_index, 1 /* unnumbered */,
      ({
  l6 = ip_interface_address_get_address (&lcm->im6->lookup_main, ia);
  ip_addr_v6(rloc) = l6[0];
  vec_add1(rlocs, rloc[0]);
      }));
    }
  return rlocs;
}

static vlib_buffer_t *
build_encapsulated_map_request (vlib_main_t * vm, lisp_cp_main_t *lcm,
                                gid_address_t * seid, gid_address_t * deid,
                                locator_set_t * loc_set, u8 is_smr_invoked,
                                u64 *nonce_res, u32 * bi_res)
{
  vlib_buffer_t * b;
  u32 bi;
  ip_address_t * mr_ip, sloc;
  ip_address_t * rlocs = 0;

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

  /* get map-resolver ip XXX use first*/
  mr_ip = vec_elt_at_index(lcm->map_resolvers, 0);

  /* get local iface ip to use in map-request XXX fib 0 for now*/
  get_local_iface_ip_for_dst (lcm, mr_ip, &sloc);

  /* push outer ip header */
  pkt_push_udp_and_ip (vm, b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, &sloc,
                       mr_ip);

  bi_res[0] = bi;

  if (rlocs)
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

  /* get locator-set for seid */
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
  loc_set = pool_elt_at_index (lcm->locator_set_pool, map->locator_set_index);

  /* build the encapsulated map request */
  b = build_encapsulated_map_request (vm, lcm, seid, deid, loc_set,
                                      is_smr_invoked, &nonce, &bi);

  if (!b)
    return;

  vnet_buffer(b)->sw_if_index[VLIB_TX] = ~0;
  next_index = (ip_prefix_version(&gid_address_ippref(seid)) == IP4) ?
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
  pmr->src_mapping_index = map_index;
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
      ip_addr_v4(src).as_u32 = ip4->src_address.as_u32;
      ip_addr_version(src) = IP4;
      ip_addr_v4(dst).as_u32 = ip4->dst_address.as_u32;
      ip_addr_version(dst) = IP4;
    }
  else
    {
      ip6 = hdr;
      memcpy (&ip_addr_v6(src), &ip6->src_address, sizeof(ip6->src_address));
      ip_addr_version(src) = IP6;
      memcpy (&ip_addr_v6(dst), &ip6->dst_address, sizeof(ip6->dst_address));
      ip_addr_version(dst) = IP6;
    }
}

static uword
lisp_cp_lookup (vlib_main_t * vm, vlib_node_runtime_t * node,
              vlib_frame_t * from_frame)
{
  u32 * from, * to_next_drop;
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
          u32 pi0;
          vlib_buffer_t * p0;
          ip4_header_t * ip0;
          gid_address_t src, dst;
          ip_prefix_t * spref, * dpref;

          gid_address_type (&src) = IP_PREFIX;
          spref = &gid_address_ippref(&src);
          gid_address_type (&dst) = IP_PREFIX;
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

          /* send map-request */
          send_encapsulated_map_request (vm, lcm, &src, &dst, 0);

          pkts_mapped++;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_cp_lookup_trace_t *tr = vlib_add_trace (vm, node, p0,
                                                          sizeof(*tr));
              gid_address_copy (&tr->dst_eid, &dst);
              memcpy (&tr->map_resolver_ip,
                      vec_elt_at_index(lcm->map_resolvers, 0),
                      sizeof(ip_address_t));
            }
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
#define foreach_lisp_cp_input_error                   \
_(DROP, "drop")                                        \
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
ip_interface_get_first_ip_addres (ip_lookup_main_t *lm, u32 sw_if_index,
                                   u8 loop)
{
  ip_interface_address_t * ia = ip_interface_get_first_interface_address (
      lm, sw_if_index, loop);
  return ip_interface_address_get_address (lm, ia);
}

void
del_fwd_entry (lisp_cp_main_t * lcm, u32 src_map_index,
               u32 dst_map_index)
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
  a->iid = 0; // XXX should be part of mapping/eid
  gid_address_copy(&a->deid, &fe->deid);

  vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);

  /* delete entry in fwd table */
  hash_unset(lcm->fwd_entry_by_mapping_index, dst_map_index);
  pool_put(lcm->fwd_entry_pool, fe);
}

void
add_fwd_entry (lisp_cp_main_t* lcm, u32 src_map_index, u32 dst_map_index)
{
  mapping_t * src_map, * dst_map;
  locator_set_t * dst_ls, * src_ls;
  u32 i, minp = ~0;
  locator_t * dl = 0;
  uword * feip = 0;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, * a = &_a;
  memset (a, 0, sizeof(*a));

  /* remove entry if it already exists */
  feip = hash_get (lcm->fwd_entry_by_mapping_index, dst_map_index);
  if (feip)
    del_fwd_entry (lcm, src_map_index, dst_map_index);

  src_map = pool_elt_at_index (lcm->mapping_pool, src_map_index);
  dst_map = pool_elt_at_index (lcm->mapping_pool, dst_map_index);

  /* XXX simple forwarding policy: first lowest (value) priority locator */
  dst_ls = pool_elt_at_index (lcm->locator_set_pool,
                              dst_map->locator_set_index);
  for (i = 0; i < vec_len (dst_ls->locator_indices); i++)
    {
      u32 li = vec_elt (dst_ls->locator_indices, i);
      locator_t * l = pool_elt_at_index (lcm->locator_pool, li);
      if (l->priority < minp && gid_address_type(&l->address) == IP_PREFIX)
        {
          minp = l->priority;
          dl = l;
        }
    }
  if (dl)
    {
      src_ls = pool_elt_at_index (lcm->locator_set_pool,
                                  src_map->locator_set_index);
      for (i = 0; i < vec_len (src_ls->locator_indices); i++)
        {
          u32 li = vec_elt (src_ls->locator_indices, i);
          locator_t * sl = pool_elt_at_index (lcm->locator_pool, li);

          if (ip_addr_version(&gid_address_ip(&dl->address)) == IP4)
            {
              ip4_address_t * l4;
              l4 = ip_interface_get_first_ip_addres (&lcm->im4->lookup_main,
                                                     sl->sw_if_index,
                                                     1 /* unnumbered */);
              ip_addr_v4(&a->slocator) = *l4;
              ip_addr_version(&a->slocator) = IP4;
            }
          else
            {
              ip6_address_t * l6;
              l6 = ip_interface_get_first_ip_addres (&lcm->im6->lookup_main,
                                                     sl->sw_if_index,
                                                     1 /* unnumbered */);
              ip_addr_v6(&a->slocator) = *l6;
              ip_addr_version(&a->slocator) = IP6;
            }
        }
    }
  /* insert data plane forwarding entry */
  u32 sw_if_index;
  a->is_add = 1;
  if (dl)
    a->dlocator = gid_address_ip(&dl->address);
  else
    {
      a->is_negative = 1;
      a->action = dst_map->action;
    }

  gid_address_copy (&a->deid, &dst_map->eid);
  a->iid = 0; // XXX should be part of mapping/eid
  u8 ipver = ip_prefix_version(&gid_address_ippref(&a->deid));
  a->decap_next_index = (ipver == IP4) ?
          LISP_GPE_INPUT_NEXT_IP4_INPUT : LISP_GPE_INPUT_NEXT_IP6_INPUT;
  /* XXX tunnels work only with IP4 now */
  vnet_lisp_gpe_add_del_fwd_entry (a, &sw_if_index);

  /* add tunnel to fwd entry table XXX check return value from DP insertion */
  fwd_entry_t* fe;
  pool_get (lcm->fwd_entry_pool, fe);
  fe->dst_loc = a->dlocator;
  fe->src_loc = a->slocator;
  gid_address_copy (&fe->deid, &a->deid);
  hash_set (lcm->fwd_entry_by_mapping_index, dst_map_index,
            fe - lcm->fwd_entry_pool);
}

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

void
process_map_reply (lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  u32 len = 0, i, ls_index = 0;
  void * h;
  vnet_lisp_add_del_locator_set_args_t _ls_arg, * ls_arg = &_ls_arg;
  vnet_lisp_add_del_mapping_args_t _m_args, * m_args = &_m_args;
  pending_map_request_t * pmr;
  locator_t probed;
  map_reply_hdr_t * mrep_hdr;
  u64 nonce;
  u32 dst_map_index, mi;
  uword * pmr_index;

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
      memset (ls_arg, 0, sizeof(*ls_arg));
      memset (m_args, 0, sizeof(*m_args));

      h = vlib_buffer_get_current (b);
      m_args->ttl = clib_net_to_host_u32 (MAP_REC_TTL(h));
      m_args->action = MAP_REC_ACTION(h);
      m_args->authoritative = MAP_REC_AUTH(h);

      len = lisp_msg_parse_mapping_record (b, &m_args->deid, &ls_arg->locators,
                                           &probed);
      if (len == ~0)
        {
          clib_warning ("Failed to parse mapping record!");
          vec_free(ls_arg->locators);
          return;
        }

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, &m_args->deid);

      /* if mapping already exists, decide if locators (and forwarding) should
       * be updated and be done */
      if (mi != ~0)
        {
          mapping_t * old_map;
          locator_set_t * old_ls;
          old_map = pool_elt_at_index(lcm->mapping_pool, mi);

          /* update mapping attributes */
          old_map->action = m_args->action;
          old_map->authoritative = m_args->authoritative;
          old_map->ttl = m_args->ttl;

          old_ls = pool_elt_at_index(lcm->locator_set_pool,
                                     old_map->locator_set_index);
          /* if the two locators are not equal, update them and forwarding
           * otherwise there's nothing to be done */
          if (compare_locators (lcm, old_ls->locator_indices, ls_arg->locators))
            {
              /* set locator-set index to overwrite */
              ls_arg->is_add = 1;
              ls_arg->index = old_map->locator_set_index;
              vnet_lisp_add_del_locator_set (ls_arg, 0);
              add_fwd_entry (lcm, pmr->src_mapping_index, mi);
            }
        }
      /* new mapping */
      else
        {
          /* add locator-set */
          ls_arg->is_add = 1;
          ls_arg->index = ~0;
          vnet_lisp_add_del_locator_set (ls_arg, &ls_index);

          /* add mapping */
          m_args->is_add = 1;
          m_args->locator_set_index = ls_index;
          vnet_lisp_add_del_mapping (m_args, &dst_map_index);

          /* add forwarding tunnel */
          add_fwd_entry (lcm, pmr->src_mapping_index, dst_map_index);
        }
      vec_free(ls_arg->locators);
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
  gid_address_t * itr_rlocs = 0;

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

  gid_dictionary_init (&lcm->mapping_index_by_gid);
  gid_dictionary_init (&lcm->mapping_index_by_gid);

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp,
                         lisp_cp_input_node.index, 1 /* is_ip4 */);
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp6,
                         lisp_cp_input_node.index, 0 /* is_ip4 */);

  return 0;
}

VLIB_INIT_FUNCTION(lisp_cp_init);
