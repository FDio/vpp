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

#include <lb/lb.h>
#include <vnet/plugin/plugin.h>

lb_main_t lb_main;

u8 *format_lb_vip (u8 * s, va_list * args)
{
  lb_vip_t *vip = va_arg (*args, lb_vip_t *);
  return format(s, "%U new_size:%u sticky_buckets:%u sticky_size:%u #as:%u",
             format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
             vip->new_flow_table_mask + 1,
             vip->sticky_nbuckets,
             vip->sticky_size,
             pool_elts(vip->ass));
}

u8 *format_lb_vip_detailed (u8 * s, va_list * args)
{
  lb_vip_t *vip = va_arg (*args, lb_vip_t *);
  uword indent = format_get_indent (s);

  s = format(s, "%U\n"
                   "%U  new_size:%u sticky_buckets:%u sticky_size:%u\n"
                   "%U  #as:%u\n",
                  format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
                  format_white_space, indent,
                  vip->new_flow_table_mask + 1,
                  vip->sticky_nbuckets,
                  vip->sticky_size,
                  format_white_space, indent,
                  pool_elts(vip->ass));

  //Let's count the buckets for each AS
  u32 *count = 0;
  vec_validate(count, pool_len(vip->ass));
  lb_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table) {
    count[nfe->as_index]++;
  }

  lb_as_t *as;
  pool_foreach(as, vip->ass, {
      s = format(s, "%U    %U %d buckets\n", format_white_space, indent,
                 format_ip46_address, &as->address, IP46_TYPE_ANY,
                 count[as - vip->ass]);
  });

  vec_free(count);

  /*
  s = format(s, "%U  new flows table:\n", format_white_space, indent);
  lb_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table) {
    s = format(s, "%U    %d: %d\n", format_white_space, indent, nfe - vip->new_flow_table, nfe->as_index);
  }
  */
  return s;
}


typedef struct {
  lb_as_t as;
  u32 as_index;
  u32 last;
  u32 skip;
} lb_pseudorand_t;

static int lb_pseudorand_compare(void *a, void *b)
{
  return memcmp(&((lb_pseudorand_t *)a)->as.address,
                &((lb_pseudorand_t *)b)->as.address,
                sizeof(((lb_pseudorand_t *)a)->as.address));
}

static void lb_vip_update_new_flow_table(lb_vip_t *vip)
{
  lb_new_flow_entry_t *old_table;

  if (!pool_elts(vip->ass))
    return;

  //First, let's sort the ASs
  lb_pseudorand_t *pr, *sort_arr = 0;
  vec_alloc(sort_arr, pool_elts(vip->ass));

  u32 i = 0;
  lb_as_t *as;
  pool_foreach(as, vip->ass,{
     sort_arr[i].as = *as;
     sort_arr[i].as_index = as - vip->ass;
     i++;
  });
  _vec_len(sort_arr) = i;

  vec_sort_with_function(sort_arr, lb_pseudorand_compare);

  //Now we can init random the algorithm
  vec_foreach(pr, sort_arr) {
    u64 seed = clib_xxhash(pr->as.address.as_u64[0] ^
                           pr->as.address.as_u64[1]);
    /* We have 2^n buckets.
     * skip must be prime with 2^n.
     * So skip must be odd.
     */
    pr->skip = ((seed & 0xffffffff) | 1) & vip->new_flow_table_mask;
    pr->last = (seed >> 32) & vip->new_flow_table_mask;
  }

  //Let's create a new flow table
  lb_new_flow_entry_t *new_flow_table = 0;
  vec_validate(new_flow_table, vip->new_flow_table_mask);
  for (i=0; i<vec_len(new_flow_table); i++)
    new_flow_table[i].as_index = ~0;

  u32 done = 0;
  while (1) {
    vec_foreach(pr, sort_arr) {
      while (1) {
        u32 last = pr->last;
        pr->last = (pr->last + pr->skip) & vip->new_flow_table_mask;
        if (new_flow_table[last].as_index == ~0) {
          new_flow_table[last].as_index = pr->as_index;
          break;
        }
      }
      done++;
      if (done == vec_len(new_flow_table))
        goto finished;
    }
  }
finished:

  old_table = vip->new_flow_table;
  vip->new_flow_table = new_flow_table;
  vec_free(old_table);
}


int lb_conf(ip4_address_t *ip4_address, ip6_address_t *ip6_address)
{
  lb_main_t *lbm = &lb_main;
  lbm->ip4_src_address = *ip4_address;
  lbm->ip6_src_address = *ip6_address;
  return 0;
}

/**
 * Add the VIP adjacency to the ip4 or ip6 fib
 */
static void lb_vip_add_adjacency(lb_main_t *lbm, lb_vip_t *vip)
{
  ip_adjacency_t adj;
  //Adjacency
  memset (&adj, 0, sizeof (adj));
  adj.explicit_fib_index = ~0;
  lb_adj_data_t *ad = (lb_adj_data_t *) &adj.opaque;
  ad->vip_index = vip - lbm->vips;

  if (lb_vip_is_ip4(vip)) {
    adj.lookup_next_index = lbm->ip4_lookup_next_index;
    ip4_add_del_route_args_t route_args = {};
    ip4_main_t *im4 = &ip4_main;
    route_args.table_index_or_table_id = 0;
    route_args.flags = IP4_ROUTE_FLAG_ADD;
    route_args.dst_address = vip->prefix.ip4;
    route_args.dst_address_length = vip->plen - 96;
    route_args.adj_index = ~0;
    route_args.add_adj = &adj;
    route_args.n_add_adj = 1;
    ip4_add_del_route (im4, &route_args);
  } else {
    adj.lookup_next_index = lbm->ip6_lookup_next_index;
    ip6_add_del_route_args_t route_args = {};
    ip6_main_t *im6 = &ip6_main;
    route_args.table_index_or_table_id = 0;
    route_args.flags = IP6_ROUTE_FLAG_ADD;
    route_args.dst_address = vip->prefix.ip6;
    route_args.dst_address_length = vip->plen;
    route_args.adj_index = ~0;
    route_args.add_adj = &adj;
    route_args.n_add_adj = 1;
    ip6_add_del_route (im6, &route_args);
  }
}

/**
 * Deletes the adjacency associated with the VIP
 */
static void lb_vip_del_adjacency(lb_main_t *lbm, lb_vip_t *vip)
{
  if (lb_vip_is_ip4(vip)) {
    ip4_main_t *im4 = &ip4_main;
    ip4_add_del_route_args_t route_args = {};
    route_args.table_index_or_table_id = 0;
    route_args.flags = IP4_ROUTE_FLAG_DEL;
    route_args.dst_address = vip->prefix.ip4;
    route_args.dst_address_length = vip->plen - 96;
    route_args.adj_index = ~0;
    route_args.add_adj = NULL;
    route_args.n_add_adj = 0;
    ip4_add_del_route (im4, &route_args);
  } else {
    ip6_main_t *im6 = &ip6_main;
    ip6_add_del_route_args_t route_args = {};
    route_args.table_index_or_table_id = 0;
    route_args.flags = IP6_ROUTE_FLAG_DEL;
    route_args.dst_address = vip->prefix.ip6;
    route_args.dst_address_length = vip->plen;
    route_args.adj_index = ~0;
    route_args.add_adj = NULL;
    route_args.n_add_adj = 0;
    ip6_add_del_route (im6, &route_args);
  }
}

int lb_vip_add(ip46_address_t *prefix, u8 plen,
               u32 new_length, u32 sticky_buckets, u32 sticky_size,
               u32 *vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  ip46_prefix_normalize(prefix, plen);

  if (!lb_vip_find_index(prefix, plen, vip_index))
    return VNET_LB_ERR_EXISTS;

  if (!is_pow2(new_length) ||
      !is_pow2(sticky_buckets))
    return VNET_LB_ERR_INVALID_SIZE;

  //Allocate
  pool_get(lbm->vips, vip);

  //Init
  vip->prefix = *prefix;
  vip->plen = plen;
  vip->ass = 0;

  //Configure new flow table
  vip->new_flow_table_mask = new_length - 1;
  vip->new_flow_table = 0; // For now there is no AS, so no flow

  // Create sticky flow table
  vip->sticky_nbuckets = sticky_buckets;
  vip->sticky_size = sticky_size;
  BV (clib_bihash_init) (&vip->sticky_flows_table,
      "sticky flow table",
      vip->sticky_nbuckets, vip->sticky_size);

  //Create adjacency to direct traffic
  lb_vip_add_adjacency(lbm, vip);

  //Return result
  *vip_index = vip - lbm->vips;
  return 0;
}

int lb_vip_del(u32 vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  if (!(vip = lb_vip_get_by_index(vip_index)))
    return VNET_LB_ERR_NOT_FOUND;


  {
    //Remove all ASs
    //Note: There probably will be a deadlock once we have locks
    ip46_address_t *ass = 0;
    lb_as_t *as;
    pool_foreach(as, vip->ass, {
        vec_add1(ass, as->address);
    });
    if (vec_len(ass))
      lb_vip_del_ass(vip_index, ass, vec_len(ass));
    vec_free(ass);
  }

  //Delete adjacency
  lb_vip_del_adjacency(lbm, vip);

  //Destroy sticky flow table
  BV (clib_bihash_free)(&vip->sticky_flows_table);

  //Free new flow table
  vec_free(vip->new_flow_table);

  //Free ASs pool
  pool_free(vip->ass);

  //Free VIP
  pool_put(lbm->vips, vip);

  return 0;
}

int lb_vip_find_index(ip46_address_t *prefix, u8 plen, u32 *vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  ip46_prefix_normalize(prefix, plen);
  pool_foreach(vip, lbm->vips, {
      if (vip->plen == plen &&
          vip->prefix.as_u64[0] == prefix->as_u64[0] &&
          vip->prefix.as_u64[1] == prefix->as_u64[1]) {
        *vip_index = vip - lbm->vips;
        return 0;
      }
  });
  return -1;
}

static int lb_as_find_index_vip(lb_vip_t *vip, ip46_address_t *address, u32 *as_index)
{
  lb_as_t *as;
  pool_foreach(as, vip->ass, {
      if (as->address.as_u64[0] == address->as_u64[0] &&
          as->address.as_u64[1] == address->as_u64[1]) {
        *as_index = as - vip->ass;
        return 0;
      }
  });
  return -1;
}

int lb_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  lb_vip_t *vip;
  if (!(vip = lb_vip_get_by_index(vip_index)))
    return VNET_LB_ERR_NOT_FOUND;

  ip46_type_t type = lb_vip_is_ip4(vip)?IP46_TYPE_IP4:IP46_TYPE_IP6;
  u32 n_s = n;

  //Sanity check
  while (n--) {
    u32 i;
    if (!lb_as_find_index_vip(vip, &addresses[n], &i))
      return VNET_LB_ERR_EXISTS;

    if (n) {
      u32 n2 = n;
      while(n2--) { //Check for duplicates
        if (addresses[n2].as_u64[0] == addresses[n].as_u64[0] &&
            addresses[n2].as_u64[1] == addresses[n].as_u64[1])
          return VNET_LB_ERR_EXISTS;
      }
    }

    if (ip46_address_type(&addresses[n]) != type)
      return VNET_LB_ERR_ADDRESS_TYPE;
  }

  while (n_s--) {
    lb_as_t *as;
    pool_get(vip->ass, as);
    as->address = addresses[n_s];
  }

  //Recompute flows
  lb_vip_update_new_flow_table(vip);

  return 0;
}

int lb_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  lb_vip_t *vip;
  if (!(vip = lb_vip_get_by_index(vip_index)))
    return VNET_LB_ERR_NOT_FOUND;

  u32 *indexes = NULL;
  while (n--) {
    u32 i;
    if (lb_as_find_index_vip(vip, &addresses[n], &i)) {
      vec_free(indexes);
      return VNET_LB_ERR_NOT_FOUND;
    }

    if (n) { //Check for duplicates
      u32 n2 = n - 1;
      while(n2--) {
        if (addresses[n2].as_u64[0] == addresses[n].as_u64[0] &&
            addresses[n2].as_u64[1] == addresses[n].as_u64[1])
          return VNET_LB_ERR_EXISTS;
      }
    }

    vec_add1(indexes, i);
  }

  if (indexes != NULL)
    while (_vec_len(indexes)--)
      pool_put_index(vip->ass, indexes[_vec_len(indexes)]);

  vec_free(indexes);


  //TODO: Do this in the right order (recompute first, free after)
  //Recompute flows
  lb_vip_update_new_flow_table(vip);

  return 0;
}

clib_error_t *
vlib_plugin_register (vlib_main_t * vm,
                      vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  clib_error_t *error = 0;
  return error;
}

clib_error_t *
lb_init (vlib_main_t * vm)
{
  lb_main_t *lbm = &lb_main;

  lbm->vips = 0;
  return NULL;
}

VLIB_INIT_FUNCTION (lb_init);
