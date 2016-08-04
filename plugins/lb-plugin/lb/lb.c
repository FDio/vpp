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

//GC runs at most once every so many seconds
#define LB_GARBAGE_RUN 60

//After so many seconds. It is assumed that inter-core race condition will not occur.
#define LB_CONCURRENCY_TIMEOUT 10

#define lb_vip_foreach_as(as, vip, body) \
  pool_foreach(as, (vip)->ass, if (as - (vip)->ass != 0) {body})

lb_main_t lb_main;

#define lb_get_writer_lock() do {} while(__sync_lock_test_and_set (lb_main.writer_lock, 1))
#define lb_put_writer_lock() lb_main.writer_lock[0] = 0

u32 lb_hash_time_now(vlib_main_t * vm)
{
  return (u32) (vlib_time_now(vm) + 10000);
}

u8 *format_lb_main (u8 * s, va_list * args)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  lb_main_t *lbm = &lb_main;
  s = format(s, "lb_main");
  s = format(s, " ip4-src-address: %U \n", format_ip4_address, &lbm->ip4_src_address);
  s = format(s, " ip6-src-address: %U \n", format_ip6_address, &lbm->ip6_src_address);
  s = format(s, " #vips: %u\n", pool_elts(lbm->vips));

  u32 cpu_index;
  for(cpu_index = 0; cpu_index < tm->n_vlib_mains; cpu_index++ ) {
    lb_hash_t *h = lbm->per_cpu[cpu_index].sticky_ht;
    if (h) {
      s = format(s, "core %d\n", cpu_index);
      s = format(s, "  timeout: %ds", h->timeout);
      s = format(s, "  usage: %d / %d", lb_hash_elts(h, lb_hash_time_now(vlib_get_main())),  lb_hash_size(h));
    }
  }

  return s;
}

u8 *format_lb_vip (u8 * s, va_list * args)
{
  lb_vip_t *vip = va_arg (*args, lb_vip_t *);
  return format(s, "%U new_size:%u #as:%u",
             format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
             vip->new_flow_table_mask + 1,
             pool_elts(vip->ass) - 1);
}

u8 *format_lb_vip_detailed (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip = va_arg (*args, lb_vip_t *);
  uword indent = format_get_indent (s);

  s = format(s, "%U [%u] %U\n"
                   "%U  new_size:%u\n",
                  format_white_space, indent,
                  vip - lbm->vips, format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
                  format_white_space, indent,
                  vip->new_flow_table_mask + 1);

  //Print counters
  s = format(s, "%U  counters:\n",
             format_white_space, indent);
  u32 i;
  for (i=0; i<LB_N_VIP_COUNTERS; i++)
    s = format(s, "%U    %s: %d\n",
               format_white_space, indent,
               lbm->vip_counters[i].name,
               vlib_get_simple_counter(&lbm->vip_counters[i], vip - lbm->vips));


  s = format(s, "%U  #as:%u\n",
             format_white_space, indent,
             pool_elts(vip->ass) - 1);

  //Let's count the buckets for each AS
  u32 *count = 0;
  vec_validate(count, pool_len(vip->ass));
  lb_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table) {
    count[nfe->as_index]++;
  }

  lb_as_t *as;
  lb_vip_foreach_as(as, vip, {
      s = format(s, "%U    %U %d buckets   %d flows  %s\n", format_white_space, indent,
                   format_ip46_address, &as->address, IP46_TYPE_ANY,
                   count[as - vip->ass],
                   vlib_refcount_get(&vip->as_refcount, as - vip->ass),
                   (as->flags & LB_AS_FLAGS_USED)?"used":"removed");
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

static void lb_vip_garbage_collection(lb_vip_t *vip)
{
  lb_main_t *lbm = &lb_main;
  ASSERT (lbm->writer_lock[0]);

  u32 now = (u32) vlib_time_now(vlib_get_main());
  if (!clib_u32_loop_gt(now, vip->last_garbage_collection + LB_GARBAGE_RUN))
    return;

  vip->last_garbage_collection = now;
  lb_as_t *as;
  lb_vip_foreach_as(as, vip, {
      if (!(as->flags & LB_AS_FLAGS_USED) && //Not used
          clib_u32_loop_gt(now, as->last_used + LB_CONCURRENCY_TIMEOUT) && //Not recently used
          (vlib_refcount_get(&vip->as_refcount, as - vip->ass) == 0)) { //Not referenced
        pool_put(vip->ass, as);
      }
  });
}

static void lb_vip_update_new_flow_table(lb_vip_t *vip)
{
  lb_main_t *lbm = &lb_main;
  lb_new_flow_entry_t *old_table;
  u32 i;
  lb_new_flow_entry_t *new_flow_table = 0;
  lb_as_t *as;
  lb_pseudorand_t *pr, *sort_arr = 0;

  ASSERT (lbm->writer_lock[0]); //We must have the lock
  ASSERT(pool_elts(vip->ass)); //There always is at least the default entry

  if (pool_elts(vip->ass) == 1) {
    //Only the default. i.e. no AS
    vec_validate(new_flow_table, vip->new_flow_table_mask);
    for (i=0; i<vec_len(new_flow_table); i++)
      new_flow_table[i].as_index = 0;

    goto finished;
  }

  //First, let's sort the ASs
  sort_arr = 0;
  vec_alloc(sort_arr, pool_elts(vip->ass) - 1);

  i = 0;
  lb_vip_foreach_as(as, vip,{
     if (!(as->flags & LB_AS_FLAGS_USED)) //Not used anymore
       continue;

     sort_arr[i].as = *as;
     sort_arr[i].as_index = as - vip->ass;
     i++;
  });
  _vec_len(sort_arr) = i;

  vec_sort_with_function(sort_arr, lb_pseudorand_compare);

  //Now let's pseudo-randomly generate permutations
  vec_foreach(pr, sort_arr) {
    u64 seed = clib_xxhash(pr->as.address.as_u64[0] ^
                           pr->as.address.as_u64[1]);
    /* We have 2^n buckets.
     * skip must be prime with 2^n.
     * So skip must be odd.
     * MagLev actually state that M should be prime,
     * but this has a big computation cost (% operation).
     * Using 2^n is more better (& operation).
     */
    pr->skip = ((seed & 0xffffffff) | 1) & vip->new_flow_table_mask;
    pr->last = (seed >> 32) & vip->new_flow_table_mask;
  }

  //Let's create a new flow table
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

  vec_free(sort_arr);

finished:

  old_table = vip->new_flow_table;
  vip->new_flow_table = new_flow_table;
  vec_free(old_table);
}

int lb_conf(ip4_address_t *ip4_address, ip6_address_t *ip6_address,
           u32 per_cpu_sticky_buckets, u32 flow_timeout)
{
  lb_main_t *lbm = &lb_main;
  lb_get_writer_lock(); //Not exactly necessary but just a reminder that it exists for my future self
  lbm->ip4_src_address = *ip4_address;
  lbm->ip6_src_address = *ip6_address;
  lbm->per_cpu_sticky_buckets = per_cpu_sticky_buckets;
  lbm->flow_timeout = flow_timeout;
  lb_put_writer_lock();
  return 0;
}

int lb_vip_find_index(ip46_address_t *prefix, u8 plen, u32 *vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  ASSERT (lbm->writer_lock[0]); //This must be called with the lock owned
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
  lb_main_t *lbm = &lb_main;
  ASSERT (lbm->writer_lock[0]); //This must be called with the lock owned
  lb_as_t *as;
  lb_vip_foreach_as(as, vip, {
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
  lb_get_writer_lock();
  lb_vip_t *vip;
  if (!(vip = lb_vip_get_by_index(vip_index))) {
    lb_put_writer_lock();
    return VNET_LB_ERR_NOT_FOUND;
  }

  ip46_type_t type = lb_vip_is_ip4(vip)?IP46_TYPE_IP4:IP46_TYPE_IP6;
  u32 *to_be_added = 0;
  u32 *to_be_updated = 0;
  u32 i;
  u32 *ip;

  //Sanity check
  while (n--) {

    if (!lb_as_find_index_vip(vip, &addresses[n], &i)) {
      if (vip->ass[i].flags & LB_AS_FLAGS_USED) {
        vec_free(to_be_added);
        vec_free(to_be_updated);
        lb_put_writer_lock();
        return VNET_LB_ERR_EXISTS;
      }
      vec_add1(to_be_updated, i);
      goto next;
    }

    if (ip46_address_type(&addresses[n]) != type) {
      vec_free(to_be_added);
      vec_free(to_be_updated);
      lb_put_writer_lock();
      return VNET_LB_ERR_ADDRESS_TYPE;
    }

    if (n) {
      u32 n2 = n;
      while(n2--) //Check for duplicates
        if (addresses[n2].as_u64[0] == addresses[n].as_u64[0] &&
            addresses[n2].as_u64[1] == addresses[n].as_u64[1])
          goto next;
    }

    vec_add1(to_be_added, n);

next:
    continue;
  }

  //Update reused ASs
  vec_foreach(ip, to_be_updated) {
    vip->ass[*ip].flags = LB_AS_FLAGS_USED;
  }
  vec_free(to_be_updated);

  //Create those who have to be created
  vec_foreach(ip, to_be_added) {
    lb_as_t *as;
    pool_get(vip->ass, as);
    as->address = addresses[*ip];
    as->flags = LB_AS_FLAGS_USED;
  }
  vec_free(to_be_added);

  //Recompute flows
  lb_vip_update_new_flow_table(vip);

  //Garbage collection maybe
  lb_vip_garbage_collection(vip);

  lb_put_writer_lock();
  return 0;
}

int lb_vip_del_ass_withlock(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  u32 now = (u32) vlib_time_now(vlib_get_main());
  u32 *ip = 0;

  lb_vip_t *vip;
  if (!(vip = lb_vip_get_by_index(vip_index))) {
    return VNET_LB_ERR_NOT_FOUND;
  }

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
          goto next;
      }
    }

    vec_add1(indexes, i);
next:
  continue;
  }

  //Garbage collection maybe
  lb_vip_garbage_collection(vip);

  if (indexes != NULL) {
    vec_foreach(ip, indexes) {
      vip->ass[*ip].flags &= ~LB_AS_FLAGS_USED;
      vip->ass[*ip].last_used = now;
    }

    //Recompute flows
    lb_vip_update_new_flow_table(vip);
  }

  vec_free(indexes);
  return 0;
}

int lb_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  lb_get_writer_lock();
  int ret = lb_vip_del_ass_withlock(vip_index, addresses, n);
  lb_put_writer_lock();
  return ret;
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

  ASSERT (lbm->writer_lock[0]); //This must be called with the lock owned

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
  ASSERT (lbm->writer_lock[0]); //This must be called with the lock owned
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

int lb_vip_add(ip46_address_t *prefix, u8 plen, u32 new_length, u32 *vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  lb_as_t *as;
  lb_get_writer_lock();
  ip46_prefix_normalize(prefix, plen);

  if (!lb_vip_find_index(prefix, plen, vip_index)) {
    lb_put_writer_lock();
    return VNET_LB_ERR_EXISTS;
  }

  if (!is_pow2(new_length)) {
    lb_put_writer_lock();
    return VNET_LB_ERR_INVALID_SIZE;
  }

  //Allocate
  pool_get(lbm->vips, vip);

  //Init
  vip->prefix = *prefix;
  vip->plen = plen;
  vip->ass = 0;
  vip->last_garbage_collection = (u32) vlib_time_now(vlib_get_main());

  //Validate counters
  u32 i;
  for (i = 0; i < LB_N_VIP_COUNTERS; i++) {
    vlib_validate_simple_counter(&lbm->vip_counters[i], vip - lbm->vips);
    vlib_zero_simple_counter(&lbm->vip_counters[i], vip - lbm->vips);
  }

  //Allocate and init default AS.
  pool_get(vip->ass, as);
  as->address.ip6.as_u64[0] = 0xffffffffffffffffL;
  as->address.ip6.as_u64[1] = 0xffffffffffffffffL;

  //Configure new flow table
  vip->new_flow_table_mask = new_length - 1;
  vip->new_flow_table = 0; // For now there is no AS, so no flow

  //Create a new flow hash table full of the default entry
  lb_vip_update_new_flow_table(vip);

  //Init reference counters
  vlib_refcount_init(&vip->as_refcount);

  //Create adjacency to direct traffic
  lb_vip_add_adjacency(lbm, vip);

  //Return result
  *vip_index = vip - lbm->vips;

  lb_put_writer_lock();
  return 0;
}

int lb_vip_del(u32 vip_index)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  lb_get_writer_lock();
  if (!(vip = lb_vip_get_by_index(vip_index))) {
    lb_put_writer_lock();
    return VNET_LB_ERR_NOT_FOUND;
  }

  //FIXME: This operation is actually not working
  //We will need to remove state before performing this.

  {
    //Remove all ASs
    //Note: There probably will be a deadlock once we have locks
    ip46_address_t *ass = 0;
    lb_as_t *as;
    lb_vip_foreach_as(as, vip, {
        vec_add1(ass, as->address);
    });
    if (vec_len(ass))
      lb_vip_del_ass_withlock(vip_index, ass, vec_len(ass));
    vec_free(ass);
  }

  //Delete adjacency
  lb_vip_del_adjacency(lbm, vip);

  //TODO: Clean sticky hash table

  //Free new flow table
  vec_free(vip->new_flow_table);

  //Free ASs pool
  pool_free(vip->ass);

  //Free VIP
  pool_put(lbm->vips, vip);

  lb_put_writer_lock();
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
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  lb_main_t *lbm = &lb_main;
  lbm->vips = 0;
  lbm->per_cpu = 0;
  vec_validate(lbm->per_cpu, tm->n_vlib_mains - 1);
  lbm->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,  CLIB_CACHE_LINE_BYTES);
  lbm->writer_lock[0] = 0;
  lbm->per_cpu_sticky_buckets = LB_DEFAULT_PER_CPU_STICKY_BUCKETS;
  lbm->flow_timeout = LB_DEFAULT_FLOW_TIMEOUT;

#define _(a,b,c) lbm->vip_counters[c].name = b;
  lb_foreach_vip_counter
#undef _
  return NULL;
}

VLIB_INIT_FUNCTION (lb_init);
