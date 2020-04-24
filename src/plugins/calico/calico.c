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

#include <calico/calico.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/api_errno.h>
#include <vnet/udp/udp.h>
#include <vppinfra/lock.h>

//GC runs at most once every so many seconds
#define CALICO_GARBAGE_RUN 60

//After so many seconds. It is assumed that inter-core race condition will not occur.
#define CALICO_CONCURRENCY_TIMEOUT 10

// FIB source for adding routes
static fib_source_t calico_fib_src;

calico_main_t calico_main;

#define calico_get_writer_lock() clib_spinlock_lock (&calico_main.writer_lock)
#define calico_put_writer_lock() clib_spinlock_unlock (&calico_main.writer_lock)

static void calico_as_stack (calico_as_t *as);

const static char * const calico_dpo_nat4_ip4_port[] = { "calico4-nat4-port" , NULL };
const static char* const * const calico_dpo_nat4_port_nodes[DPO_PROTO_NUM] =
    {
        [DPO_PROTO_IP4]  = calico_dpo_nat4_ip4_port,
    };

const static char * const calico_dpo_nat6_ip6_port[] = { "calico6-nat6-port" , NULL };
const static char* const * const calico_dpo_nat6_port_nodes[DPO_PROTO_NUM] =
    {
        [DPO_PROTO_IP6]  = calico_dpo_nat6_ip6_port,
    };

u32 calico_hash_time_now(vlib_main_t * vm)
{
  return (u32) (vlib_time_now(vm) + 10000);
}

u8 *format_calico_main (u8 * s, va_list * args)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  calico_main_t *cam = &calico_main;
  s = format(s, "calico_main");
  s = format(s, " #vips: %u\n", pool_elts(cam->vips));
  s = format(s, " #ass: %u\n", pool_elts(cam->ass) - 1);

  u32 thread_index;
  for(thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++ ) {
    calico_hash_t *h = cam->per_cpu[thread_index].sticky_ht;
    if (h) {
      s = format(s, "core %d\n", thread_index);
      s = format(s, "  timeout: %ds\n", h->timeout);
      s = format(s, "  usage: %d / %d\n", calico_hash_elts(h, calico_hash_time_now(vlib_get_main())),  calico_hash_size(h));
    }
  }

  return s;
}

static char *calico_vip_type_strings[] = {
    [CALICO_VIP_TYPE_IP4_NAT4] = "ip4-nat4",
    [CALICO_VIP_TYPE_IP6_NAT6] = "ip6-nat6",
};

u8 *format_calico_vip_type (u8 * s, va_list * args)
{
  calico_vip_type_t vipt = va_arg (*args, calico_vip_type_t);
  u32 i;
  for (i=0; i<CALICO_VIP_N_TYPES; i++)
    if (vipt == i)
      return format(s, calico_vip_type_strings[i]);
  return format(s, "_WRONG_TYPE_");
}

uword unformat_calico_vip_type (unformat_input_t * input, va_list * args)
{
  calico_vip_type_t *vipt = va_arg (*args, calico_vip_type_t *);
  u32 i;
  for (i=0; i<CALICO_VIP_N_TYPES; i++)
    if (unformat(input, calico_vip_type_strings[i])) {
      *vipt = i;
      return 1;
    }
  return 0;
}

u8 *format_calico_vip (u8 * s, va_list * args)
{
  calico_vip_t *vip = va_arg (*args, calico_vip_t *);
  s = format(s, "%U new_size:%u #as:%u%s",
             format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
             vip->new_flow_table_mask + 1,
             pool_elts(vip->as_indexes),
             (vip->flags & CALICO_VIP_FLAGS_USED)?"":" removed");

  if (vip->port != 0)
    {
      s = format(s, "  protocol:%u port:%u ", vip->protocol, ntohs(vip->port));
    }

  s = format (s, " port:%u target_port:%u",
      ntohs(vip->port), ntohs(vip->target_port));

  return s;
}

u8 *format_calico_as (u8 * s, va_list * args)
{
  calico_as_t *as = va_arg (*args, calico_as_t *);
  return format(s, "%U %s", format_ip46_address,
                &as->address, IP46_TYPE_ANY,
                (as->flags & CALICO_AS_FLAGS_USED)?"used":"removed");
}

u8 *format_calico_vip_detailed (u8 * s, va_list * args)
{
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip = va_arg (*args, calico_vip_t *);
  u32 indent = format_get_indent (s);

  s = format(s, "%U [%lu] %U%s\n"
                   "%U  new_size:%u\n",
                  format_white_space, indent,
                  vip - cam->vips,
                  format_ip46_prefix, &vip->prefix, (u32) vip->plen, IP46_TYPE_ANY,
                  (vip->flags & CALICO_VIP_FLAGS_USED)?"":" removed",
                  format_white_space, indent,
                  vip->new_flow_table_mask + 1);

  if (vip->port != 0)
    {
      s = format(s, "%U  protocol:%u port:%u\n",
                 format_white_space, indent,
                 vip->protocol, ntohs(vip->port));
    }

  s = format (s, "%U  port:%u target_port:%u",
      format_white_space, indent,
      ntohs(vip->port), ntohs(vip->target_port));

  //Print counters
  s = format(s, "%U  counters:\n",
             format_white_space, indent);
  u32 i;
  for (i=0; i<CALICO_N_VIP_COUNTERS; i++)
    s = format(s, "%U    %s: %Lu\n",
               format_white_space, indent,
               cam->vip_counters[i].name,
               vlib_get_simple_counter(&cam->vip_counters[i], vip - cam->vips));


  s = format(s, "%U  #as:%u\n",
             format_white_space, indent,
             pool_elts(vip->as_indexes));

  //Let's count the buckets for each AS
  u32 *count = 0;
  vec_validate(count, pool_len(cam->ass)); //Possibly big alloc for not much...
  calico_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table)
    count[nfe->as_index]++;

  calico_as_t *as;
  u32 *as_index;
  pool_foreach(as_index, vip->as_indexes, {
      as = &cam->ass[*as_index];
      s = format(s, "%U    %U %u buckets   %Lu flows  dpo:%u %s\n",
                   format_white_space, indent,
                   format_ip46_address, &as->address, IP46_TYPE_ANY,
                   count[as - cam->ass],
                   vlib_refcount_get(&cam->as_refcount, as - cam->ass),
                   as->dpo.dpoi_index,
                   (as->flags & CALICO_AS_FLAGS_USED)?"used":" removed");
  });

  vec_free(count);
  return s;
}

typedef struct {
  u32 as_index;
  u32 last;
  u32 skip;
} calico_pseudorand_t;

static int calico_pseudorand_compare(void *a, void *b)
{
  calico_as_t *asa, *asb;
  calico_main_t *cam = &calico_main;
  asa = &cam->ass[((calico_pseudorand_t *)a)->as_index];
  asb = &cam->ass[((calico_pseudorand_t *)b)->as_index];
  return memcmp(&asa->address, &asb->address, sizeof(asb->address));
}

static void calico_vip_garbage_collection(calico_vip_t *vip)
{
  calico_main_t *cam = &calico_main;
  CLIB_SPINLOCK_ASSERT_LOCKED (&cam->writer_lock);

  u32 now = (u32) vlib_time_now(vlib_get_main());
  if (!clib_u32_loop_gt(now, vip->last_garbage_collection + CALICO_GARBAGE_RUN))
    return;

  vip->last_garbage_collection = now;
  calico_as_t *as;
  u32 *as_index;
  pool_foreach(as_index, vip->as_indexes, {
      as = &cam->ass[*as_index];
      if (!(as->flags & CALICO_AS_FLAGS_USED) && //Not used
          clib_u32_loop_gt(now, as->last_used + CALICO_CONCURRENCY_TIMEOUT) &&
          (vlib_refcount_get(&cam->as_refcount, as - cam->ass) == 0))
        { //Not referenced

          fib_entry_child_remove(as->next_hop_fib_entry_index,
                                as->next_hop_child_index);
          fib_table_entry_delete_index(as->next_hop_fib_entry_index,
                                       FIB_SOURCE_RR);
          as->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;

          pool_put(vip->as_indexes, as_index);
          pool_put(cam->ass, as);
        }
  });
}

void calico_garbage_collection()
{
  calico_main_t *cam = &calico_main;
  calico_get_writer_lock();
  calico_vip_t *vip;
  u32 *to_be_removed_vips = 0, *i;
  pool_foreach(vip, cam->vips, {
      calico_vip_garbage_collection(vip);

      if (!(vip->flags & CALICO_VIP_FLAGS_USED) &&
          (pool_elts(vip->as_indexes) == 0)) {
        vec_add1(to_be_removed_vips, vip - cam->vips);
      }
  });

  vec_foreach(i, to_be_removed_vips) {
    vip = &cam->vips[*i];
    pool_put(cam->vips, vip);
    pool_free(vip->as_indexes);
  }

  vec_free(to_be_removed_vips);
  calico_put_writer_lock();
}

static void calico_vip_update_new_flow_table(calico_vip_t *vip)
{
  calico_main_t *cam = &calico_main;
  calico_new_flow_entry_t *old_table;
  u32 i, *as_index;
  calico_new_flow_entry_t *new_flow_table = 0;
  calico_as_t *as;
  calico_pseudorand_t *pr, *sort_arr = 0;

  CLIB_SPINLOCK_ASSERT_LOCKED (&cam->writer_lock); // We must have the lock

  //Check if some AS is configured or not
  i = 0;
  pool_foreach(as_index, vip->as_indexes, {
      as = &cam->ass[*as_index];
      if (as->flags & CALICO_AS_FLAGS_USED) { //Not used anymore
        i = 1;
        goto out; //Not sure 'break' works in this macro-loop
      }
  });

out:
  if (i == 0) {
    //Only the default. i.e. no AS
    vec_validate(new_flow_table, vip->new_flow_table_mask);
    for (i=0; i<vec_len(new_flow_table); i++)
      new_flow_table[i].as_index = 0;

    goto finished;
  }

  //First, let's sort the ASs
  vec_alloc(sort_arr, pool_elts(vip->as_indexes));

  i = 0;
  pool_foreach(as_index, vip->as_indexes, {
      as = &cam->ass[*as_index];
      if (!(as->flags & CALICO_AS_FLAGS_USED)) //Not used anymore
        continue;

      sort_arr[i].as_index = as - cam->ass;
      i++;
  });
  _vec_len(sort_arr) = i;

  vec_sort_with_function(sort_arr, calico_pseudorand_compare);

  //Now let's pseudo-randomly generate permutations
  vec_foreach(pr, sort_arr) {
    calico_as_t *as = &cam->ass[pr->as_index];

    u64 seed = clib_xxhash(as->address.as_u64[0] ^
                           as->address.as_u64[1]);
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
    new_flow_table[i].as_index = 0;

  u32 done = 0;
  while (1) {
    vec_foreach(pr, sort_arr) {
      while (1) {
        u32 last = pr->last;
        pr->last = (pr->last + pr->skip) & vip->new_flow_table_mask;
        if (new_flow_table[last].as_index == 0) {
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
  vec_free(sort_arr);

  old_table = vip->new_flow_table;
  vip->new_flow_table = new_flow_table;
  vec_free(old_table);
}

int calico_conf(u32 per_cpu_sticky_buckets, u32 flow_timeout)
{
  calico_main_t *cam = &calico_main;

  if (!is_pow2(per_cpu_sticky_buckets))
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;

  calico_get_writer_lock(); //Not exactly necessary but just a reminder that it exists for my future self
  cam->per_cpu_sticky_buckets = per_cpu_sticky_buckets;
  cam->flow_timeout = flow_timeout;
  calico_put_writer_lock();
  return 0;
}

int
calico_search_snat6_entry(ip6_address_t *addr, ip6_address_t *notaddr, ip6_address_t *dst, u32 fib_index)
{
  calico_fib6 *table = &calico_main.snat6_fib;
  ip6_address_t *_dst;
  clib_bihash_kv_24_8_t kv, val, nkv;
  u64 fib;
  int i, n_p, rv;
  n_p = vec_len (table->prefix_lengths_in_search_order);
  kv.key[0] = addr->as_u64[0];
  kv.key[1] = addr->as_u64[1];

  nkv.key[0] = notaddr->as_u64[0];
  nkv.key[1] = notaddr->as_u64[1];
  fib = ((u64)((fib_index))<<32);
  /*
    * start search from a mask length same length or shorter.
    * we don't want matches longer than the mask passed
    */
  i = 0;
  for (; i < n_p; i++)
    {
	int dst_address_length = table->prefix_lengths_in_search_order[i];
	ip6_address_t * mask = &ip6_main.fib_masks[dst_address_length];

	ASSERT(dst_address_length >= 0 && dst_address_length <= 128);
	//As lengths are decreasing, masks are increasingly specific.
	kv.key[0] &= mask->as_u64[0];
	kv.key[1] &= mask->as_u64[1];
	kv.key[2] = fib | dst_address_length;
	rv = clib_bihash_search_inline_2_24_8(&table->ip6_hash, &kv, &val);
	if (rv == 0)
	  {
	    _dst = pool_elt_at_index(table->dst_addresses, val.value);
	    clib_memcpy(dst, _dst, sizeof(ip6_address_t));
	    return 0;
	  }

	nkv.key[0] &= mask->as_u64[0];
	nkv.key[1] &= mask->as_u64[1];
	nkv.key[2] = fib | dst_address_length;
	rv = clib_bihash_search_inline_2_24_8(&table->ip6_hash, &nkv, &val);
	if (rv == 0)
	  return -1;
    }
  return -1;
}

static void
calico_compute_prefix_lengths_in_search_order (calico_fib6 *table)
{
    int i;
    vec_reset_length (table->prefix_lengths_in_search_order);
    /* Note: bitmap reversed so this is in fact a longest prefix match */
    clib_bitmap_foreach (i, table->non_empty_dst_address_length_bitmap,
    ({
	int dst_address_length = 128 - i;
	vec_add1(table->prefix_lengths_in_search_order, dst_address_length);
    }));
}

static void
calico_init_fibs() {
  calico_fib6 *table = &calico_main.snat6_fib;
  int i;
  for (i = 0; i < ARRAY_LEN (table->fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	table->fib_masks[i].as_u32[j] = ~0;

      if (i1)
	table->fib_masks[i].as_u32[i0] =
	  clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  clib_bihash_init_24_8 (&table->ip6_hash, "snat prefixes->addr map", CALICO_MAPPING_BUCKETS, CALICO_MAPPING_MEMORY_SIZE);
}

/* This snat's with addr all trafic for which src matches prefix/plen but dest does not */
static int
calico_add_snat6_entry(calico_add_del_snat_args_t *args)
{
  calico_fib6 *table = &calico_main.snat6_fib;
  ip6_address_t *prefix = (ip6_address_t *) &args->prefix;
  clib_bihash_kv_24_8_t kv;
  ip6_address_t *mask, *_addr;
  u32 addr_index;
  u8 len = args->len;
  u64 fib;

  pool_get(table->dst_addresses, _addr);
  addr_index = (_addr - table->dst_addresses);
  clib_memcpy(_addr, &args->target_addr, sizeof(ip6_address_t));

  mask = &ip6_main.fib_masks[len];
  fib = (u64) args->fib_index << 32;

  kv.key[1] = clib_host_to_net_u64(prefix->as_u64[0] & mask->as_u64[0]);
  kv.key[0] = clib_host_to_net_u64(prefix->as_u64[1] & mask->as_u64[1]);
  kv.key[2] = fib | len;
  kv.value = addr_index;
  clib_bihash_add_del_24_8(&table->ip6_hash, &kv, 1 /* is_add */);

  table->dst_address_length_refcounts[len]++;
  table->non_empty_dst_address_length_bitmap = clib_bitmap_set (table->non_empty_dst_address_length_bitmap, 128 - len, 1);
  calico_compute_prefix_lengths_in_search_order (table);

  return 0;
}

static int
calico_del_snat6_entry(calico_add_del_snat_args_t *args)
{
  calico_fib6 *table = &calico_main.snat6_fib;
  ip6_address_t *prefix = (ip6_address_t *) &args->prefix;
  clib_bihash_kv_24_8_t kv, val;
  ip6_address_t *mask, *_addr;
  u64 fib;
  u8 len = args->len;

  mask = &ip6_main.fib_masks[len];
  fib = (u64) args->fib_index << 32;

  kv.key[0] = prefix->as_u64[0] & mask->as_u64[0];
  kv.key[1] = prefix->as_u64[1] & mask->as_u64[1];
  kv.key[2] = fib | args->len;
  if (clib_bihash_search_24_8(&table->ip6_hash, &kv, &val))
    {
      return 1;
    }
  _addr = pool_elt_at_index(table->dst_addresses, val.value);
  pool_put(table->dst_addresses, _addr);
  clib_bihash_add_del_24_8(&table->ip6_hash, &kv, 0 /* is_add */);

  /* refcount accounting */
  ASSERT (table->dst_address_length_refcounts[len] > 0);
  if (--table->dst_address_length_refcounts[len] == 0)
    {
	table->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (table->non_empty_dst_address_length_bitmap,
                              128 - len, 0);
	calico_compute_prefix_lengths_in_search_order (table);
    }
  return 0;
}

int
calico_add_del_snat_entry(calico_add_del_snat_args_t *args, u8 is_add)
{
  if (ip46_address_type(&args->prefix) == IP46_TYPE_IP6)
    {
      if (is_add)
	return calico_add_snat6_entry(args);
      else
	return calico_del_snat6_entry(args);
    }
  else
    {
    	clib_warning("not implented");
    	return -1;
    }
}

static
int calico_vip_port_find_index(ip46_address_t *prefix, u8 plen,
                           u8 protocol, u16 port,
                           calico_lkp_type_t lkp_type,
                           u32 *vip_index)
{
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip;
  /* This must be called with the lock owned */
  CLIB_SPINLOCK_ASSERT_LOCKED (&cam->writer_lock);
  ip46_prefix_normalize(prefix, plen);
  pool_foreach(vip, cam->vips, {
      if ((vip->flags & CALICO_AS_FLAGS_USED) &&
          vip->plen == plen &&
          vip->prefix.as_u64[0] == prefix->as_u64[0] &&
          vip->prefix.as_u64[1] == prefix->as_u64[1])
        {
          if((lkp_type == CALICO_LKP_SAME_IP_PORT &&
               vip->protocol == protocol &&
               vip->port == port) ||
             (lkp_type == CALICO_LKP_ALL_PORT_IP &&
               vip->port == 0) ||
             (lkp_type == CALICO_LKP_DIFF_IP_PORT &&
                (vip->protocol != protocol ||
                vip->port != port) ) )
            {
              *vip_index = vip - cam->vips;
              return 0;
            }
        }
  });
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

static
int calico_vip_port_find_index_with_lock(ip46_address_t *prefix, u8 plen,
                                     u8 protocol, u16 port, u32 *vip_index)
{
  return calico_vip_port_find_index(prefix, plen, protocol, port,
                                CALICO_LKP_SAME_IP_PORT, vip_index);
}

static
int calico_vip_port_find_all_port_vip(ip46_address_t *prefix, u8 plen,
                                  u32 *vip_index)
{
  return calico_vip_port_find_index(prefix, plen, ~0, 0,
                                CALICO_LKP_ALL_PORT_IP, vip_index);
}

/* Find out per-port-vip entry with different protocol and port */
static
int calico_vip_port_find_diff_port(ip46_address_t *prefix, u8 plen,
                               u8 protocol, u16 port, u32 *vip_index)
{
  return calico_vip_port_find_index(prefix, plen, protocol, port,
                                CALICO_LKP_DIFF_IP_PORT, vip_index);
}

int calico_vip_find_index(ip46_address_t *prefix, u8 plen, u8 protocol,
                      u16 port, u32 *vip_index)
{
  int ret;
  calico_get_writer_lock();
  ret = calico_vip_port_find_index_with_lock(prefix, plen,
                                         protocol, port, vip_index);
  calico_put_writer_lock();
  return ret;
}

static int calico_as_find_index_vip(calico_vip_t *vip, ip46_address_t *address, u32 *as_index)
{
  calico_main_t *cam = &calico_main;
  /* This must be called with the lock owned */
  CLIB_SPINLOCK_ASSERT_LOCKED (&cam->writer_lock);
  calico_as_t *as;
  u32 *asi;
  pool_foreach(asi, vip->as_indexes, {
      as = &cam->ass[*asi];
      if (as->vip_index == (vip - cam->vips) &&
          as->address.as_u64[0] == address->as_u64[0] &&
          as->address.as_u64[1] == address->as_u64[1])
      {
        *as_index = as - cam->ass;
        return 0;
      }
  });
  return -1;
}

int calico_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  calico_main_t *cam = &calico_main;
  calico_get_writer_lock();
  calico_vip_t *vip;
  if (!(vip = calico_vip_get_by_index(vip_index))) {
    calico_put_writer_lock();
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  ip46_type_t type = vip->is_ip6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4;
  u32 *to_be_added = 0;
  u32 *to_be_updated = 0;
  u32 i;
  u32 *ip;

  //Sanity check
  while (n--) {

    if (!calico_as_find_index_vip(vip, &addresses[n], &i)) {
      if (cam->ass[i].flags & CALICO_AS_FLAGS_USED) {
        vec_free(to_be_added);
        vec_free(to_be_updated);
        calico_put_writer_lock();
        return VNET_API_ERROR_VALUE_EXIST;
      }
      vec_add1(to_be_updated, i);
      goto next;
    }

    if (ip46_address_type(&addresses[n]) != type) {
      vec_free(to_be_added);
      vec_free(to_be_updated);
      calico_put_writer_lock();
      return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
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
    cam->ass[*ip].flags = CALICO_AS_FLAGS_USED;
  }
  vec_free(to_be_updated);

  //Create those who have to be created
  vec_foreach(ip, to_be_added) {
    calico_as_t *as;
    u32 *as_index;
    pool_get(cam->ass, as);
    as->address = addresses[*ip];
    as->flags = CALICO_AS_FLAGS_USED;
    as->vip_index = vip_index;
    pool_get(vip->as_indexes, as_index);
    *as_index = as - cam->ass;

    /*
     * become a child of the FIB entry
     * so we are informed when its forwarding changes
     */
    fib_prefix_t nh = {};
    if (!vip->is_ip6) {
        nh.fp_addr.ip4 = as->address.ip4;
        nh.fp_len = 32;
        nh.fp_proto = FIB_PROTOCOL_IP4;
    } else {
        nh.fp_addr.ip6 = as->address.ip6;
        nh.fp_len = 128;
        nh.fp_proto = FIB_PROTOCOL_IP6;
    }

    as->next_hop_fib_entry_index =
        fib_table_entry_special_add(0,
                                    &nh,
                                    FIB_SOURCE_RR,
                                    FIB_ENTRY_FLAG_NONE);
    as->next_hop_child_index =
        fib_entry_child_add(as->next_hop_fib_entry_index,
                            cam->fib_node_type,
                            as - cam->ass);

    calico_as_stack(as);

  }
  vec_free(to_be_added);

  //Recompute flows
  calico_vip_update_new_flow_table(vip);

  //Garbage collection maybe
  calico_vip_garbage_collection(vip);

  calico_put_writer_lock();
  return 0;
}

int
calico_flush_vip_as (u32 vip_index, u32 as_index)
{
  u32 thread_index;
  vlib_thread_main_t *tm = vlib_get_thread_main();
  calico_main_t *cam = &calico_main;

  for(thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++ ) {
    calico_hash_t *h = cam->per_cpu[thread_index].sticky_ht;
    if (h != NULL) {
        u32 i;
        calico_hash_bucket_t *b;

        calico_hash_foreach_entry(h, b, i) {
          if ((vip_index == ~0)
              || ((b->vip[i] == vip_index) && (as_index == ~0))
              || ((b->vip[i] == vip_index) && (b->value[i] == as_index)))
            {
              vlib_refcount_add(&cam->as_refcount, thread_index, b->value[i], -1);
              vlib_refcount_add(&cam->as_refcount, thread_index, 0, 1);
              b->vip[i] = ~0;
              b->value[i] = 0;
            }
        }
        if (vip_index == ~0)
          {
            calico_hash_free(h);
            cam->per_cpu[thread_index].sticky_ht = 0;
          }
      }
    }

  return 0;
}

int calico_vip_del_ass_withlock(u32 vip_index, ip46_address_t *addresses, u32 n,
                            u8 flush)
{
  calico_main_t *cam = &calico_main;
  u32 now = (u32) vlib_time_now(vlib_get_main());
  u32 *ip = 0;
  u32 as_index = 0;

  calico_vip_t *vip;
  if (!(vip = calico_vip_get_by_index(vip_index))) {
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  u32 *indexes = NULL;
  while (n--) {
    if (calico_as_find_index_vip(vip, &addresses[n], &as_index)) {
      vec_free(indexes);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

    if (n) { //Check for duplicates
      u32 n2 = n - 1;
      while(n2--) {
        if (addresses[n2].as_u64[0] == addresses[n].as_u64[0] &&
            addresses[n2].as_u64[1] == addresses[n].as_u64[1])
          goto next;
      }
    }

    vec_add1(indexes, as_index);
next:
  continue;
  }

  //Garbage collection maybe
  calico_vip_garbage_collection(vip);

  if (indexes != NULL) {
    vec_foreach(ip, indexes) {
      cam->ass[*ip].flags &= ~CALICO_AS_FLAGS_USED;
      cam->ass[*ip].last_used = now;

      if(flush)
        {
          /* flush flow table for deleted ASs*/
          calico_flush_vip_as(vip_index, *ip);
        }
    }

    //Recompute flows
    calico_vip_update_new_flow_table(vip);
  }

  vec_free(indexes);
  return 0;
}

int calico_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n, u8 flush)
{
  calico_get_writer_lock();
  int ret = calico_vip_del_ass_withlock(vip_index, addresses, n, flush);
  calico_put_writer_lock();

  return ret;
}

static int
calico_vip_prefix_index_alloc (calico_main_t *cam)
{
  /*
   * Check for dynamically allocated instance number.
   */
  u32 bit;

  bit = clib_bitmap_first_clear (cam->vip_prefix_indexes);

  cam->vip_prefix_indexes = clib_bitmap_set(cam->vip_prefix_indexes, bit, 1);

  return bit;
}

static int
calico_vip_prefix_index_free (calico_main_t *cam, u32 instance)
{

  if (clib_bitmap_get (cam->vip_prefix_indexes, instance) == 0)
    {
      return -1;
    }

  cam->vip_prefix_indexes = clib_bitmap_set (cam->vip_prefix_indexes,
                                             instance, 0);

  return 0;
}

/**
 * Add the VIP adjacency to the ip4 or ip6 fib
 */
static void calico_vip_add_adjacency(calico_main_t *cam, calico_vip_t *vip,
                                 u32 *vip_prefix_index)
{
  dpo_proto_t proto = 0;
  dpo_type_t dpo_type = 0;
  u32 vip_idx = 0;

  if (vip->port != 0)
    {
      /* for per-port vip, if VIP adjacency has been added,
       * no need to add adjacency. */
      if (!calico_vip_port_find_diff_port(&(vip->prefix), vip->plen,
                                      vip->protocol, vip->port, &vip_idx))
        {
          calico_vip_t *exists_vip = calico_vip_get_by_index(vip_idx);
          *vip_prefix_index = exists_vip ? exists_vip->vip_prefix_index : ~0;
          return;
        }

      /* Allocate an index for per-port vip */
      *vip_prefix_index = calico_vip_prefix_index_alloc(cam);
    }
  else
    {
      *vip_prefix_index = vip - cam->vips;
    }

  dpo_id_t dpo = DPO_INVALID;
  fib_prefix_t pfx = {};
  if (!vip->is_ip6) {
      pfx.fp_addr.ip4 = vip->prefix.ip4;
      pfx.fp_len = vip->plen - 96;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      proto = DPO_PROTO_IP4;
  } else {
      pfx.fp_addr.ip6 = vip->prefix.ip6;
      pfx.fp_len = vip->plen;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      proto = DPO_PROTO_IP6;
  }

  if (!vip->is_ip6)
    dpo_type = cam->dpo_nat4_port_type;
  else
    dpo_type = cam->dpo_nat6_port_type;

  dpo_set(&dpo, dpo_type, proto, *vip_prefix_index);
  fib_table_entry_special_dpo_add(0,
                                  &pfx,
                                  calico_fib_src,
                                  FIB_ENTRY_FLAG_EXCLUSIVE,
                                  &dpo);
  dpo_reset(&dpo);
}

/**
 * Add the VIP filter entry
 */
static int calico_vip_add_port_filter(calico_main_t *cam, calico_vip_t *vip,
                                  u32 vip_prefix_index, u32 vip_idx)
{
  vip_port_key_t key;
  clib_bihash_kv_8_8_t kv;

  key.vip_prefix_index = vip_prefix_index;
  key.protocol = vip->protocol;
  key.port = vip->port;
  key.rsv = 0;

  kv.key = key.as_u64;
  kv.value = vip_idx;
  clib_bihash_add_del_8_8(&cam->vip_index_per_port, &kv, 1);

  return 0;
}

/**
 * Del the VIP filter entry
 */
static int calico_vip_del_port_filter(calico_main_t *cam, calico_vip_t *vip)
{
  vip_port_key_t key;
  clib_bihash_kv_8_8_t kv, value;
  calico_vip_t *m = 0;

  key.vip_prefix_index = vip->vip_prefix_index;
  key.protocol = vip->protocol;
  key.port = vip->port;
  key.rsv = 0;

  kv.key = key.as_u64;
  if(clib_bihash_search_8_8(&cam->vip_index_per_port, &kv, &value) != 0)
    {
      clib_warning("looking up vip_index_per_port failed.");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  m = pool_elt_at_index (cam->vips, value.value);
  ASSERT (m);

  kv.value = m - cam->vips;
  clib_bihash_add_del_8_8(&cam->vip_index_per_port, &kv, 0);

  return 0;
}

/**
 * Deletes the adjacency associated with the VIP
 */
static void calico_vip_del_adjacency(calico_main_t *cam, calico_vip_t *vip)
{
  fib_prefix_t pfx = {};
  u32 vip_idx = 0;

  if (vip->port != 0)
    {
      /* If this vip adjacency is used by other per-port vip,
       * no need to del this adjacency. */
      if (!calico_vip_port_find_diff_port(&(vip->prefix), vip->plen,
                                      vip->protocol, vip->port, &vip_idx))
        {
          calico_put_writer_lock();
          return;
        }

      /* Return vip_prefix_index for per-port vip */
      calico_vip_prefix_index_free(cam, vip->vip_prefix_index);

    }

  if (!vip->is_ip6) {
      pfx.fp_addr.ip4 = vip->prefix.ip4;
      pfx.fp_len = vip->plen - 96;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
  } else {
      pfx.fp_addr.ip6 = vip->prefix.ip6;
      pfx.fp_len = vip->plen;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
  }
  fib_table_entry_special_remove(0, &pfx, calico_fib_src);
}

int calico_vip_add(calico_vip_add_args_t args, u32 *vip_index)
{
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip;
  u32 vip_prefix_index = 0;
  u8 is_ip6 = !ip46_prefix_is_ip4(&(args.prefix), args.plen);

  calico_get_writer_lock();
  ip46_prefix_normalize(&(args.prefix), args.plen);

  if (!calico_vip_port_find_index_with_lock(&(args.prefix), args.plen,
                                         args.protocol, args.port,
                                         vip_index))
    {
      calico_put_writer_lock();
      return VNET_API_ERROR_VALUE_EXIST;
    }

  /* Make sure we can't add a per-port VIP entry
   * when there already is an all-port VIP for the same prefix. */
  if ((args.port != 0) &&
      !calico_vip_port_find_all_port_vip(&(args.prefix), args.plen, vip_index))
    {
      calico_put_writer_lock();
      return VNET_API_ERROR_VALUE_EXIST;
    }

  /* Make sure we can't add a all-port VIP entry
   * when there already is an per-port VIP for the same prefix. */
  if ((args.port == 0) &&
      !calico_vip_port_find_diff_port(&(args.prefix), args.plen,
                                  args.protocol, args.port, vip_index))
    {
      calico_put_writer_lock();
      return VNET_API_ERROR_VALUE_EXIST;
    }

  /* Make sure all VIP for a given prefix (using different ports) have the same type. */
  if ((args.port != 0) &&
      !calico_vip_port_find_diff_port(&(args.prefix), args.plen,
                                  args.protocol, args.port, vip_index)
      && (is_ip6 != cam->vips[*vip_index].is_ip6))
    {
      calico_put_writer_lock();
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (!is_pow2(args.new_length)) {
    calico_put_writer_lock();
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;
  }

  //Allocate
  pool_get(cam->vips, vip);

  //Init
  memcpy (&(vip->prefix), &(args.prefix), sizeof(args.prefix));
  vip->plen = args.plen;
  if (args.port != 0)
    {
      vip->protocol = args.protocol;
      vip->port = args.port;
    }
  else
    {
      vip->protocol = (u8)~0;
      vip->port = 0;
    }
  vip->last_garbage_collection = (u32) vlib_time_now(vlib_get_main());
  vip->is_ip6 = is_ip6;

  vip->target_port = args.target_port;

  vip->flags = CALICO_VIP_FLAGS_USED;
  vip->as_indexes = 0;

  //Validate counters
  u32 i;
  for (i = 0; i < CALICO_N_VIP_COUNTERS; i++) {
    vlib_validate_simple_counter(&cam->vip_counters[i], vip - cam->vips);
    vlib_zero_simple_counter(&cam->vip_counters[i], vip - cam->vips);
  }

  //Configure new flow table
  vip->new_flow_table_mask = args.new_length - 1;
  vip->new_flow_table = 0;

  //Update flow hash table
  calico_vip_update_new_flow_table(vip);

  //Create adjacency to direct traffic
  calico_vip_add_adjacency(cam, vip, &vip_prefix_index);

  *vip_index = vip - cam->vips;
  //Create per-port vip filtering table
  if (args.port != 0)
    {
      calico_vip_add_port_filter(cam, vip, vip_prefix_index, *vip_index);
      vip->vip_prefix_index = vip_prefix_index;
    }

  calico_put_writer_lock();
  return 0;
}

int calico_vip_del(u32 vip_index)
{
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip;
  int rv = 0;

  /* Does not remove default vip, i.e. vip_index = 0 */
  if (vip_index == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  calico_get_writer_lock();
  if (!(vip = calico_vip_get_by_index(vip_index))) {
    calico_put_writer_lock();
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  //FIXME: This operation is actually not working
  //We will need to remove state before performing this.

  {
    //Remove all ASs
    ip46_address_t *ass = 0;
    calico_as_t *as;
    u32 *as_index;

    pool_foreach(as_index, vip->as_indexes, {
        as = &cam->ass[*as_index];
        vec_add1(ass, as->address);
    });
    if (vec_len(ass))
      calico_vip_del_ass_withlock(vip_index, ass, vec_len(ass), 0);
    vec_free(ass);
  }

  //Delete adjacency
  calico_vip_del_adjacency(cam, vip);

  //Delete per-port vip filtering entry
  if (vip->port != 0)
    {
      rv = calico_vip_del_port_filter(cam, vip);
    }

  //Set the VIP as unused
  vip->flags &= ~CALICO_VIP_FLAGS_USED;

  calico_put_writer_lock();
  return rv;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Load Balancer (LB)",
};
/* *INDENT-ON* */

u8 *format_calico_dpo (u8 * s, va_list * va)
{
  index_t index = va_arg (*va, index_t);
  CLIB_UNUSED(u32 indent) = va_arg (*va, u32);
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip = pool_elt_at_index (cam->vips, index);
  return format (s, "%U", format_calico_vip, vip);
}

static void calico_dpo_lock (dpo_id_t *dpo) {}
static void calico_dpo_unlock (dpo_id_t *dpo) {}

static fib_node_t *
calico_fib_node_get_node (fib_node_index_t index)
{
  calico_main_t *cam = &calico_main;
  calico_as_t *as = pool_elt_at_index (cam->ass, index);
  return (&as->fib_node);
}

static void
calico_fib_node_last_lock_gone (fib_node_t *node)
{
}

static calico_as_t *
calico_as_from_fib_node (fib_node_t *node)
{
  return ((calico_as_t*)(((char*)node) -
      STRUCT_OFFSET_OF(calico_as_t, fib_node)));
}

static void
calico_as_stack (calico_as_t *as)
{
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip = &cam->vips[as->vip_index];
  dpo_type_t dpo_type = 0;

  if (!vip->is_ip6)
    dpo_type = cam->dpo_nat4_port_type;
  else
    dpo_type = cam->dpo_nat6_port_type;

  dpo_stack(dpo_type,
            vip->is_ip6 ? DPO_PROTO_IP6 : DPO_PROTO_IP4,
            &as->dpo,
            fib_entry_contribute_ip_forwarding(
                as->next_hop_fib_entry_index));
}

static fib_node_back_walk_rc_t
calico_fib_node_back_walk_notify (fib_node_t *node,
                 fib_node_back_walk_ctx_t *ctx)
{
    calico_as_stack(calico_as_from_fib_node(node));
    return (FIB_NODE_BACK_WALK_CONTINUE);
}

int calico_nat4_interface_add_del (u32 sw_if_index, int is_del)
{
  if (is_del)
    {
      vnet_feature_enable_disable ("ip4-unicast", "calico-nat4-in2out",
                                   sw_if_index, 0, 0, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-unicast", "calico-nat4-in2out",
                                   sw_if_index, 1, 0, 0);
    }

  return 0;
}

int calico_nat6_interface_add_del (u32 sw_if_index, int is_del)
{
  if (is_del)
    {
      vnet_feature_enable_disable ("ip6-output", "calico-nat6-in2out",
                                   sw_if_index, 0, 0, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip6-output", "calico-nat6-in2out",
                                   sw_if_index, 1, 0, 0);
    }

  return 0;
}

clib_error_t *
calico_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  calico_main_t *cam = &calico_main;
  cam->vnet_main = vnet_get_main ();
  cam->vlib_main = vm;

  calico_vip_t *default_vip;
  calico_as_t *default_as;
  fib_node_vft_t calico_fib_node_vft = {
      .fnv_get = calico_fib_node_get_node,
      .fnv_last_lock = calico_fib_node_last_lock_gone,
      .fnv_back_walk = calico_fib_node_back_walk_notify,
  };
  dpo_vft_t calico_vft = {
      .dv_lock = calico_dpo_lock,
      .dv_unlock = calico_dpo_unlock,
      .dv_format = format_calico_dpo,
  };

  //Allocate and init default VIP.
  cam->vips = 0;
  pool_get(cam->vips, default_vip);
  default_vip->new_flow_table_mask = 0;
  default_vip->prefix.ip6.as_u64[0] = 0xffffffffffffffffL;
  default_vip->prefix.ip6.as_u64[1] = 0xffffffffffffffffL;
  default_vip->protocol = ~0;
  default_vip->port = 0;
  default_vip->flags = CALICO_VIP_FLAGS_USED;

  cam->per_cpu = 0;
  vec_validate(cam->per_cpu, tm->n_vlib_mains - 1);
  clib_spinlock_init (&cam->writer_lock);
  cam->per_cpu_sticky_buckets = CALICO_DEFAULT_PER_CPU_STICKY_BUCKETS;
  cam->flow_timeout = CALICO_DEFAULT_FLOW_TIMEOUT;
  cam->dpo_nat4_port_type = dpo_register_new_type(&calico_vft,
                                                  calico_dpo_nat4_port_nodes);
  cam->dpo_nat6_port_type = dpo_register_new_type(&calico_vft,
                                                  calico_dpo_nat6_port_nodes);
  cam->fib_node_type = fib_node_register_new_type(&calico_fib_node_vft);

  //Init AS reference counters
  vlib_refcount_init(&cam->as_refcount);

  //Allocate and init default AS.
  cam->ass = 0;
  pool_get(cam->ass, default_as);
  default_as->flags = 0;
  default_as->dpo.dpoi_next_node = CALICO_NEXT_DROP;
  default_as->vip_index = ~0;
  default_as->address.ip6.as_u64[0] = 0xffffffffffffffffL;
  default_as->address.ip6.as_u64[1] = 0xffffffffffffffffL;

  /* Generate a valid flow table for default VIP */
  default_vip->as_indexes = NULL;
  calico_get_writer_lock();
  calico_vip_update_new_flow_table(default_vip);
  calico_put_writer_lock();

  clib_bihash_init_8_8 (&cam->vip_index_per_port,
                        "vip_index_per_port", CALICO_VIP_PER_PORT_BUCKETS,
                        CALICO_VIP_PER_PORT_MEMORY_SIZE);

  clib_bihash_init_40_8 (&cam->return_path_5tuple_map,
                        "return_path_5tuple_map", CALICO_MAPPING_BUCKETS,
                        CALICO_MAPPING_MEMORY_SIZE);

  calico_init_fibs();

#define _(a,b,c) cam->vip_counters[c].name = b;
  calico_foreach_vip_counter
#undef _

  calico_fib_src = fib_source_allocate("calico",
                                   FIB_SOURCE_PRIORITY_HI,
                                   FIB_SOURCE_BH_SIMPLE);

  return NULL;
}

VLIB_INIT_FUNCTION (calico_init);
