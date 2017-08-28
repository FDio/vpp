/*
 * Copyright (c) 2016 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or anated to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kp/kp.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/api_errno.h>

//GC runs at most once every so many seconds
#define KP_GARBAGE_RUN 60

//After so many seconds. It is assumed that inter-core race condition will not occur.
#define KP_CONCURRENCY_TIMEOUT 10

kp_main_t kp_main;

#define kp_get_writer_lock() do {} while(__sync_lock_test_and_set (kp_main.writer_lock, 1))
#define kp_put_writer_lock() kp_main.writer_lock[0] = 0

static void kp_as_stack (kp_as_t *as);


const static char * const kp_dpo_nat4_ip4[] = { "kp4-nat4" , NULL };
const static char * const kp_dpo_nat4_ip6[] = { "kp6-nat4" , NULL };
const static char* const * const kp_dpo_nat4_nodes[DPO_PROTO_NUM] =
    {
	[DPO_PROTO_IP4]  = kp_dpo_nat4_ip4,
	[DPO_PROTO_IP6]  = kp_dpo_nat4_ip6,
    };

const static char * const kp_dpo_nat6_ip4[] = { "kp4-nat6" , NULL };
const static char * const kp_dpo_nat6_ip6[] = { "kp6-nat6" , NULL };
const static char* const * const kp_dpo_nat6_nodes[DPO_PROTO_NUM] =
    {
	[DPO_PROTO_IP4]  = kp_dpo_nat6_ip4,
	[DPO_PROTO_IP6]  = kp_dpo_nat6_ip6,
    };

u32 kp_hash_time_now(vlib_main_t * vm)
{
  return (u32) (vlib_time_now(vm) + 10000);
}

u8 *format_kp_main (u8 * s, va_list * args)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  kp_main_t *kpm = &kp_main;
  s = format(s, "kp_main");
  s = format(s, " #vips: %u\n", pool_elts(kpm->vips));
  s = format(s, " #ass: %u\n", pool_elts(kpm->ass) - 1);

  u32 thread_index;
  for(thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++ ) {
    kp_hash_t *h = kpm->per_cpu[thread_index].sticky_ht;
    if (h) {
      s = format(s, "core %d\n", thread_index);
      s = format(s, "  timeout: %ds\n", h->timeout);
      s = format(s, "  usage: %d / %d\n", kp_hash_elts(h, kp_hash_time_now(vlib_get_main())),  kp_hash_size(h));
    }
  }

  return s;
}

static char *kp_vip_type_strings[] = {
    [KP_VIP_TYPE_IP4_NAT44] = "ip4-nat44",
    [KP_VIP_TYPE_IP4_NAT46] = "ip4-nat46",
    [KP_VIP_TYPE_IP6_NAT64] = "ip6-nat64",
    [KP_VIP_TYPE_IP6_NAT66] = "ip6-nat66",
};

u8 *format_kp_vip_type (u8 * s, va_list * args)
{
  kp_vip_type_t vipt = va_arg (*args, kp_vip_type_t);
  u32 i;
  for (i=0; i<KP_VIP_N_TYPES; i++)
    if (vipt == i)
      return format(s, kp_vip_type_strings[i]);
  return format(s, "_WRONG_TYPE_");
}

uword unformat_kp_vip_type (unformat_input_t * input, va_list * args)
{
  kp_vip_type_t *vipt = va_arg (*args, kp_vip_type_t *);
  u32 i;
  for (i=0; i<KP_VIP_N_TYPES; i++)
    if (unformat(input, kp_vip_type_strings[i])) {
      *vipt = i;
      return 1;
    }
  return 0;
}

u8 *format_kp_vip (u8 * s, va_list * args)
{
  kp_vip_t *vip = va_arg (*args, kp_vip_t *);
  return format(s, "%U %U port:%u target_port:%u node_port:%u "
                   "new_size:%u #as:%u%s",
             format_kp_vip_type, vip->type,
             format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
	     ntohs(vip->port), ntohs(vip->target_port),
	     ntohs(vip->node_port),
             vip->new_flow_table_mask + 1,
             pool_elts(vip->as_indexes),
             (vip->flags & KP_VIP_FLAGS_USED)?"":" removed");
}

u8 *format_kp_as (u8 * s, va_list * args)
{
  kp_as_t *as = va_arg (*args, kp_as_t *);
  return format(s, "%U %s", format_ip46_address,
		&as->address, IP46_TYPE_ANY,
		(as->flags & KP_AS_FLAGS_USED)?"used":"removed");
}

u8 *format_kp_vip_detailed (u8 * s, va_list * args)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip = va_arg (*args, kp_vip_t *);
  uword indent = format_get_indent (s);

  s = format(s, "%U %U [%u] %U port:%u target_port:%u node_port:%u%s\n"
                   "%U  new_size:%u\n",
                  format_white_space, indent,
                  format_kp_vip_type, vip->type,
                  vip - kpm->vips, format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
		  ntohs(vip->port), ntohs(vip->target_port),
		  ntohs(vip->node_port),
                  (vip->flags & KP_VIP_FLAGS_USED)?"":" removed",
                  format_white_space, indent,
                  vip->new_flow_table_mask + 1);

  //Print counters
  s = format(s, "%U  counters:\n",
             format_white_space, indent);
  u32 i;
  for (i=0; i<KP_N_VIP_COUNTERS; i++)
    s = format(s, "%U    %s: %d\n",
               format_white_space, indent,
               kpm->vip_counters[i].name,
               vlib_get_simple_counter(&kpm->vip_counters[i], vip - kpm->vips));


  s = format(s, "%U  #as:%u\n",
             format_white_space, indent,
             pool_elts(vip->as_indexes));

  //Let's count the buckets for each AS
  u32 *count = 0;
  vec_validate(count, pool_len(kpm->ass)); //Possibly big alloc for not much...
  kp_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table)
    count[nfe->as_index]++;

  kp_as_t *as;
  u32 *as_index;
  pool_foreach(as_index, vip->as_indexes, {
      as = &kpm->ass[*as_index];
      s = format(s, "%U    %U %d buckets   %d flows  dpo:%u %s\n",
                   format_white_space, indent,
                   format_ip46_address, &as->address, IP46_TYPE_ANY,
                   count[as - kpm->ass],
                   vlib_refcount_get(&kpm->as_refcount, as - kpm->ass),
                   as->dpo.dpoi_index,
                   (as->flags & KP_AS_FLAGS_USED)?"used":" removed");
  });

  vec_free(count);

  /*
  s = format(s, "%U  new flows table:\n", format_white_space, indent);
  kp_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table) {
    s = format(s, "%U    %d: %d\n", format_white_space, indent, nfe - vip->new_flow_table, nfe->as_index);
  }
  */
  return s;
}

typedef struct {
  u32 as_index;
  u32 last;
  u32 skip;
} kp_pseudorand_t;

static int kp_pseudorand_compare(void *a, void *b)
{
  kp_as_t *asa, *asb;
  kp_main_t *kpm = &kp_main;
  asa = &kpm->ass[((kp_pseudorand_t *)a)->as_index];
  asb = &kpm->ass[((kp_pseudorand_t *)b)->as_index];
  return memcmp(&asa->address, &asb->address, sizeof(asb->address));
}

static void kp_vip_garbage_collection(kp_vip_t *vip)
{
  kp_main_t *kpm = &kp_main;
  ASSERT (kpm->writer_lock[0]);

  u32 now = (u32) vlib_time_now(vlib_get_main());
  if (!clib_u32_loop_gt(now, vip->last_garbage_collection + KP_GARBAGE_RUN))
    return;

  vip->last_garbage_collection = now;
  kp_as_t *as;
  u32 *as_index;
  pool_foreach(as_index, vip->as_indexes, {
      as = &kpm->ass[*as_index];
      if (!(as->flags & KP_AS_FLAGS_USED) && //Not used
	  clib_u32_loop_gt(now, as->last_used + KP_CONCURRENCY_TIMEOUT) && //Not recently used
	  (vlib_refcount_get(&kpm->as_refcount, as - kpm->ass) == 0))
	{ //Not referenced
	  fib_entry_child_remove(as->next_hop_fib_entry_index,
				 as->next_hop_child_index);
	  fib_table_entry_delete_index(as->next_hop_fib_entry_index,
				       FIB_SOURCE_RR);
	  as->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;

	  pool_put(vip->as_indexes, as_index);
	  pool_put(kpm->ass, as);
	}
  });
}

void kp_garbage_collection()
{
  kp_main_t *kpm = &kp_main;
  kp_get_writer_lock();
  kp_vip_t *vip;
  u32 *to_be_removed_vips = 0, *i;
  pool_foreach(vip, kpm->vips, {
      kp_vip_garbage_collection(vip);

      if (!(vip->flags & KP_VIP_FLAGS_USED) &&
          (pool_elts(vip->as_indexes) == 0)) {
        vec_add1(to_be_removed_vips, vip - kpm->vips);
      }
  });

  vec_foreach(i, to_be_removed_vips) {
    vip = &kpm->vips[*i];
    pool_put(kpm->vips, vip);
    pool_free(vip->as_indexes);
  }

  vec_free(to_be_removed_vips);
  kp_put_writer_lock();
}

static void kp_vip_update_new_flow_table(kp_vip_t *vip)
{
  kp_main_t *kpm = &kp_main;
  kp_new_flow_entry_t *old_table;
  u32 i, *as_index;
  kp_new_flow_entry_t *new_flow_table = 0;
  kp_as_t *as;
  kp_pseudorand_t *pr, *sort_arr = 0;
  u32 count;

  ASSERT (kpm->writer_lock[0]); //We must have the lock

  //Check if some AS is configured or not
  i = 0;
  pool_foreach(as_index, vip->as_indexes, {
      as = &kpm->ass[*as_index];
      if (as->flags & KP_AS_FLAGS_USED) { //Not used anymore
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
  sort_arr = 0;
  vec_alloc(sort_arr, pool_elts(vip->as_indexes));

  i = 0;
  pool_foreach(as_index, vip->as_indexes, {
      as = &kpm->ass[*as_index];
      if (!(as->flags & KP_AS_FLAGS_USED)) //Not used anymore
        continue;

      sort_arr[i].as_index = as - kpm->ass;
      i++;
  });
  _vec_len(sort_arr) = i;

  vec_sort_with_function(sort_arr, kp_pseudorand_compare);

  //Now let's pseudo-randomly generate permutations
  vec_foreach(pr, sort_arr) {
    kp_as_t *as = &kpm->ass[pr->as_index];

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

//Count number of changed entries
  count = 0;
  for (i=0; i<vec_len(new_flow_table); i++)
    if (vip->new_flow_table == 0 ||
        new_flow_table[i].as_index != vip->new_flow_table[i].as_index)
      count++;

  old_table = vip->new_flow_table;
  vip->new_flow_table = new_flow_table;
  vec_free(old_table);
}

int kp_conf(u32 per_cpu_sticky_buckets, u32 flow_timeout)
{
  kp_main_t *kpm = &kp_main;

  if (!is_pow2(per_cpu_sticky_buckets))
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;

  kp_get_writer_lock(); //Not exactly necessary but just a reminder that it exists for my future self
  kpm->per_cpu_sticky_buckets = per_cpu_sticky_buckets;
  kpm->flow_timeout = flow_timeout;
  kp_put_writer_lock();
  return 0;
}

static
int kp_vip_find_index_with_lock(ip46_address_t *prefix, u8 plen, u32 *vip_index)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip;
  ASSERT (kpm->writer_lock[0]); //This must be called with the lock owned
  ip46_prefix_normalize(prefix, plen);
  pool_foreach(vip, kpm->vips, {
      if ((vip->flags & KP_AS_FLAGS_USED) &&
          vip->plen == plen &&
          vip->prefix.as_u64[0] == prefix->as_u64[0] &&
          vip->prefix.as_u64[1] == prefix->as_u64[1]) {
        *vip_index = vip - kpm->vips;
        return 0;
      }
  });
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int kp_vip_find_index(ip46_address_t *prefix, u8 plen, u32 *vip_index)
{
  int ret;
  kp_get_writer_lock();
  ret = kp_vip_find_index_with_lock(prefix, plen, vip_index);
  kp_put_writer_lock();
  return ret;
}

static int kp_as_find_index_vip(kp_vip_t *vip, ip46_address_t *address, u32 *as_index)
{
  kp_main_t *kpm = &kp_main;
  ASSERT (kpm->writer_lock[0]); //This must be called with the lock owned
  kp_as_t *as;
  u32 *asi;
  pool_foreach(asi, vip->as_indexes, {
      as = &kpm->ass[*asi];
      if (as->vip_index == (vip - kpm->vips) &&
          as->address.as_u64[0] == address->as_u64[0] &&
          as->address.as_u64[1] == address->as_u64[1]) {
        *as_index = as - kpm->ass;
        return 0;
      }
  });
  return -1;
}

int kp_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  kp_main_t *kpm = &kp_main;
  kp_get_writer_lock();
  kp_vip_t *vip;
  if (!(vip = kp_vip_get_by_index(vip_index))) {
    kp_put_writer_lock();
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  ip46_type_t type = kp_vip_is_nat4(vip)?IP46_TYPE_IP4:IP46_TYPE_IP6;
  u32 *to_be_added = 0;
  u32 *to_be_updated = 0;
  u32 i;
  u32 *ip;

  //Sanity check
  while (n--) {

    if (!kp_as_find_index_vip(vip, &addresses[n], &i)) {
      if (kpm->ass[i].flags & KP_AS_FLAGS_USED) {
        vec_free(to_be_added);
        vec_free(to_be_updated);
        kp_put_writer_lock();
        return VNET_API_ERROR_VALUE_EXIST;
      }
      vec_add1(to_be_updated, i);
      goto next;
    }

    if (ip46_address_type(&addresses[n]) != type) {
      vec_free(to_be_added);
      vec_free(to_be_updated);
      kp_put_writer_lock();
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
    kpm->ass[*ip].flags = KP_AS_FLAGS_USED;
  }
  vec_free(to_be_updated);

  //Create those who have to be created
  vec_foreach(ip, to_be_added) {
    kp_as_t *as;
    u32 *as_index;
    pool_get(kpm->ass, as);
    as->address = addresses[*ip];
    as->flags = KP_AS_FLAGS_USED;
    as->vip_index = vip_index;
    pool_get(vip->as_indexes, as_index);
    *as_index = as - kpm->ass;

    /*
     * become a child of the FIB entry
     * so we are informed when its forwarding changes
     */
    fib_prefix_t nh = {};
    if (kp_vip_is_nat4(vip)) {
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
			    kpm->fib_node_type,
			    as - kpm->ass);

    kp_as_stack(as);
  }
  vec_free(to_be_added);

  //Recompute flows
  kp_vip_update_new_flow_table(vip);

  //Garbage collection maybe
  kp_vip_garbage_collection(vip);

  kp_put_writer_lock();
  return 0;
}

int kp_vip_del_ass_withlock(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  kp_main_t *kpm = &kp_main;
  u32 now = (u32) vlib_time_now(vlib_get_main());
  u32 *ip = 0;

  kp_vip_t *vip;
  if (!(vip = kp_vip_get_by_index(vip_index))) {
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  u32 *indexes = NULL;
  while (n--) {
    u32 i;
    if (kp_as_find_index_vip(vip, &addresses[n], &i)) {
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

    vec_add1(indexes, i);
next:
  continue;
  }

  //Garbage collection maybe
  kp_vip_garbage_collection(vip);

  if (indexes != NULL) {
    vec_foreach(ip, indexes) {
      kpm->ass[*ip].flags &= ~KP_AS_FLAGS_USED;
      kpm->ass[*ip].last_used = now;
    }

    //Recompute flows
    kp_vip_update_new_flow_table(vip);
  }

  vec_free(indexes);
  return 0;
}

int kp_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  kp_get_writer_lock();
  int ret = kp_vip_del_ass_withlock(vip_index, addresses, n);
  kp_put_writer_lock();
  return ret;
}

/**
 * Add the VIP adjacency to the ip4 or ip6 fib
 */
static void kp_vip_add_adjacency(kp_main_t *kpm, kp_vip_t *vip)
{
  dpo_proto_t proto = 0;
  dpo_id_t dpo = DPO_INVALID;
  fib_prefix_t pfx = {};
  if (kp_vip_is_ip4(vip)) {
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
  dpo_set(&dpo, kp_vip_is_nat4(vip)?kpm->dpo_nat4_type:kpm->dpo_nat6_type,
      proto, vip - kpm->vips);
  fib_table_entry_special_dpo_add(0,
				  &pfx,
				  FIB_SOURCE_PLUGIN_HI,
				  FIB_ENTRY_FLAG_EXCLUSIVE,
				  &dpo);
  dpo_reset(&dpo);
}

/**
 * Deletes the adjacency associated with the VIP
 */
static void kp_vip_del_adjacency(kp_main_t *kpm, kp_vip_t *vip)
{
  fib_prefix_t pfx = {};
  if (kp_vip_is_ip4(vip)) {
      pfx.fp_addr.ip4 = vip->prefix.ip4;
      pfx.fp_len = vip->plen - 96;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
  } else {
      pfx.fp_addr.ip6 = vip->prefix.ip6;
      pfx.fp_len = vip->plen;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
  }
  fib_table_entry_special_remove(0, &pfx, FIB_SOURCE_PLUGIN_HI);
}

int kp_vip_add(ip46_address_t *prefix, u8 plen, kp_vip_type_t type,
	       u32 new_length, u32 *vip_index,
	       u16 port, u16 target_port, u16 node_port)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip;
  kp_get_writer_lock();
  ip46_prefix_normalize(prefix, plen);

  if (!kp_vip_find_index_with_lock(prefix, plen, vip_index)) {
    kp_put_writer_lock();
    return VNET_API_ERROR_VALUE_EXIST;
  }

  if (!is_pow2(new_length)) {
    kp_put_writer_lock();
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;
  }

  if (ip46_prefix_is_ip4(prefix, plen) &&
      (type != KP_VIP_TYPE_IP4_NAT44) &&
      (type != KP_VIP_TYPE_IP4_NAT46))
    return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;


  //Allocate
  pool_get(kpm->vips, vip);

  //Init
  vip->prefix = *prefix;
  vip->plen = plen;
  vip->port = clib_host_to_net_u16(port);
  vip->target_port = clib_host_to_net_u16(target_port);
  vip->node_port = clib_host_to_net_u16(node_port);
  vip->last_garbage_collection = (u32) vlib_time_now(vlib_get_main());
  vip->type = type;
  vip->flags = KP_VIP_FLAGS_USED;
  vip->as_indexes = 0;

  //Validate counters
  u32 i;
  for (i = 0; i < KP_N_VIP_COUNTERS; i++) {
    vlib_validate_simple_counter(&kpm->vip_counters[i], vip - kpm->vips);
    vlib_zero_simple_counter(&kpm->vip_counters[i], vip - kpm->vips);
  }

  //Configure new flow table
  vip->new_flow_table_mask = new_length - 1;
  vip->new_flow_table = 0;

  //Create a new flow hash table full of the default entry
  kp_vip_update_new_flow_table(vip);

  //Create adjacency to direct traffic
  kp_vip_add_adjacency(kpm, vip);

  //Return result
  *vip_index = vip - kpm->vips;

  kp_put_writer_lock();
  return 0;
}

int kp_vip_del(u32 vip_index)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip;
  kp_get_writer_lock();
  if (!(vip = kp_vip_get_by_index(vip_index))) {
    kp_put_writer_lock();
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  //FIXME: This operation is actually not working
  //We will need to remove state before performing this.

  {
    //Remove all ASs
    ip46_address_t *ass = 0;
    kp_as_t *as;
    u32 *as_index;
    pool_foreach(as_index, vip->as_indexes, {
        as = &kpm->ass[*as_index];
        vec_add1(ass, as->address);
    });
    if (vec_len(ass))
      kp_vip_del_ass_withlock(vip_index, ass, vec_len(ass));
    vec_free(ass);
  }

  //Delete adjacency
  kp_vip_del_adjacency(kpm, vip);

  //Set the VIP as unused
  vip->flags &= ~KP_VIP_FLAGS_USED;

  kp_put_writer_lock();
  return 0;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "kube-proxy",
};
/* *INDENT-ON* */

u8 *format_kp_dpo (u8 * s, va_list * va)
{
  index_t index = va_arg (*va, index_t);
  CLIB_UNUSED(u32 indent) = va_arg (*va, u32);
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip = pool_elt_at_index (kpm->vips, index);
  return format (s, "%U", format_kp_vip, vip);
}

static void kp_dpo_lock (dpo_id_t *dpo) {}
static void kp_dpo_unlock (dpo_id_t *dpo) {}

static fib_node_t *
kp_fib_node_get_node (fib_node_index_t index)
{
  kp_main_t *kpm = &kp_main;
  kp_as_t *as = pool_elt_at_index (kpm->ass, index);
  return (&as->fib_node);
}

static void
kp_fib_node_last_lock_gone (fib_node_t *node)
{
}

static kp_as_t *
kp_as_from_fib_node (fib_node_t *node)
{
  return ((kp_as_t*)(((char*)node) -
      STRUCT_OFFSET_OF(kp_as_t, fib_node)));
}

static void
kp_as_stack (kp_as_t *as)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip = &kpm->vips[as->vip_index];
  dpo_stack(kp_vip_is_nat4(vip)?kpm->dpo_nat4_type:kpm->dpo_nat6_type,
	    kp_vip_is_ip4(vip)?DPO_PROTO_IP4:DPO_PROTO_IP6,
	    &as->dpo,
	    fib_entry_contribute_ip_forwarding(
		as->next_hop_fib_entry_index));
}

static fib_node_back_walk_rc_t
kp_fib_node_back_walk_notify (fib_node_t *node,
			       fib_node_back_walk_ctx_t *ctx)
{
    kp_as_stack(kp_as_from_fib_node(node));
    return (FIB_NODE_BACK_WALK_CONTINUE);
}

clib_error_t *
kp_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  kp_main_t *kpm = &kp_main;
  kp_as_t *default_as;
  fib_node_vft_t kp_fib_node_vft = {
      .fnv_get = kp_fib_node_get_node,
      .fnv_last_lock = kp_fib_node_last_lock_gone,
      .fnv_back_walk = kp_fib_node_back_walk_notify,
  };
  dpo_vft_t kp_vft = {
      .dv_lock = kp_dpo_lock,
      .dv_unlock = kp_dpo_unlock,
      .dv_format = format_kp_dpo,
  };

  kpm->vips = 0;
  kpm->per_cpu = 0;
  vec_validate(kpm->per_cpu, tm->n_vlib_mains - 1);
  kpm->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,  CLIB_CACHE_LINE_BYTES);
  kpm->writer_lock[0] = 0;
  kpm->per_cpu_sticky_buckets = KP_DEFAULT_PER_CPU_STICKY_BUCKETS;
  kpm->flow_timeout = KP_DEFAULT_FLOW_TIMEOUT;
  kpm->dpo_nat4_type = dpo_register_new_type(&kp_vft, kp_dpo_nat4_nodes);
  kpm->dpo_nat6_type = dpo_register_new_type(&kp_vft, kp_dpo_nat6_nodes);
  kpm->fib_node_type = fib_node_register_new_type(&kp_fib_node_vft);

  //Init AS reference counters
  vlib_refcount_init(&kpm->as_refcount);

  //Allocate and init default AS.
  kpm->ass = 0;
  pool_get(kpm->ass, default_as);
  default_as->flags = 0;
  default_as->dpo.dpoi_next_node = KP_NEXT_DROP;
  default_as->vip_index = ~0;
  default_as->address.ip6.as_u64[0] = 0xffffffffffffffffL;
  default_as->address.ip6.as_u64[1] = 0xffffffffffffffffL;

#define _(a,b,c) kpm->vip_counters[c].name = b;
  kp_foreach_vip_counter
#undef _
  return NULL;
}

VLIB_INIT_FUNCTION (kp_init);
