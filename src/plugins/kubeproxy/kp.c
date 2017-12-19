/*
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or anated to in writing, software
 * distributed under the License is distributed on an "POD IS" BPODIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kubeproxy/kp.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/api_errno.h>
#include <vnet/udp/udp.h>

//GC runs at most once every so many seconds
#define KP_GARBAGE_RUN 60

//After so many seconds. It is assumed that inter-core race condition will not occur.
#define KP_CONCURRENCY_TIMEOUT 10

kp_main_t kp_main;

#define kp_get_writer_lock() do {} while(__sync_lock_test_and_set (kp_main.writer_lock, 1))
#define kp_put_writer_lock() kp_main.writer_lock[0] = 0

static void kp_pod_stack (kp_pod_t *pod);

void ip46_prefix_normalize(ip46_address_t *prefix, u8 plen)
{
  if (plen == 0) {
    prefix->as_u64[0] = 0;
    prefix->as_u64[1] = 0;
  } else if (plen <= 64) {
    prefix->as_u64[0] &= clib_host_to_net_u64(0xffffffffffffffffL << (64 - plen));
    prefix->as_u64[1] = 0;
  } else {
    prefix->as_u64[1] &= clib_host_to_net_u64(0xffffffffffffffffL << (128 - plen));
  }

}

uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}

u8 *format_ip46_prefix (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u32 len = va_arg (*args, u32); //va_arg cannot use u8 or u16
  ip46_type_t type = va_arg (*args, ip46_type_t);

  int is_ip4 = 0;
  if (type == IP46_TYPE_IP4)
    is_ip4 = 1;
  else if (type == IP46_TYPE_IP6)
    is_ip4 = 0;
  else
    is_ip4 = (len >= 96) && ip46_address_is_ip4(ip46);

  return is_ip4 ?
      format(s, "%U/%d", format_ip4_address, &ip46->ip4, len - 96):
      format(s, "%U/%d", format_ip6_address, &ip46->ip6, len);
}

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
  s = format(s, " #pods: %u\n", pool_elts(kpm->pods) - 1);

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
                   "new_size:%u #pod:%u%s",
             format_kp_vip_type, vip->type,
             format_ip46_prefix, &vip->prefix, vip->plen, IP46_TYPE_ANY,
	     ntohs(vip->port), ntohs(vip->target_port),
	     ntohs(vip->node_port),
             vip->new_flow_table_mask + 1,
             pool_elts(vip->pod_indexes),
             (vip->flags & KP_VIP_FLAGS_USED)?"":" removed");
}

u8 *format_kp_pod (u8 * s, va_list * args)
{
  kp_pod_t *pod = va_arg (*args, kp_pod_t *);
  return format(s, "%U %s", format_ip46_address,
		&pod->address, IP46_TYPE_ANY,
		(pod->flags & KP_POD_FLAGS_USED)?"used":"removed");
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


  s = format(s, "%U  #pod:%u\n",
             format_white_space, indent,
             pool_elts(vip->pod_indexes));

  //Let's count the buckets for each POD
  u32 *count = 0;
  vec_validate(count, pool_len(kpm->pods)); //Possibly big alloc for not much...
  kp_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table)
    count[nfe->pod_index]++;

  kp_pod_t *pod;
  u32 *pod_index;
  pool_foreach(pod_index, vip->pod_indexes, {
      pod = &kpm->pods[*pod_index];
      s = format(s, "%U    %U %d buckets   %d flows  dpo:%u %s\n",
                   format_white_space, indent,
                   format_ip46_address, &pod->address, IP46_TYPE_ANY,
                   count[pod - kpm->pods],
                   vlib_refcount_get(&kpm->pod_refcount, pod - kpm->pods),
                   pod->dpo.dpoi_index,
                   (pod->flags & KP_POD_FLAGS_USED)?"used":" removed");
  });

  vec_free(count);

  /*
  s = format(s, "%U  new flows table:\n", format_white_space, indent);
  kp_new_flow_entry_t *nfe;
  vec_foreach(nfe, vip->new_flow_table) {
    s = format(s, "%U    %d: %d\n", format_white_space, indent, nfe - vip->new_flow_table, nfe->pod_index);
  }
  */
  return s;
}

typedef struct {
  u32 pod_index;
  u32 last;
  u32 skip;
} kp_pseudorand_t;

static int kp_pseudorand_compare(void *a, void *b)
{
  kp_pod_t *poda, *podb;
  kp_main_t *kpm = &kp_main;
  poda = &kpm->pods[((kp_pseudorand_t *)a)->pod_index];
  podb = &kpm->pods[((kp_pseudorand_t *)b)->pod_index];
  return memcmp(&poda->address, &podb->address, sizeof(podb->address));
}

static void kp_vip_garbage_collection(kp_vip_t *vip)
{
  kp_main_t *kpm = &kp_main;
  ASSERT (kpm->writer_lock[0]);

  u32 now = (u32) vlib_time_now(vlib_get_main());
  if (!clib_u32_loop_gt(now, vip->last_garbage_collection + KP_GARBAGE_RUN))
    return;

  vip->last_garbage_collection = now;
  kp_pod_t *pod;
  u32 *pod_index;
  pool_foreach(pod_index, vip->pod_indexes, {
      pod = &kpm->pods[*pod_index];
      if (!(pod->flags & KP_POD_FLAGS_USED) && //Not used
	  clib_u32_loop_gt(now, pod->last_used + KP_CONCURRENCY_TIMEOUT) && //Not recently used
	  (vlib_refcount_get(&kpm->pod_refcount, pod - kpm->pods) == 0))
	{ //Not referenced
	  fib_entry_child_remove(pod->next_hop_fib_entry_index,
				 pod->next_hop_child_index);
	  fib_table_entry_delete_index(pod->next_hop_fib_entry_index,
				       FIB_SOURCE_RR);
	  pod->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;

	  pool_put(vip->pod_indexes, pod_index);
	  pool_put(kpm->pods, pod);
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
          (pool_elts(vip->pod_indexes) == 0)) {
        vec_add1(to_be_removed_vips, vip - kpm->vips);
      }
  });

  vec_foreach(i, to_be_removed_vips) {
    vip = &kpm->vips[*i];
    pool_put(kpm->vips, vip);
    pool_free(vip->pod_indexes);
  }

  vec_free(to_be_removed_vips);
  kp_put_writer_lock();
}

static void kp_vip_update_new_flow_table(kp_vip_t *vip)
{
  kp_main_t *kpm = &kp_main;
  kp_new_flow_entry_t *old_table;
  u32 i, *pod_index;
  kp_new_flow_entry_t *new_flow_table = 0;
  kp_pod_t *pod;
  kp_pseudorand_t *pr, *sort_arr = 0;
  u32 count;

  ASSERT (kpm->writer_lock[0]); //We must have the lock

  //Check if some POD is configured or not
  i = 0;
  pool_foreach(pod_index, vip->pod_indexes, {
      pod = &kpm->pods[*pod_index];
      if (pod->flags & KP_POD_FLAGS_USED) { //Not used anymore
        i = 1;
        goto out; //Not sure 'break' works in this macro-loop
      }
  });

out:
  if (i == 0) {
    //Only the default. i.e. no POD
    vec_validate(new_flow_table, vip->new_flow_table_mask);
    for (i=0; i<vec_len(new_flow_table); i++)
      new_flow_table[i].pod_index = 0;

    goto finished;
  }

  //First, let's sort the PODs
  sort_arr = 0;
  vec_alloc(sort_arr, pool_elts(vip->pod_indexes));

  i = 0;
  pool_foreach(pod_index, vip->pod_indexes, {
      pod = &kpm->pods[*pod_index];
      if (!(pod->flags & KP_POD_FLAGS_USED)) //Not used anymore
        continue;

      sort_arr[i].pod_index = pod - kpm->pods;
      i++;
  });
  _vec_len(sort_arr) = i;

  vec_sort_with_function(sort_arr, kp_pseudorand_compare);

  //Now let's pseudo-randomly generate permutations
  vec_foreach(pr, sort_arr) {
    kp_pod_t *pod = &kpm->pods[pr->pod_index];

    u64 seed = clib_xxhash(pod->address.as_u64[0] ^
                           pod->address.as_u64[1]);
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
    new_flow_table[i].pod_index = ~0;

  u32 done = 0;
  while (1) {
    vec_foreach(pr, sort_arr) {
      while (1) {
        u32 last = pr->last;
        pr->last = (pr->last + pr->skip) & vip->new_flow_table_mask;
        if (new_flow_table[last].pod_index == ~0) {
          new_flow_table[last].pod_index = pr->pod_index;
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
        new_flow_table[i].pod_index != vip->new_flow_table[i].pod_index)
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
      if ((vip->flags & KP_POD_FLAGS_USED) &&
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

static int kp_pod_find_index_vip(kp_vip_t *vip, ip46_address_t *address, u32 *pod_index)
{
  kp_main_t *kpm = &kp_main;
  ASSERT (kpm->writer_lock[0]); //This must be called with the lock owned
  kp_pod_t *pod;
  u32 *podi;
  pool_foreach(podi, vip->pod_indexes, {
      pod = &kpm->pods[*podi];
      if (pod->vip_index == (vip - kpm->vips) &&
          pod->address.as_u64[0] == address->as_u64[0] &&
          pod->address.as_u64[1] == address->as_u64[1]) {
        *pod_index = pod - kpm->pods;
        return 0;
      }
  });
  return -1;
}

int kp_vip_add_pods(u32 vip_index, ip46_address_t *addresses, u32 n)
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
  kp_snat_mapping_t *m;
  kp_snat4_key_t m_key4;
  clib_bihash_kv_8_8_t kv;

  //Sanity check
  while (n--) {

    if (!kp_pod_find_index_vip(vip, &addresses[n], &i)) {
      if (kpm->pods[i].flags & KP_POD_FLAGS_USED) {
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

  //Update reused PODs
  vec_foreach(ip, to_be_updated) {
    kpm->pods[*ip].flags = KP_POD_FLAGS_USED;
  }
  vec_free(to_be_updated);

  //Create those who have to be created
  vec_foreach(ip, to_be_added) {
    kp_pod_t *pod;
    u32 *pod_index;
    pool_get(kpm->pods, pod);
    pod->address = addresses[*ip];
    pod->flags = KP_POD_FLAGS_USED;
    pod->vip_index = vip_index;
    pool_get(vip->pod_indexes, pod_index);
    *pod_index = pod - kpm->pods;

    /*
     * become a child of the FIB entry
     * so we are informed when its forwarding changes
     */
    fib_prefix_t nh = {};
    if (kp_vip_is_nat4(vip)) {
	nh.fp_addr.ip4 = pod->address.ip4;
	nh.fp_len = 32;
	nh.fp_proto = FIB_PROTOCOL_IP4;
    } else {
	nh.fp_addr.ip6 = pod->address.ip6;
	nh.fp_len = 128;
	nh.fp_proto = FIB_PROTOCOL_IP6;
    }

    pod->next_hop_fib_entry_index =
	fib_table_entry_special_add(0,
				    &nh,
				    FIB_SOURCE_RR,
				    FIB_ENTRY_FLAG_NONE);
    pod->next_hop_child_index =
	fib_entry_child_add(pod->next_hop_fib_entry_index,
			    kpm->fib_node_type,
			    pod - kpm->pods);

    kp_pod_stack(pod);

    /* Add SNAT static mapping */
    pool_get (kpm->snat_mappings, m);
    memset (m, 0, sizeof (*m));
    if (kp_vip_is_nat4(vip)) {
	m_key4.addr = pod->address.ip4;
	m_key4.port = vip->target_port;
	m_key4.protocol = 0;
	m_key4.fib_index = 0;

        m->vip.ip4 = vip->prefix.ip4;;
        m->node_ip.ip4.as_u32 = 0;
        m->pod_ip.ip4 = pod->address.ip4;
        m->vip_is_ipv6 = 0;
        m->node_ip_is_ipv6 = 0;
        m->pod_ip_is_ipv6 = 0;
        m->port = vip->port;
        m->node_port = vip->node_port;
        m->target_port = vip->target_port;
	m->vrf_id = 0;
	m->fib_index = 0;

	kv.key = m_key4.as_u64;
	kv.value = m - kpm->snat_mappings;
	clib_bihash_add_del_8_8(&kpm->mapping_by_pod, &kv, 1);
    } else {
	/* TBD */
    }

  }
  vec_free(to_be_added);

  //Recompute flows
  kp_vip_update_new_flow_table(vip);

  //Garbage collection maybe
  kp_vip_garbage_collection(vip);

  kp_put_writer_lock();
  return 0;
}

int kp_vip_del_pods_withlock(u32 vip_index, ip46_address_t *addresses, u32 n)
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
    if (kp_pod_find_index_vip(vip, &addresses[n], &i)) {
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
      kpm->pods[*ip].flags &= ~KP_POD_FLAGS_USED;
      kpm->pods[*ip].last_used = now;
    }

    //Recompute flows
    kp_vip_update_new_flow_table(vip);
  }

  vec_free(indexes);
  return 0;
}

int kp_vip_del_pods(u32 vip_index, ip46_address_t *addresses, u32 n)
{
  kp_get_writer_lock();
  int ret = kp_vip_del_pods_withlock(vip_index, addresses, n);
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
 * Deletes the adjacency podsociated with the VIP
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
  vlib_main_t *vm = kpm->vlib_main;
  kp_vip_t *vip;
  u32 key, *key_copy;
  uword * entry;

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
      (type != KP_VIP_TYPE_IP4_NAT46)) {
    kp_put_writer_lock();
    return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
  }


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
  vip->pod_indexes = 0;

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

  //Create maping from nodeport to vip_index
  key = clib_host_to_net_u16(node_port);
  entry = hash_get_mem (kpm->nodeport_by_key, &key);
  if (entry) {
    kp_put_writer_lock();
    return VNET_API_ERROR_VALUE_EXIST;
  }

  key_copy = clib_mem_alloc (sizeof (*key_copy));
  clib_memcpy (key_copy, &key, sizeof (*key_copy));
  hash_set_mem (kpm->nodeport_by_key, key_copy, vip - kpm->vips);

  /* receive packets destined to NodeIP:NodePort */
  udp_register_dst_port (vm, node_port, kp4_nodeport_node.index, 1);
  udp_register_dst_port (vm, node_port, kp6_nodeport_node.index, 0);

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
    //Remove all PODs
    ip46_address_t *pods = 0;
    kp_pod_t *pod;
    u32 *pod_index;
    pool_foreach(pod_index, vip->pod_indexes, {
        pod = &kpm->pods[*pod_index];
        vec_add1(pods, pod->address);
    });
    if (vec_len(pods))
      kp_vip_del_pods_withlock(vip_index, pods, vec_len(pods));
    vec_free(pods);
  }

  //Delete adjacency
  kp_vip_del_adjacency(kpm, vip);

  //Set the VIP pod unused
  vip->flags &= ~KP_VIP_FLAGS_USED;

  kp_put_writer_lock();
  return 0;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "kube-proxy data plane",
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
  kp_pod_t *pod = pool_elt_at_index (kpm->pods, index);
  return (&pod->fib_node);
}

static void
kp_fib_node_last_lock_gone (fib_node_t *node)
{
}

static kp_pod_t *
kp_pod_from_fib_node (fib_node_t *node)
{
  return ((kp_pod_t*)(((char*)node) -
      STRUCT_OFFSET_OF(kp_pod_t, fib_node)));
}

static void
kp_pod_stack (kp_pod_t *pod)
{
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip = &kpm->vips[pod->vip_index];
  dpo_stack(kp_vip_is_nat4(vip)?kpm->dpo_nat4_type:kpm->dpo_nat6_type,
	    kp_vip_is_ip4(vip)?DPO_PROTO_IP4:DPO_PROTO_IP6,
	    &pod->dpo,
	    fib_entry_contribute_ip_forwarding(
		pod->next_hop_fib_entry_index));
}

static fib_node_back_walk_rc_t
kp_fib_node_back_walk_notify (fib_node_t *node,
			       fib_node_back_walk_ctx_t *ctx)
{
    kp_pod_stack(kp_pod_from_fib_node(node));
    return (FIB_NODE_BACK_WALK_CONTINUE);
}

int kp_nat4_interface_add_del (u32 sw_if_index, int is_del)
{
  if (is_del)
    {
      vnet_feature_enable_disable ("ip4-unicast", "kp-nat4-in2out",
                                   sw_if_index, 0, 0, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-unicast", "kp-nat4-in2out",
                                   sw_if_index, 1, 0, 0);
    }

  return 0;
}

clib_error_t *
kp_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  kp_main_t *kpm = &kp_main;
  kpm->vnet_main = vnet_get_main ();
  kpm->vlib_main = vm;

  kp_pod_t *default_pod;
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

  //Init POD reference counters
  vlib_refcount_init(&kpm->pod_refcount);

  //Allocate and init default POD.
  kpm->pods = 0;
  pool_get(kpm->pods, default_pod);
  default_pod->flags = 0;
  default_pod->dpo.dpoi_next_node = KP_NEXT_DROP;
  default_pod->vip_index = ~0;
  default_pod->address.ip6.as_u64[0] = 0xffffffffffffffffL;
  default_pod->address.ip6.as_u64[1] = 0xffffffffffffffffL;

  kpm->nodeport_by_key
    = hash_create_mem (0, sizeof(u16), sizeof (uword));

  clib_bihash_init_8_8 (&kpm->mapping_by_pod,
                        "mapping_by_pod", KP_MAPPING_BUCKETS,
			KP_MAPPING_MEMORY_SIZE);

#define _(a,b,c) kpm->vip_counters[c].name = b;
  kp_foreach_vip_counter
#undef _
  return NULL;
}

VLIB_INIT_FUNCTION (kp_init);
