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
#ifndef __included_ioam_cache_h__
#define __included_ioam_cache_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/udp.h>
#include <vnet/sr/sr.h>

#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vppinfra/bihash_8_8.h>
#include <ioam/analyse/ioam_analyse.h>

#define MAX_CACHE_ENTRIES 1024
#define MAX_CACHE_TS_ENTRIES 1048576 //1M entries per pool
#define IOAM_CACHE_TABLE_DEFAULT_HASH_NUM_BUCKETS (4 * 1024)
#define IOAM_CACHE_TABLE_DEFAULT_HASH_MEMORY_SIZE (2<<20)


typedef struct {
  ip6_address_t src_address;
  ip6_address_t dst_address;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u32 seq_no;
  u8 *ioam_rewrite_string;
} ioam_cache_entry_t;

typedef struct {
  volatile u8 lock;
  ip6_address_t src_address;
  ip6_address_t dst_address;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u32 seq_no;
  u32 buffer_index;
  ip6_hop_by_hop_header_t *hbh; //pointer to hbh header in the buffer
  u64 created_at;
  u8 response_received;
  u8 max_responses;
  u64 hash_key;
} ioam_cache_ts_entry_t;

typedef struct {
  u64 inuse;
  u64 add_failed;
} ioam_cache_ts_pool_stats_t;


typedef struct {
  /* API message ID base */
  u16 msg_id_base;
  
  /* Pool of ioam_cache_buffer_t */
  ioam_cache_entry_t *ioam_rewrite_pool;

  /* The current rewrite we're using */
  u8 * rewrite;
  u8 rewrite_pool_index_offset;

  u64 lookup_table_nbuckets;
  u64 lookup_table_size;
  clib_bihash_8_8_t ioam_rewrite_cache_table;

  /* Pool of ioam_cache_buffer_t per thread */
  ioam_cache_ts_entry_t **ioam_ts_pool;
  ioam_cache_ts_pool_stats_t *ts_stats;
  volatile u32 **lockp_ts;
  bool criteria_oneway;

  /* convenience */
  vlib_main_t * vlib_main;

  uword cache_hbh_slot;
  uword ts_hbh_slot;
  u32 ip6_hbh_pop_node_index;
  u32 error_node_index;
  u32 cleanup_process_node_index;
} ioam_cache_main_t;

ioam_cache_main_t ioam_cache_main;

vlib_node_registration_t ioam_cache_node;
vlib_node_registration_t ioam_cache_ts_node;

/* Compute flow hash.  We'll use it to select which Sponge to use for this
   flow.  And other things. */
always_inline u32
ip6_compute_flow_hash_ext (const ip6_header_t * ip,
			   u8 protocol,
			   u16 src_port,
			   u16 dst_port,
		       flow_hash_config_t flow_hash_config)
{
    u64 a, b, c;
    u64 t1, t2;

    t1 = (ip->src_address.as_u64[0] ^ ip->src_address.as_u64[1]);
    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) ? t1 : 0;

    t2 = (ip->dst_address.as_u64[0] ^ ip->dst_address.as_u64[1]);
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) ? t2 : 0;

    a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
    b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;
    b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? protocol : 0;

    t1 = src_port;
    t2 = dst_port;

    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;

    c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
        ((t1<<16) | t2) : ((t2<<16) | t1);

    hash_mix64 (a, b, c);
    return (u32) c;
}

inline static void ioam_cache_entry_free (ioam_cache_entry_t *entry)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  if (entry)
    {
      vec_free(entry->ioam_rewrite_string);
      memset(entry, 0, sizeof(*entry));
      pool_put(cm->ioam_rewrite_pool, entry);
    }
}

inline static ioam_cache_entry_t * ioam_cache_entry_cleanup (u32 pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_entry_t *entry = 0;

  entry = pool_elt_at_index(cm->ioam_rewrite_pool, pool_index);
  ioam_cache_entry_free(entry);
  return(0);
}

inline static ioam_cache_entry_t * ioam_cache_lookup (ip6_header_t *ip0,
                                  u16 src_port,
				  u16 dst_port,
				  u32 seq_no)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  u32 flow_hash = ip6_compute_flow_hash_ext(ip0, ip0->protocol,
					    src_port, dst_port,
					    IP_FLOW_HASH_DEFAULT | IP_FLOW_HASH_REVERSE_SRC_DST);
  clib_bihash_kv_8_8_t kv, value;

  kv.key = (u64)flow_hash << 32 | seq_no;
  kv.value = 0;
  value.key = 0;
  value.value = 0;

  if (clib_bihash_search_8_8(&cm->ioam_rewrite_cache_table, &kv, &value) >= 0)
    {
      ioam_cache_entry_t *entry = 0;

      entry = pool_elt_at_index(cm->ioam_rewrite_pool, value.value);
      /* match */
      if (ip6_address_compare(&ip0->src_address, &entry->dst_address) == 0 &&
	  ip6_address_compare(&ip0->dst_address, &entry->src_address) == 0 &&
	  entry->src_port == dst_port &&
	  entry->dst_port == src_port &&
	  entry->seq_no == seq_no)
	{
	  /* If lookup is successful remove it from the hash */
	  clib_bihash_add_del_8_8(&cm->ioam_rewrite_cache_table, &kv, 0);
	  return(entry);
	}
      else
	return(0);

    }
  return(0);
}
#define HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID 30
#define HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID 31

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 e2e_type;
  u8 reserved[5];
  ip6_address_t id;
}) ioam_e2e_id_option_t;

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 e2e_type;
  u8 pool_id;
  u32 pool_index;
}) ioam_e2e_cache_option_t;

#define IOAM_E2E_ID_OPTION_RND ((sizeof(ioam_e2e_id_option_t) + 7) & ~7)
#define IOAM_E2E_ID_HBH_EXT_LEN (IOAM_E2E_ID_OPTION_RND >> 3)
#define IOAM_E2E_CACHE_OPTION_RND ((sizeof(ioam_e2e_cache_option_t) + 7) & ~7)
#define IOAM_E2E_CACHE_HBH_EXT_LEN (IOAM_E2E_CACHE_OPTION_RND >> 3)

/* get first interface address */
static inline ip6_address_t *
ip6_interface_first_address (u32 sw_if_index)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip6_address_t *result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */ ,
                                (
				{
                                  ip6_address_t * a =
				    ip_interface_address_get_address (lm, ia);
                                  if (ip6_address_is_link_local_unicast(a))
				    continue;
                                  result = a;
                                  break;
				}
				  ));
  return result;
}
static inline void
ioam_e2e_id_rewrite_handler (ioam_e2e_id_option_t *e2e_option,
                             vlib_buffer_t *b0)
{
  ip6_address_t *my_address = 0;
  e2e_option->hdr.type = HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID
    | HBH_OPTION_TYPE_SKIP_UNKNOWN;
  e2e_option->hdr.length = sizeof (ioam_e2e_id_option_t) -
    sizeof (ip6_hop_by_hop_option_t);
  e2e_option->e2e_type = 1;
  my_address = ip6_interface_first_address(vnet_buffer (b0)->sw_if_index[VLIB_RX]);
  if (my_address)
    {
      e2e_option->id.as_u64[0] = my_address->as_u64[0];
      e2e_option->id.as_u64[1] = my_address->as_u64[1];
    }
}

/*
 * Caches ioam hbh header
 * Extends the hbh header with option to contain IP6 address of the node
 * that caches it
 */
inline static int ioam_cache_add (
                                  vlib_buffer_t *b0,
                                  ip6_header_t *ip0,
                                  u16 src_port,
				  u16 dst_port,
				  ip6_hop_by_hop_header_t *hbh0,
				  u32 seq_no)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_entry_t *entry = 0;
  u32 rewrite_len = 0;
  u32 pool_index = 0;
  ioam_e2e_id_option_t *e2e = 0;

  pool_get_aligned(cm->ioam_rewrite_pool, entry, CLIB_CACHE_LINE_BYTES);
  memset (entry, 0, sizeof (*entry));
  pool_index = entry - cm->ioam_rewrite_pool;

  clib_memcpy(entry->dst_address.as_u64, ip0->dst_address.as_u64, sizeof(ip6_address_t));
  clib_memcpy(entry->src_address.as_u64, ip0->src_address.as_u64, sizeof(ip6_address_t));
  entry->src_port = src_port;
  entry->dst_port = dst_port;
  entry->seq_no = seq_no;
  rewrite_len = ((hbh0->length + 1) << 3);
  vec_validate(entry->ioam_rewrite_string, rewrite_len - 1 + IOAM_E2E_ID_OPTION_RND);
  /* setup e2e id option to insert v6 address of the node caching it */
  clib_memcpy(entry->ioam_rewrite_string, hbh0, rewrite_len);
  hbh0 = (ip6_hop_by_hop_header_t *) entry->ioam_rewrite_string;
  hbh0->length += IOAM_E2E_ID_HBH_EXT_LEN;

  /* suffix rewrite string with e2e ID option */
  e2e = (ioam_e2e_id_option_t *)(entry->ioam_rewrite_string + rewrite_len);
  ioam_e2e_id_rewrite_handler(e2e, b0);

  /* add it to hash, replacing and freeing any collision for now */
  u32 flow_hash = ip6_compute_flow_hash_ext(ip0, hbh0->protocol, src_port, dst_port,
					    IP_FLOW_HASH_DEFAULT);
  clib_bihash_kv_8_8_t kv, value;
  kv.key = (u64)flow_hash << 32 | seq_no;
  kv.value = 0;
  if (clib_bihash_search_8_8(&cm->ioam_rewrite_cache_table, &kv, &value) >= 0)
    {
      /* replace */
      ioam_cache_entry_cleanup(value.value);
    }
  kv.value = pool_index;
  clib_bihash_add_del_8_8(&cm->ioam_rewrite_cache_table, &kv, 1);
  return(0);
}

inline static int ioam_cache_table_init (vlib_main_t *vm)
{
  ioam_cache_main_t *cm = &ioam_cache_main;

  pool_alloc_aligned(cm->ioam_rewrite_pool,
		      MAX_CACHE_ENTRIES,
		      CLIB_CACHE_LINE_BYTES);
  cm->lookup_table_nbuckets = IOAM_CACHE_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  cm->lookup_table_nbuckets = 1 << max_log2 (cm->lookup_table_nbuckets);
  cm->lookup_table_size = IOAM_CACHE_TABLE_DEFAULT_HASH_MEMORY_SIZE;

  clib_bihash_init_8_8(&cm->ioam_rewrite_cache_table,
	               "ioam rewrite cache table",
		       cm->lookup_table_nbuckets, cm->lookup_table_size);
  return(1);
}

inline static int ioam_cache_table_destroy (vlib_main_t *vm)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_entry_t *entry = 0;
  /* free pool and hash table */
  clib_bihash_free_8_8(&cm->ioam_rewrite_cache_table);
  pool_foreach (entry, cm->ioam_rewrite_pool,
		({
		  ioam_cache_entry_free(entry);
		}));
  pool_free(cm->ioam_rewrite_pool);
  cm->ioam_rewrite_pool = 0;
  return(0);
}

inline static u8 * format_ioam_cache_entry (u8 * s, va_list * args)
{
  ioam_cache_entry_t *e = va_arg (*args, ioam_cache_entry_t *);
  ioam_cache_main_t *cm = &ioam_cache_main;

  s = format (s, "%d: %U:%d to  %U:%d seq_no %lu\n",
	      (e - cm->ioam_rewrite_pool),
	      format_ip6_address, &e->src_address,
	      e->src_port,
	      format_ip6_address, &e->dst_address,
	      e->dst_port,
	      e->seq_no);
  s = format (s, "  %U",
	      format_ip6_hop_by_hop_ext_hdr,
	      (ip6_hop_by_hop_header_t *)e->ioam_rewrite_string,
	      vec_len(e->ioam_rewrite_string)-1);
  return s;
}

inline static int ioam_cache_ts_table_init (vlib_main_t *vm)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  int no_of_threads = vec_len(vlib_worker_threads);
  int i;

  vec_validate_aligned(cm->ioam_ts_pool, no_of_threads-1,
		       CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned(cm->lockp_ts, no_of_threads-1,
		       CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned(cm->ts_stats, no_of_threads-1,
		       CLIB_CACHE_LINE_BYTES);
  cm->lookup_table_nbuckets = IOAM_CACHE_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  cm->lookup_table_nbuckets = 1 << max_log2 (cm->lookup_table_nbuckets);
  cm->lookup_table_size = IOAM_CACHE_TABLE_DEFAULT_HASH_MEMORY_SIZE;
  for (i=0; i < no_of_threads; i++)
    {
      pool_alloc_aligned(cm->ioam_ts_pool[i],
		      MAX_CACHE_TS_ENTRIES,
		      CLIB_CACHE_LINE_BYTES);
      memset(&cm->ts_stats[i], 0, sizeof(ioam_cache_ts_pool_stats_t));
      cm->lockp_ts[i] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
       				     CLIB_CACHE_LINE_BYTES);
      memset ((void *) cm->lockp_ts[i], 0, CLIB_CACHE_LINE_BYTES);
    }
  return(1);
}

inline static void ioam_cache_ts_entry_free (u32 thread_id,
					     ioam_cache_ts_entry_t *entry,
					     u32 node_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  vlib_main_t *vm = cm->vlib_main;
  vlib_frame_t * nf = 0;
  u32 * to_next;

  if (entry)
    { 
      if (entry->hbh != 0) 
	{
	  nf = vlib_get_frame_to_node (vm, node_index);
	  nf->n_vectors = 0;
	  to_next = vlib_frame_vector_args (nf);
	  nf->n_vectors = 1;
	  to_next[0] = entry->buffer_index;
	  vlib_put_frame_to_node(vm, node_index, nf);
	}
       pool_put(cm->ioam_ts_pool[thread_id], entry);
       cm->ts_stats[thread_id].inuse--;
       // Intentional: to ensure, entry is marked as free before releasing the lock
       memset(entry, 0, sizeof(*entry));
    }
}

inline static int ioam_cache_ts_table_destroy (vlib_main_t *vm)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;
  int no_of_threads = vec_len(vlib_worker_threads);
  int i;

  /* free pool and hash table */
  for (i=0; i < no_of_threads; i++)
    {
      pool_foreach (entry, cm->ioam_ts_pool[i],
		    ({
		      ioam_cache_ts_entry_free(i, entry, cm->error_node_index);
		    }));
      pool_free(cm->ioam_ts_pool[i]);
      cm->ioam_ts_pool = 0;
      clib_mem_free((void *) cm->lockp_ts[i]);
      cm->lockp_ts[i] = 0;
    }
  vec_free(cm->ioam_ts_pool);
  vec_free(cm->lockp_ts);
  return(0);
}

inline static int ioam_cache_ts_entry_cleanup (u32 thread_id,
					       u32 pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;

  entry = pool_elt_at_index(cm->ioam_ts_pool[thread_id], pool_index);
  ioam_cache_ts_entry_free(thread_id, entry, cm->error_node_index);
  return(0);
}

/*
 * Caches buffer for ioam SR tunnel select
 */
inline static int ioam_cache_ts_add (
                                  ip6_header_t *ip0,
                                  u16 src_port,
				  u16 dst_port,
                                  u32 seq_no,
				  u8 max_responses,
				  u64 now,
				  u32 thread_id,
				  u32 *pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;

  if (cm->ts_stats[thread_id].inuse == MAX_CACHE_TS_ENTRIES)
    {
      cm->ts_stats[thread_id].add_failed++;
      return(-1);
    }

  while (__sync_lock_test_and_set (cm->lockp_ts[thread_id], 1)) 
    ;
  
  pool_get_aligned(cm->ioam_ts_pool[thread_id], entry, CLIB_CACHE_LINE_BYTES);
  memset (entry, 0, sizeof (*entry));
  *pool_index = entry - cm->ioam_ts_pool[thread_id];

  clib_memcpy(entry->dst_address.as_u64, ip0->dst_address.as_u64, sizeof(ip6_address_t));
  clib_memcpy(entry->src_address.as_u64, ip0->src_address.as_u64, sizeof(ip6_address_t));
  entry->src_port = src_port;
  entry->dst_port = dst_port;
  entry->seq_no = seq_no;
  entry->response_received = 0;
  entry->max_responses = max_responses;
  entry->created_at = now; 
  entry->hbh = 0;
  entry->buffer_index = 0;
  entry->lock = 0;
  cm->ts_stats[thread_id].inuse++;
  *cm->lockp_ts[thread_id] = 0;
  return(0);
}

inline static void ioam_cache_ts_send (u32 thread_id,
				       i32 pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;

  entry = pool_elt_at_index(cm->ioam_ts_pool[thread_id], pool_index);
  if (!pool_is_free(cm->ioam_ts_pool[thread_id], entry)
      && entry->lock == 0 && entry && entry->hbh)
    {

      while (__sync_lock_test_and_set (&entry->lock, 1)) 
	    ;
      if (entry->hbh)
	{
	  //REMOVE This: E2E ID is not needed when manycast server and client stack are separate
	  ioam_e2e_id_option_t *e2e;
	  e2e = ip6_ioam_find_hbh_option(entry->hbh, HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID);
	  /* Select SR tunnel */
	  (void) ip6_sr_multicastmap_select_tunnel(&(entry->dst_address), &(e2e->id));
	}
      /* send and free pool entry */
      ioam_cache_ts_entry_free(thread_id, entry, cm->ip6_hbh_pop_node_index);
    }
}

#define IOAM_CACHE_TS_TIMEOUT (20.0)

// Should be called with cache ts entry already is locked
inline static void ioam_cache_ts_check_and_send (u32 thread_id,
						 i32 pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;
  entry = pool_elt_at_index(cm->ioam_ts_pool[thread_id], pool_index);
  if (entry && entry->hbh)
    {
      if (entry->response_received == entry->max_responses ||
	  entry->created_at + IOAM_CACHE_TS_TIMEOUT <= vlib_time_now(cm->vlib_main))
	{
          entry->lock = 0;
          while (__sync_lock_test_and_set (cm->lockp_ts[thread_id], 1)) 
            ;
	  ioam_cache_ts_send(thread_id, pool_index);
	  *cm->lockp_ts[thread_id] = 0;
	}
    }
}

//called with entry locked
inline static int ioam_cache_ts_update (u32 thread_id,
					i32 pool_index, 
					u32 buffer_index,
					ip6_hop_by_hop_header_t *hbh)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;
  vlib_main_t *vm = cm->vlib_main;
  vlib_frame_t * nf = 0;
  u32 * to_next;

  entry = pool_elt_at_index(cm->ioam_ts_pool[thread_id], pool_index);
  if (!pool_is_free(cm->ioam_ts_pool[thread_id], entry) && entry)
    {
      /* drop existing buffer */
      if (entry->hbh != 0) 
	{
	  nf = vlib_get_frame_to_node (vm, cm->error_node_index);
	  nf->n_vectors = 0;
	  to_next = vlib_frame_vector_args (nf);
	  nf->n_vectors = 1;
	  to_next[0] = entry->buffer_index;
	  vlib_put_frame_to_node(vm, cm->error_node_index, nf);
	}
      /* update */
      entry->buffer_index = buffer_index;
      entry->hbh = hbh;
      /* check and send */
      ioam_cache_ts_check_and_send (thread_id, pool_index);
      return(0);
    }
  return (-1);
}
inline static void ioam_cache_ts_entry_unlock (u8 thread_id,
					       u32 pool_index)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_ts_entry_t *entry = 0;

  if (!pool_is_free(cm->ioam_ts_pool[thread_id], entry))
    {
      entry = pool_elt_at_index(cm->ioam_ts_pool[thread_id], pool_index);
    }
  if (entry)
    {
      entry->lock = 0;
    }
}
    
/* 
 * looks up the entry based on the e2e option pool index
 * result = 0 
 *    when matching entry is found returns the hbh in the entry
 *    The pool entry is locked and cannot be updated by 
 *    any other thread
 * result < 0 indicates failture to find an entry
 */
inline static int ioam_cache_ts_lookup (ip6_header_t *ip0,
					u8 protocol,
					u16 src_port,
					u16 dst_port,
					u32 seq_no,
					ip6_hop_by_hop_header_t **hbh,
					u32 *pool_index,
					u8 *thread_id,
					u8 response_seen)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ip6_hop_by_hop_header_t *hbh0 = 0;
  ioam_e2e_cache_option_t *e2e = 0;
  
  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
  e2e = (ioam_e2e_cache_option_t *)((u8 *)hbh0 + cm->rewrite_pool_index_offset);
  if ((u8 *)e2e < ((u8*)hbh0 + ((hbh0->length + 1) << 3)) &&
      e2e->hdr.type == HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID)
    {
      ioam_cache_ts_entry_t *entry = 0;
      *pool_index = e2e->pool_index;
      *thread_id = e2e->pool_id;
      while (__sync_lock_test_and_set (cm->lockp_ts[*thread_id], 1)) 
	 ;
      entry = pool_elt_at_index(cm->ioam_ts_pool[*thread_id], *pool_index);
      if (entry && !pool_is_free(cm->ioam_ts_pool[*thread_id], entry))
	{
	  while (__sync_lock_test_and_set (&entry->lock, 1)) 
	    ;
	}
      *cm->lockp_ts[*thread_id] = 0;
      /* match */
      if (entry &&
	  ip6_address_compare(&ip0->src_address, &entry->dst_address) == 0 &&
	  ip6_address_compare(&ip0->dst_address, &entry->src_address) == 0 &&
	  entry->src_port == dst_port &&
	  entry->dst_port == src_port &&
	  entry->seq_no == seq_no)
	{
	  *hbh = entry->hbh;
	  entry->response_received += response_seen;
	  return(0);
	}
      else if(entry)
	{
	  entry->lock = 0;
	  return(-1);
	}
    }
  return(-1);
}

inline static u8 * format_ioam_cache_ts_entry (u8 * s, va_list * args)
{
  ioam_cache_ts_entry_t *e = va_arg (*args, ioam_cache_ts_entry_t *);
  u32 thread_id = va_arg (*args, u32);
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_e2e_id_option_t *e2e = 0;
  vlib_main_t *vm = cm->vlib_main;
  clib_time_t *ct = &vm->clib_time; 

  if (e && e->hbh)
    {
      e2e = ip6_ioam_find_hbh_option(e->hbh, HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID);

      s = format (s, "%d: %U:%d to  %U:%d seq_no %u buffer %u %U \n\t\tCreated at %U Received %d\n",
		  (e - cm->ioam_ts_pool[thread_id]),
		  format_ip6_address, &e->src_address,
		  e->src_port,
		  format_ip6_address, &e->dst_address,
		  e->dst_port,
		  e->seq_no,
		  e->buffer_index,
		  format_ip6_address, e2e? &e2e->id:0,
		  format_time_interval, "h:m:s:u", 
		  (e->created_at - vm->cpu_time_main_loop_start) * ct->seconds_per_clock,
		  e->response_received);
    }
  else
    {
      s = format (s, "%d: %U:%d to  %U:%d seq_no %u Buffer %u \n\t\tCreated at %U Received %d\n",
		  (e - cm->ioam_ts_pool[thread_id]),
		  format_ip6_address, &e->src_address,
		  e->src_port,
		  format_ip6_address, &e->dst_address,
		  e->dst_port,
		  e->seq_no,
		  e->buffer_index,
		  format_time_interval, "h:m:s:u", 
                  (e->created_at - vm->cpu_time_main_loop_start) * ct->seconds_per_clock,
		  e->response_received);
    }
  return s;
}
/* 
 * Get extended rewrite string for iOAM data in v6 
 * This makes space for an e2e option to carry cache pool info
 * It set the rewrite string per configs in ioam ip6 + new option
 * for cache along with offset to the option to populate cache
 * pool id and index
 */
static inline int
ip6_ioam_ts_cache_set_rewrite (void)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  ioam_cache_main_t *cm = &ioam_cache_main;
  ip6_hop_by_hop_header_t *hbh;
  u32 rewrite_len = 0;
  ioam_e2e_cache_option_t *e2e = 0;
  
  vec_free(cm->rewrite);
  ip6_ioam_set_rewrite(&(cm->rewrite), hm->has_trace_option, hm->has_pot_option,
		       hm->has_seqno_option);
  hbh = (ip6_hop_by_hop_header_t *)cm->rewrite;
  rewrite_len = ((hbh->length + 1) << 3);
  vec_validate(cm->rewrite, rewrite_len - 1 + IOAM_E2E_CACHE_OPTION_RND);
  hbh = (ip6_hop_by_hop_header_t *)cm->rewrite;
  /* setup e2e id option to insert pool id and index of the node caching it*/
  hbh->length += IOAM_E2E_CACHE_HBH_EXT_LEN;
  cm->rewrite_pool_index_offset = rewrite_len;
  e2e = (ioam_e2e_cache_option_t *)(cm->rewrite + rewrite_len);
  e2e->hdr.type = HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID
    | HBH_OPTION_TYPE_SKIP_UNKNOWN;
  e2e->hdr.length = sizeof (ioam_e2e_cache_option_t) -
    sizeof (ip6_hop_by_hop_option_t);
  e2e->e2e_type = 2;
  return(0);
}

static inline int
ip6_ioam_ts_cache_cleanup_rewrite (void)
{
  ioam_cache_main_t *cm = &ioam_cache_main;

  vec_free(cm->rewrite);
  cm->rewrite = 0;
  cm->rewrite_pool_index_offset = 0;
  return(0);
}
#endif /* __included_ioam_cache_h__ */
