/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2026 Cisco and/or its affiliates.
 */

#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <vnet/ip/ip.h>
#include <vnet/crypto/crypto.h>
#include <vnet/feature/feature.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>
#include <vnet/ipsec/ipsec_sa.h>

#include <vppinfra/bihash_8_16.h>

#include <vppinfra/bihash_24_16.h>

#define IPSEC_FP_IP4_HASHES_POOL_SIZE 128
#define IPSEC_FP_IP6_HASHES_POOL_SIZE 128

typedef struct
{
  u64 key[2]; // 16 bytes
  u64 value;
  i32 bucket_lock;
  u32 un_used;
} ipsec4_hash_kv_16_8_t;

typedef union
{
  struct
  {
    ip4_address_t ip4_addr[2];
    u16 port[2];
    u8 proto;
    u8 pad[3];
  };
  ipsec4_hash_kv_16_8_t kv_16_8;
} ipsec4_spd_5tuple_t;

typedef union
{
  struct
  {
    ip4_address_t ip4_src_addr;
    ip4_address_t ip4_dest_addr;
    ipsec_spd_policy_type_t policy_type;
    u8 pad[4];
  }; // 16 bytes total
  ipsec4_hash_kv_16_8_t kv_16_8;
} ipsec4_inbound_spd_tuple_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_chunk_t *chunks;
} ipsec_per_thread_data_t;
typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  /* pool of policies */
  ipsec_policy_t *policies;
  /* pool of bihash tables for ipv4 ipsec rules */
  clib_bihash_16_8_t *fp_ip4_lookup_hashes_pool;
  /* pool of bihash tables for ipv6 ipsec rules */
  clib_bihash_40_8_t *fp_ip6_lookup_hashes_pool;

  u32 fp_spd_ipv4_out_is_enabled;
  u32 fp_spd_ipv4_in_is_enabled;
  u32 fp_spd_ipv6_out_is_enabled;
  u32 fp_spd_ipv6_in_is_enabled;
  /* pool of fast path mask types */
  ipsec_fp_mask_type_entry_t *fp_mask_types;
  u32 fp_lookup_hash_buckets; /* number of buckets should be power of two */

  /* hash tables of UDP port registrations */
  uword *udp_port_registrations;

  uword *tunnel_index_by_key;

  /* next_header protocol registration */
  u16 *next_header_registrations;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec4_if_pool_index_by_key;
  uword *ipsec6_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;
  uword *ipsec_if_by_sw_if_index;

  ipsec4_hash_kv_16_8_t *ipsec4_out_spd_hash_tbl;
  ipsec4_hash_kv_16_8_t *ipsec4_in_spd_hash_tbl;
  clib_bihash_8_16_t tun4_protect_by_key;
  clib_bihash_24_16_t tun6_protect_by_key;

  /* node indices */
  u32 error_drop_node_index;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_decrypt_tun_node_index;
  u32 esp4_encrypt_tun_node_index;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_decrypt_tun_node_index;
  u32 esp6_encrypt_tun_node_index;
  u32 esp_mpls_encrypt_tun_node_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  /* next node indices */
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp4_decrypt_tun_next_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 esp6_decrypt_tun_next_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;

  /* per-thread data */
  ipsec_per_thread_data_t *ptd;

  /** Worker handoff */
  u32 ah4_enc_fq_index;
  u32 ah4_dec_fq_index;
  u32 ah6_enc_fq_index;
  u32 ah6_dec_fq_index;

  u32 esp4_enc_fq_index;
  u32 esp4_dec_fq_index;
  u32 esp6_enc_fq_index;
  u32 esp6_dec_fq_index;
  u32 esp4_enc_tun_fq_index;
  u32 esp6_enc_tun_fq_index;
  u32 esp_mpls_enc_tun_fq_index;
  u32 esp4_dec_tun_fq_index;
  u32 esp6_dec_tun_fq_index;

  u32 handoff_queue_size;

  /* Number of buckets for flow cache */
  u32 ipsec4_out_spd_hash_num_buckets;
  u32 ipsec4_out_spd_flow_cache_entries;
  u32 epoch_count;
  u8 output_flow_cache_flag;

  u32 ipsec4_in_spd_hash_num_buckets;
  u32 ipsec4_in_spd_flow_cache_entries;
  u32 input_epoch_count;
  u8 input_flow_cache_flag;

  u8 async_mode;
  u16 msg_id_base;

  ipsec_sa_t *sa_pool;
  ipsec_sa_inb_rt_t **inb_sa_runtimes;
  ipsec_sa_outb_rt_t **outb_sa_runtimes;
} ipsec_main_t;

typedef enum ipsec_format_flags_t_
{
  IPSEC_FORMAT_BRIEF = 0,
  IPSEC_FORMAT_DETAIL = (1 << 0),
  IPSEC_FORMAT_INSECURE = (1 << 1),
} ipsec_format_flags_t;

typedef struct
{
  u32 sa_index;
  u32 spi;
  u64 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

typedef struct
{
  u32 next_index;
} esp_encrypt_post_trace_t;

typedef struct
{
  u32 seq;
  u64 sa_seq64;
  u32 pkt_seq_hi;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

typedef struct
{
  u32 sa_index;
  u32 spi;
  u64 seq;
  ipsec_integ_alg_t integ_alg;
} ah_encrypt_trace_t;

typedef struct
{
  ipsec_integ_alg_t integ_alg;
  u32 seq_num;
} ah_decrypt_trace_t;

typedef struct ipsec_handoff_trace_t_
{
  u32 next_worker_index;
} ipsec_handoff_trace_t;

typedef struct
{
  ip_protocol_t proto;
  u32 spd;
  u32 policy_index;
  u32 policy_type;
  u32 sa_id;
  u32 spi;
  u32 seq;
} ipsec_input_trace_t;

typedef struct
{
  u32 spd_id;
  u32 policy_id;
} ipsec_output_trace_t;

extern ipsec_main_t ipsec_main;

extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

/*
 * functions
 */
format_function_t format_esp_encrypt_trace;
format_function_t format_esp_post_encrypt_trace;
format_function_t format_esp_decrypt_trace;
format_function_t format_ah_encrypt_trace;
format_function_t format_ah_decrypt_trace;
format_function_t format_ipsec_handoff_trace;
format_function_t format_ipsec_input_trace;
format_function_t format_ipsec_output_trace;

/*
 *  inline functions
 */

static_always_inline u32
get_next_output_feature_node_index (vlib_buffer_t * b,
				    vlib_node_runtime_t * nr)
{
  u32 next;
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node = vlib_get_node (vm, nr->node_index);

  vnet_feature_next (&next, b);
  return node->next_nodes[next];
}

static_always_inline u64
ipsec4_hash_16_8 (ipsec4_hash_kv_16_8_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 16);
#else
  u64 tmp = v->key[0] ^ v->key[1];
  return clib_xxhash (tmp);
#endif
}

static_always_inline int
ipsec4_hash_key_compare_16_8 (u64 *a, u64 *b)
{
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v;
  v = u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
#endif
}

/* clib_spinlock_lock is not used to save another memory indirection */
static_always_inline void
ipsec_spinlock_lock (i32 *lock)
{
  i32 free = 0;
  while (!clib_atomic_cmp_and_swap_acq_relax_n (lock, &free, 1, 0))
    {
      /* atomic load limits number of compare_exchange executions */
      while (clib_atomic_load_relax_n (lock))
	CLIB_PAUSE ();
      /* on failure, compare_exchange writes lock into free */
      free = 0;
    }
}

static_always_inline void
ipsec_spinlock_unlock (i32 *lock)
{
  /* Make sure all reads/writes are complete before releasing the lock */
  clib_atomic_release (lock);
}

/* Special case to drop or hand off packets for sync/async modes.
 *
 * Different than sync mode, async mode only enqueue drop or hand-off packets
 * to next nodes.
 */
always_inline void
ipsec_set_next_index (vlib_buffer_t *b, vlib_node_runtime_t *node,
		      clib_thread_index_t thread_index, u32 err,
		      u32 ipsec_sa_err, u16 index, u16 *nexts, u16 drop_next,
		      u32 sa_index)
{
  nexts[index] = drop_next;
  b->error = node->errors[err];
  if (PREDICT_TRUE (ipsec_sa_err != ~0))
    vlib_increment_simple_counter (&ipsec_sa_err_counters[ipsec_sa_err],
				   thread_index, sa_index, 1);
}

void ipsec_set_async_mode (u32 is_enabled);

extern void ipsec_register_udp_port (u16 udp_port, u8 is_ip4);
extern void ipsec_unregister_udp_port (u16 udp_port, u8 is_ip4);

extern clib_error_t *ipsec_register_next_header (vlib_main_t *vm,
						 u8 next_header,
						 const char *next_node);

#include <vnet/ipsec/ipsec_funcs.h>

#endif /* __IPSEC_H__ */
