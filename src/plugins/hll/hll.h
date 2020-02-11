/*
 * hll.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_hll_h__
#define __included_hll_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/error.h>

#define HLL_PLUGIN_HASH_BUCKETS (2 << 14)
#define HLL_PLUGIN_HASH_MEMORY (2 << 25)

#define INTERMEDIATE_ZONE (1 << 8)
#define RELEGATION_SPOT (1 << 8)
#define PROMOTION_BINMASK ((1 << 8)-1)
#define TOPK_MINRANK_THRESHOLD 5
#define TOPK_REG_THRESHOLD 31
#define TOPK_WREG_THRESHOLD1 63

#define TOPK_PKT_MARGIN 4500


/* HyperLogLog (HLL) is an efficient structure to estimate the cardinality of a set.
 * HLL is based on the probabilistic counting method developed by  Flajolet and Martin.
 * The counting method performs the hash $h(x)$ of an incoming item $x$ and estimate the number
 * of distinct items depending on the value of $h(x)$. In particular, we first compute $\rho(h(x))$,
 * where $\rho$ returns the position of the leftmost 1 in the binary representation of $h(x)$.
 * After, stores the maximum between the current max value and the new $\rho(h(x))$ value.
 * At the end of the computation, the number of distinct items can be estimated as $2^{max_i(\rho(h(x_i)))}$.
 * In fact, it is easy to understand that the probability that $\rho(h(x))$ gets a specific value n with
 * probability $2^{-n}$. Hence, from a statistical point of view, after n distinct elements,
 * $\rho(h(x))$ roughly approximate the $log_2$ of the number of distinct elements.*/







/* information on the HLL associated to a specific flow */
typedef struct
{
  /* flow id */
  u64 hll_key_as_u64[2];
  /* index to raw_counter list */
  u32 raw_count_index;
} hll_info_t;


/* HT value */
//typedef struct __attribute__ ((aligned (8))){
typedef struct
{
  /* index to hll_info */
  u32 hll_index;
  u32 reserved;
} hll_value_t;


/* HT key */
//typedef struct __attribute__ ((aligned (8))){
typedef union
{
  u64 as_u64[2];
  struct
  {
    //u8 src_mac[6];
    //u8 dst_mac[6];
    //u16 ethertype;
    u32 src_address;
    u32 dst_address;
    u8 protocol;
    u16 src_port;
    u16 dst_port;
    u8 pad[3];
  };
} hll_key_t;



typedef struct
{
  /* log(substreams) */
  u8 bits;
  /* number of substreams */
  u32 size;
  u32 size_asu64;
  /* number of perflow_hlls */
  u32 multihll_size;

  /* function mode (<flow key , discriminator key>) */
  /* 1 <src_ip , dst_ip> */
  /* 2 <dst_ip , src_ip> */
  /* 3 <src_ip , 5-tuple> */
  /* 4 <dst_ip , 5-tuple> */
  u8 mode;

  /* pkt_level infos for debug */
  u64 pkt_count;
  u64 deniedaccess;
  u64 admittedaccess;
  u64 n_swaps;

  /* active hll counter */
  u32 hll_assigned;

  /* hll_raw_count_vec and reverse_hll_vec are extra structures used to support a top-k implementation */
  /* list of hll-raw_counters, sorted by raw_value */
  u32 *hll_raw_count_vec;
  u32 *hll_reg_count_vec;
  double *hll_raw_q_count_vec;
  double *hll_raw_est_vec;
  u64 last_pkt_c;
  /* list of reverse hll index, sorted by raw_value */
  u32 *reverse_hll_vec;

  /* pointer to HT */
  clib_bihash_16_8_t *hll_list_hash;

  /* hll info array */
  hll_info_t **hll_info_vec;

  /* list of hll-sketches */
  u8 **hllreg_vec;
} hll_list_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;
  /* Node index, non-zero if the periodic process has been created */
  u32 periodic_node_index;

  u64 counter;

  /* HLLs associated with interfaces */
  hll_list_t **input_hll_vec_by_sw_if_index;
  u32 *associated_sw_if_index;

  /* hash table. */
  clib_bihash_16_8_t *hll_list_hash;
  u32 hll_list_hash_buckets;
  uword hll_list_hash_memory;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} hll_main_t;

extern hll_main_t hll_main;

extern vlib_node_registration_t hll_node;
extern vlib_node_registration_t hll_periodic_node;

/* Periodic function events */
#define HLL_EVENT1 1
#define HLL_EVENT2 2
#define HLL_EVENT_PERIODIC_ENABLE_DISABLE 3

void hll_create_periodic_process (hll_main_t *);

#endif /* __included_hll_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
