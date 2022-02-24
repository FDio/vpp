/*
 *------------------------------------------------------------------
 * ip_path_mtu.h
 *
 * Copyright (c) 2021 Graphiant.
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
 *------------------------------------------------------------------
 */

#include <vnet/ip/ip.h>

/**
 * @brief
 * The Path MTU DPO. interposed in the forwarding chain of the host prefix.
 */
typedef struct ip_pmtu_dpo_t_
{
  /**
   * The protocol of packets using this DPO
   */
  dpo_proto_t ipm_proto;

  u8 __pad8;

  /**
   * Configured Path Mtu
   */
  u16 ipm_pmtu;

  /**
   * number of locks.
   */
  u16 ipm_locks;

  /**
   * Stacked DPO
   */
  dpo_id_t ipm_dpo;
} ip_pmtu_dpo_t;

/*
 * PMTU DPOs are accessed in the data-path so they should not straddle a cache
 * line. Align to a integer factor of a cacheline
 */
STATIC_ASSERT_SIZEOF (ip_pmtu_dpo_t, 2 * sizeof (u64));

#define foreach_ip_pmtu_flag                                                  \
  _ (ATTACHED, 0, "attached")                                                 \
  _ (REMOTE, 1, "remote")                                                     \
  _ (STALE, 2, "stale")

typedef enum ip_pmtu_flags_t_
{
#define _(a, b, c) IP_PMTU_FLAG_##a = (1 << b),
  foreach_ip_pmtu_flag
#undef _
} ip_pmtu_flags_t;

/**
 * Remote Path MTU tracking object
 */
typedef struct ip_pmtu_t_
{
  /** linkage into the FIB graph */
  fib_node_t ipt_node;

  /** Track fib entry */
  fib_node_index_t ipt_fib_entry;
  u32 ipt_sibling;
  ip_pmtu_flags_t ipt_flags;

  /** Configured MTU */
  u16 ipt_cfg_pmtu;

  /** MTU from the parent MTU */
  u16 ipt_parent_pmtu;

  /** operational MTU; the minimum value of the cfg and parent MTU */
  u16 ipt_oper_pmtu;
} ip_pmtu_t;

extern int ip_path_mtu_update (const ip_address_t *nh, u32 table_id, u16 pmtu);

typedef walk_rc_t (*ip_path_mtu_walk_t) (index_t ipti, void *ctx);

extern void ip_path_mtu_walk (ip_path_mtu_walk_t fn, void *ctx);
extern int ip_path_mtu_replace_begin (void);
extern int ip_path_mtu_replace_end (void);

extern u32 ip_pmtu_get_table_id (const ip_pmtu_t *ipt);
extern void ip_pmtu_get_ip (const ip_pmtu_t *ipt, ip_address_t *ip);

extern void ip_pmtu_dpo_add_or_lock (u16 pmtu, const dpo_id_t *parent,
				     dpo_id_t *dpo);

/**
 * Data-plane accessor functions
 */
extern ip_pmtu_dpo_t *ip_pmtu_dpo_pool;
static_always_inline ip_pmtu_dpo_t *
ip_pmtu_dpo_get (index_t index)
{
  return (pool_elt_at_index (ip_pmtu_dpo_pool, index));
}

extern ip_pmtu_t *ip_pmtu_pool;
static_always_inline ip_pmtu_t *
ip_path_mtu_get (index_t index)
{
  return (pool_elt_at_index (ip_pmtu_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
