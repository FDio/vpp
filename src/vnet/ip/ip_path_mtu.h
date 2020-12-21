/*
 *------------------------------------------------------------------
 * ip_path_mtu.h
 *
 * Copyright (c) 2020 Graphiant.
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
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * The protocol of packets using this DPO
   */
  dpo_proto_t ipm_proto;

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

extern int ip_path_mtu_update (const ip_address_t *nh, u32 table_id, u16 pmtu);

typedef walk_rc_t (*ip_path_mtu_walk_t) (const ip_address_t *nh, u32 table_id,
					 u16 pmtu, void *ctx);

extern void ip_path_mtu_walk (ip_path_mtu_walk_t fn, void *ctx);

/**
 * Data-plane accessor functions
 */
extern ip_pmtu_dpo_t *ip_pmtu_dpo_pool;
static_always_inline ip_pmtu_dpo_t *
ip_pmtu_dpo_get (index_t index)
{
  return (pool_elt_at_index (ip_pmtu_dpo_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
