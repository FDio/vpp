/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or arnated to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_rnat_h
#define included_rnat_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/adj/adj_types.h>

/**
 * @brief A representation of a RNAT rule
 */
typedef struct
{
  /**
   * Required for pool_get_aligned
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * The source address rewrite to use
   */
  ip_address_t src;

  /**
   * The dest address rewrite to use
   */
  ip_address_t dst;

  /**
   * The rule next-hop
   */
  fib_prefix_t nh;

  u32 hw_if_index;
  u32 sw_if_index;

  u32 dev_instance;
} rnat_rule_t;

typedef struct
{
  ip_address_t src;
  ip_address_t dst;
  ip_address_t nh;
} rnat_rule_hk_t;

/**
 * @brief RNAT related global data
 */
typedef struct
{
  /**
   * pool of rule instances
   */
  rnat_rule_t *rules;

  /**
   * Hash mapping to rule with src/dst/nh
   */
  uword *rules_ht;

  /**
   * Mapping from sw_if_index to rule index
   */
  u32 *rule_index_by_sw_if_index;

  u16 msg_id_base;
} rnat_main_t;

extern rnat_main_t rnat_main;

typedef struct
{
  u8 is_del;
  ip_address_t src;
  ip_address_t dst;
  ip_address_t nh;
} rnat_add_del_args_t;

extern int rnat_add_del (const rnat_add_del_args_t *a, u32 *sw_if_index);

#endif /* included_rnat_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
