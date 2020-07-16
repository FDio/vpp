/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT66 global declarations
 */
#ifndef __included_nat66_h__
#define __included_nat66_h__

#include <vnet/ip/ip.h>
#include <vppinfra/bihash_24_8.h>

typedef struct
{
  ip6_address_t l_addr;
  ip6_address_t e_addr;
  u32 fib_index;
} nat66_static_mapping_t;

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t addr;
      u32 fib_index;
      u32 rsvd;
    };
    u64 as_u64[3];
  };
} nat66_sm_key_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} nat66_interface_t;
#define NAT66_INTERFACE_FLAG_IS_INSIDE 1
#define NAT66_INTERFACE_FLAG_IS_OUTSIDE 2
#define nat66_interface_is_inside(i) i->flags & NAT66_INTERFACE_FLAG_IS_INSIDE
#define nat66_interface_is_outside(i) i->flags & NAT66_INTERFACE_FLAG_IS_OUTSIDE

typedef struct
{
  /** Interface pool */
  nat66_interface_t *interfaces;
  /** Static mapping pool */
  nat66_static_mapping_t *sm;
  /** Static mapping by local address lookup table */
  clib_bihash_24_8_t sm_l;
  /** Static mapping by external address lookup table */
  clib_bihash_24_8_t sm_e;
  /** Session counters */
  vlib_combined_counter_main_t session_counters;
  /** node index **/
  u32 in2out_node_index;
  u32 out2in_node_index;

  u32 outside_vrf_id;
  u32 outside_fib_index;

  u16 msg_id_base;
  u8 log_level;

  vlib_simple_counter_main_t in2out_packets;
  vlib_simple_counter_main_t out2in_packets;;
} nat66_main_t;

#define nat66_elog(_level, _str)                         \
do                                                       \
  {                                                      \
    nat66_main_t *nm = &nat66_main;                      \
    if (PREDICT_FALSE (nm->log_level >= _level))         \
      {                                                  \
        ELOG_TYPE_DECLARE (e) =                          \
          {                                              \
            .format = "nat66-msg " _str,                 \
            .format_args = "",                           \
          };                                             \
        ELOG_DATA (&vlib_global_main.elog_main, e);      \
      }                                                  \
  } while (0);

#define nat66_elog_warn(nat_elog_str) \
  nat66_elog(0x02, "[warning] " nat_elog_str)


extern nat66_main_t nat66_main;
extern vlib_node_registration_t nat66_in2out_node;
extern vlib_node_registration_t nat66_out2in_node;

typedef int (*nat66_interface_walk_fn_t) (nat66_interface_t * i, void *ctx);
void nat66_interfaces_walk (nat66_interface_walk_fn_t fn, void *ctx);
int nat66_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add);
typedef int (*nat66_static_mapping_walk_fn_t) (nat66_static_mapping_t * sm,
					       void *ctx);
void nat66_static_mappings_walk (nat66_static_mapping_walk_fn_t fn,
				 void *ctx);
nat66_static_mapping_t *nat66_static_mapping_get (ip6_address_t * addr,
						  u32 fib_index, u8 is_local);
int nat66_static_mapping_add_del (ip6_address_t * l_addr,
				  ip6_address_t * e_addr, u32 vrf_id,
				  u8 is_add);

#endif /* __included_nat66_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
