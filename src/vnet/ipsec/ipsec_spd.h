/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __IPSEC_SPD_H__
#define __IPSEC_SPD_H__

#include <vlib/vlib.h>

struct ipsec_policy_t_;

/**
 * @brief A Secruity Policy Database
 */
typedef struct ipsec_spd_t_
{
  u32 id;
  /* pool of policies */
  struct ipsec_policy_t_ *policies;
  /* vectors of policy indices */
  u32 *ipv4_outbound_policies;
  u32 *ipv6_outbound_policies;
  u32 *ipv4_inbound_protect_policy_indices;
  u32 *ipv4_inbound_policy_discard_and_bypass_indices;
  u32 *ipv6_inbound_protect_policy_indices;
  u32 *ipv6_inbound_policy_discard_and_bypass_indices;
} ipsec_spd_t;

/**
 * @brief Add/Delete a SPD
 */
extern int ipsec_add_del_spd (vlib_main_t * vm, u32 spd_id, int is_add);

/**
 * @brief Bind/attach a SPD to an interface
 */
extern int ipsec_set_interface_spd (vlib_main_t * vm,
				    u32 sw_if_index, u32 spd_id, int is_add);

#endif /* __IPSEC_SPD_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
