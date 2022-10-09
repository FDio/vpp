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

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vlib/vlib.h>

#define foreach_ipsec_spd_policy_type                 \
  _(IP4_OUTBOUND, "ip4-outbound")                     \
  _(IP6_OUTBOUND, "ip6-outbound")                     \
  _(IP4_INBOUND_PROTECT, "ip4-inbound-protect")       \
  _(IP6_INBOUND_PROTECT, "ip6-inbound-protect")       \
  _(IP4_INBOUND_BYPASS,  "ip4-inbound-bypass")        \
  _(IP6_INBOUND_BYPASS,  "ip6-inbound-bypass")	      \
  _(IP4_INBOUND_DISCARD,  "ip4-inbound-discard")      \
  _(IP6_INBOUND_DISCARD,  "ip6-inbound-discard")

typedef enum ipsec_spd_policy_t_
{
#define _(s,v) IPSEC_SPD_POLICY_##s,
  foreach_ipsec_spd_policy_type
#undef _
    IPSEC_SPD_POLICY_N_TYPES,
} ipsec_spd_policy_type_t;

#define FOR_EACH_IPSEC_SPD_POLICY_TYPE(_t)      \
  for (_t = 0; _t < IPSEC_SPD_POLICY_N_TYPES; _t++)

extern u8 *format_ipsec_policy_type (u8 * s, va_list * args);

typedef struct
{
  /* index in the mask types pool */
  u32 mask_type_idx;
  /* counts references correspond to given mask type index */
  u32 refcount;
} ipsec_fp_mask_id_t;

/**
 * @brief A fast path Security Policy Database
 */
typedef struct
{
  ipsec_fp_mask_id_t *fp_mask_ids[IPSEC_SPD_POLICY_N_TYPES];
  /* names of bihash tables */
  u8 *name4_out;
  u8 *name4_in;
  u8 *name6_out;
  u8 *name6_in;
  u32 ip6_out_lookup_hash_idx; /* fp ip6 lookup hash out index in the pool */
  u32 ip4_out_lookup_hash_idx; /* fp ip4 lookup hash out index in the pool */
  u32 ip6_in_lookup_hash_idx;  /* fp ip6 lookup hash in index in the pool */
  u32 ip4_in_lookup_hash_idx;  /* fp ip4 lookup hash in index in the pool */
} ipsec_spd_fp_t;

/**
 * @brief A Security Policy Database
 */
typedef struct
{
  /** the User's ID for this policy */
  u32 id;
  /** vectors for each of the policy types */
  u32 *policies[IPSEC_SPD_POLICY_N_TYPES];
  ipsec_spd_fp_t fp_spd;
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

extern u8 *format_ipsec_spd (u8 * s, va_list * args);

extern u8 *format_ipsec_out_spd_flow_cache (u8 *s, va_list *args);
extern u8 *format_ipsec_in_spd_flow_cache (u8 *s, va_list *args);

#endif /* __IPSEC_SPD_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
