/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_capo_interface_h
#define included_capo_interface_h

#include <vppinfra/clib.h>

typedef struct
{
  u32 *rx_policies;
  u32 *tx_policies;
  u32 *profiles;
  u8 invert_rx_tx;
  u8 policy_default_rx;
  u8 policy_default_tx;
  u8 profile_default_rx;
  u8 profile_default_tx;
} capo_interface_config_t;

int capo_configure_policies (u32 sw_if_index, u32 num_rx_policies,
			     u32 num_tx_policies, u32 num_profiles,
			     u32 *policy_ids, u8 invert_rx_tx,
			     u8 policy_default_rx, u8 policy_default_tx,
			     u8 profile_default_rx, u8 profile_default_tx);
u8 *format_capo_interface (u8 *s, va_list *args);

STATIC_ASSERT (sizeof (capo_interface_config_t) <=
		 (sizeof (clib_bihash_kv_8_32_t) -
		  STRUCT_OFFSET_OF (clib_bihash_kv_8_32_t, value)),
	       "bihash value size");

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
