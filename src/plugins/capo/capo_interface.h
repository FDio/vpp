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

typedef CLIB_PACKED (struct
{
  u32 pass_id;
  u32 *policies;
}) capo_interface_config_t;

int capo_remove_policies(u32 sw_if_index);
int capo_configure_policies(u32 sw_if_index, u32 pass_policy_id,
                            u32 num_policies, u32 *policy_ids);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
