/* Copyright (c) 2024 Cisco and/or its affiliates.
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
 * limitations under the License. */

#ifndef macvlan_h__
#define macvlan_h__

#include <stdbool.h>
#include <vlib/vlib.h>

clib_error_t *macvlan_parse_add_del (unformat_input_t *input,
				     u32 *parent_sw_if_index,
				     u32 *child_sw_if_index, bool *is_add);

int macvlan_add_del (u32 parent_sw_if_index, u32 child_sw_if_index,
		     bool is_add);

#endif /* macvlan_h__ */
