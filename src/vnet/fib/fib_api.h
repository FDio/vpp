/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __FIB_API_H__
#define __FIB_API_H__


int
add_del_route_check (fib_protocol_t table_proto,
		     u32 table_id,
		     u32 next_hop_sw_if_index,
		     dpo_proto_t next_hop_table_proto,
		     u32 next_hop_table_id,
                     u8 is_rpf_id,
		     u32 * fib_index, u32 * next_hop_fib_index);

int
add_del_route_t_handler (u8 is_multipath,
			 u8 is_add,
			 u8 is_drop,
			 u8 is_unreach,
			 u8 is_prohibit,
			 u8 is_local,
			 u8 is_multicast,
			 u8 is_classify,
			 u32 classify_table_index,
			 u8 is_resolve_host,
			 u8 is_resolve_attached,
			 u8 is_interface_rx,
                         u8 is_rpf_id,
			 u32 fib_index,
			 const fib_prefix_t * prefix,
			 dpo_proto_t next_hop_proto,
			 const ip46_address_t * next_hop,
			 u32 next_hop_sw_if_index,
			 u8 next_hop_fib_index,
			 u16 next_hop_weight,
			 u16 next_hop_preference,
			 mpls_label_t next_hop_via_label,
			 mpls_label_t * next_hop_out_label_stack);

void
copy_fib_next_hop (fib_route_path_encode_t * api_rpath,
		   void * fp_arg);

#endif /* __FIB_API_H__ */
