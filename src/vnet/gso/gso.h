/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef included_gso_h
#define included_gso_h

#include <vnet/vnet.h>
#include <vnet/gso/hdr_offset_parser.h>

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} gso_main_t;

extern gso_main_t gso_main;

int vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable);
u32 gso_segment_buffer (vlib_main_t *vm, vnet_interface_per_thread_data_t *ptd,
			u32 bi, vlib_buffer_t *b, generic_header_offset_t *gho,
			u32 n_bytes_b, u8 is_l2, u8 is_ip6);

#endif /* included_gso_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
