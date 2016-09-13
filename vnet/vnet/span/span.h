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

#ifndef __span_h__
#define __span_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#if DPDK==1
#include <vnet/dpdk_replication.h>

#define VLIB_NODE_FLAG_IS_SPAN (1 << 8)

typedef struct
{
  /* destination interface index by source interface index */
  uword *dst_sw_if_index_by_src;
  u32 *free_span_out_nodes;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} span_main_t;

span_main_t span_main;

extern vlib_node_registration_t span_node;

typedef struct
{
  u32 src_sw_if_index;		/* mirrored interface index */
  u32 mirror_sw_if_index;	/* output interface index */
} span_trace_t;

vlib_buffer_t *span_duplicate_buffer (vlib_main_t * vm,
				      vlib_buffer_t * b0,
				      uword span_if_index, u8 copy);

uword
span_out_register_node (vlib_main_t * vm,
			u32 src_sw_if_index, u32 dst_sw_if_index, u8 disable);

clib_error_t *set_span_add_delete_entry (vlib_main_t * vm,
					 u32 src_sw_if_index,
					 u32 dst_sw_if_index, u8 disable);
#endif

#endif /* __span_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
