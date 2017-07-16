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

#ifndef __span_h__
#define __span_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_output.h>

typedef enum
{
  SPAN_FEAT_DEVICE,
  SPAN_FEAT_L2,
  SPAN_FEAT_N
} span_feat_t;

typedef struct
{
  clib_bitmap_t *mirror_ports;
  u32 num_mirror_ports;
} span_mirror_t;

typedef struct
{
  span_mirror_t mirror_rxtx[SPAN_FEAT_N][VLIB_N_RX_TX];
} span_interface_t;

typedef struct
{
  /* l2 feature Next nodes */
  u32 l2_input_next[32];
  u32 l2_output_next[32];

  /* per-interface vector of span instances */
  span_interface_t *interfaces;

  /* biggest sw_if_index used so far */
  u32 max_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} span_main_t;

span_main_t span_main;

typedef struct
{
  u32 src_sw_if_index;		/* mirrored interface index */
  u32 mirror_sw_if_index;	/* output interface index */
} span_trace_t;

#endif /* __span_h__ */

int
span_add_delete_entry (vlib_main_t * vm, u32 src_sw_if_index,
		       u32 dst_sw_if_index, u8 state, span_feat_t sf);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
