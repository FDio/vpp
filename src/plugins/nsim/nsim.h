
/*
 * nsim.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_nsim_h__
#define __included_nsim_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  f64 tx_time;
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u32 output_next_index;
  u32 buffer_index;
  u32 pad;			/* pad to 32-bytes */
} nsim_wheel_entry_t;

typedef struct
{
  u32 wheel_size;
  u32 cursize;
  u32 head;
  u32 tail;
  nsim_wheel_entry_t *entries;
    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} nsim_wheel_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Two interfaces, cross-connected with delay */
  u32 sw_if_index0, sw_if_index1;
  u32 output_next_index0, output_next_index1;

  /* N interfaces, using the output feature */
  u32 *output_next_index_by_sw_if_index;

  /* Random seed for loss-rate simulation */
  u32 seed;

  /* Per-thread scheduler wheels */
  nsim_wheel_t **wheel_by_thread;

  /* Config parameters */
  f64 delay;
  f64 bandwidth;
  f64 packet_size;
  f64 drop_fraction;

  u64 mmap_size;

  /* Wheels are configured */
  int is_configured;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} nsim_main_t;

extern nsim_main_t nsim_main;

extern vlib_node_registration_t nsim_node;
extern vlib_node_registration_t nsim_input_node;

#endif /* __included_nsim_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
