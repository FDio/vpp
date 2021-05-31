
/*
 * nodebench.h - skeleton vpp engine plug-in header file
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
#ifndef __included_nodebench_h__
#define __included_nodebench_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  u64 delta_t;
  u16 orig_next_index;
} nodebench_opaque2_t;

#define nodebench_buffer(b)                                                   \
  ((nodebench_opaque2_t *) (((u8 *) (b)->opaque2) +                           \
			    sizeof (vnet_buffer_opaque2_t) -                  \
			    sizeof (nodebench_opaque2_t)))

STATIC_ASSERT (sizeof (nodebench_opaque2_t) <= 16,
	       "VNET buffer opaque2 appended nodebench meta-data too large "
	       "for vlib_buffer");

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;
  /* Node index, non-zero if the periodic process has been created */
  u32 periodic_node_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;

  u8 *benched_node_name;
  u32 benched_node_index;
  u8 benched_node_next_index;
  u8 benched_feature_arc_index;

  u32 warmup_vectors;
  u32 measured_clocks;

} nodebench_main_t;

extern nodebench_main_t nodebench_main;

extern vlib_node_registration_t nodebench_node;
extern vlib_node_registration_t nodebench_sink_node;
extern vlib_node_registration_t nodebench_periodic_node;

/* Periodic function events */
#define NODEBENCH_EVENT1			1
#define NODEBENCH_EVENT2			2
#define NODEBENCH_EVENT_PERIODIC_ENABLE_DISABLE 3

void nodebench_create_periodic_process (nodebench_main_t *);

#endif /* __included_nodebench_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
