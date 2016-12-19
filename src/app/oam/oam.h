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
#ifndef __included_oam_h__
#define __included_oam_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

/* 36 octets, make a note of it... */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  icmp46_header_t icmp;
  u16 id;
  u16 seq;
  u8 data[8];
}) oam_template_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u64 v8[4];
  u32 v4;
}) oam_template_copy_t;
/* *INDENT-ON* */

typedef enum
{
  OAM_STATE_UNKNOWN = 0,
  OAM_STATE_ALIVE,
  OAM_STATE_DEAD,
} oam_state_t;

typedef struct
{
  ip4_address_t src_address;
  ip4_address_t dst_address;
  u32 fib_id;
  u32 fib_index;
  f64 last_heard_time;
  u16 seq;
  u16 last_heard_seq;
  u16 id;
  u8 state;
  oam_template_t *template;
} oam_target_t;

typedef struct
{
  /* OAM targets */
  oam_target_t *targets;
  uword *target_by_address_and_fib_id;

  /* Config parameters */
  f64 interval;
  u32 misses_allowed;

  /* random number seed */
  u32 random_seed;
  u16 icmp_id;

  /* oam packet template */
  vlib_packet_template_t packet_template;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} oam_main_t;

int vpe_oam_add_del_target (ip4_address_t * src_address,
			    ip4_address_t * dst_address,
			    u32 fib_id, int is_add);

#endif /* __included_oam_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
