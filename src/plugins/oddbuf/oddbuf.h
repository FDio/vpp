
/*
 * oddbuf.h - awkward chained buffer geometry test tool
 *
 * Copyright (c) 2019 by Cisco and/or its affiliates.
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
#ifndef __included_oddbuf_h__
#define __included_oddbuf_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;

  /* config parameters */
  int n_to_copy;
  int second_chunk_offset;
  int first_chunk_offset;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} oddbuf_main_t;

extern oddbuf_main_t oddbuf_main;

extern vlib_node_registration_t oddbuf_node;

#endif /* __included_oddbuf_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
