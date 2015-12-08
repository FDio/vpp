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
#ifndef __included_ip6_hop_by_hop_h__
#define __included_ip6_hop_by_hop_h__

#include <vnet/ip/ip6_hop_by_hop_packet.h>

typedef struct {
  /* The current rewrite we're using */
  u8 * rewrite;

  /* Trace data processing callback */
  void *ioam_end_of_path_cb;

  /* Configured node-id */
  u32 node_id;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip6_hop_by_hop_main_t;

#endif /* __included_ip6_hop_by_hop_h__ */
