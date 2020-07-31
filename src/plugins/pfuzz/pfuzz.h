
/*
 * pfuzz.h - helper plugin for fuzzing VPP
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
#ifndef __included_pfuzz_h__
#define __included_pfuzz_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define foreach_pfuzz_mode                      \
_(FUZZ, "fuzz")				\
_(REPLAY, "replay")


typedef enum
{
#define _(n,s) PFUZZ_MODE_##n,
  foreach_pfuzz_mode
#undef _
} pfuzz_mode_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* config parameters */
  u8 mode;
  /* the file descriptor from which to replay data */
  i32 replay_fd;
  u8 use_blackbox;
  /* random seed */
  u32 seed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} pfuzz_main_t;

extern pfuzz_main_t pfuzz_main;

extern vlib_node_registration_t pfuzz_node;

#endif /* __included_pfuzz_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
