
/*
 * cltest.h - classifer test plugin header file
 *
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
#ifndef __included_cltest_h__
#define __included_cltest_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

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
} cltest_main_t;

extern cltest_main_t cltest_main;

extern vlib_node_registration_t cltest_node;
extern vlib_node_registration_t cltest_periodic_node;

/* Periodic function events */
#define CLTEST_EVENT1 1
#define CLTEST_EVENT2 2
#define CLTEST_EVENT_PERIODIC_ENABLE_DISABLE 3

void cltest_create_periodic_process (cltest_main_t *);

#endif /* __included_cltest_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
