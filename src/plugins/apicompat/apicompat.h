
/*
 * apicompat.h - skeleton vpp engine plug-in header file
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
#ifndef __included_apicompat_h__
#define __included_apicompat_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>


#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>


typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;
  /* Node index, non-zero if the periodic process has been created */
  u32 periodic_node_index;

  svm_queue_t *q;
  u32 api_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} apicompat_main_t;

extern apicompat_main_t apicompat_main;

extern vlib_node_registration_t apicompat_node;
extern vlib_node_registration_t apicompat_periodic_node;

/* Periodic function events */
#define APICOMPAT_EVENT1 1
#define APICOMPAT_EVENT2 2
#define APICOMPAT_EVENT_PERIODIC_ENABLE_DISABLE 3

void apicompat_create_periodic_process (apicompat_main_t *);
void apicompat_send_and_handle (apicompat_main_t * amp, void *msg);
int apicompat_get_message (apicompat_main_t * amp, void **msg);



#endif /* __included_apicompat_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
