/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <vppinfra/macros.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <pppoe/pppoe.h>

#define vl_msg_id(n,h) n,
typedef enum
{
#include <pppoe/pppoe.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <pppoe/pppoe.api.h>
#undef vl_typedefs


typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  volatile u32 result_ready;
  volatile i32 retval;
  volatile u32 sw_if_index;
  volatile u8 *shmem_result;
  volatile u8 *cmd_reply;

  /* API client handle */
  u32 my_client_index;

  /* For deadman timers */
  clib_time_t clib_time;

} pppoe_export_main_t;

pppoe_export_main_t pppoe_export_main;

int
connect_to_vpp (const char *name)
{
  pppoe_export_main_t *pem = &pppoe_export_main;
  api_main_t *am = &api_main;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  pem->vl_input_queue = am->shmem_hdr->vl_input_queue;
  pem->my_client_index = am->my_client_index;

  return 0;
}

int
add_del_pppoe_session (u16 session_id,
		       const u8 * mac, u32 subscriber_IP, u8 is_add)
{
  pppoe_export_main_t *pexpm = &pppoe_export_main;
  pppoe_main_t *pem = &pppoe_main;
  vl_api_pppoe_add_del_session_t *mp;
  u32 decap_vrf_id = 0;
  u32 client_ip = 0;

#if 0
  u8 *name = format (0, "pppoe_%08x%c", api_version, 0);
  pem->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);
#endif
  pem->msg_id_base = 10000;

  do
    {
      pexpm->result_ready = 0;
      mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
      memset (mp, 0, sizeof (*mp));
      mp->_vl_msg_id =
	htons (VL_API_PPPOE_ADD_DEL_SESSION + pem->msg_id_base);
      mp->client_index = pexpm->my_client_index;
    }
  while (0);

  client_ip = htonl (subscriber_IP);
  clib_memcpy (mp->client_ip, &client_ip, sizeof (client_ip));

  mp->decap_vrf_id = htonl (decap_vrf_id);
  mp->session_id = htons (session_id);
  mp->is_add = is_add;
  mp->is_ipv6 = 0;
  clib_memcpy (mp->client_mac, mac, 6);

  vl_msg_api_send_shmem (pexpm->vl_input_queue, (u8 *) & mp);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
