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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <pppoe/pppoe.h>

typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* For deadman timers */
  clib_time_t clib_time;

} pppoe_export_main_t;

pppoe_export_main_t pppoe_export_main;


int
connect_to_vpp (char *name)
{
  pppoe_export_main_t *pem = &pppoe_export_main;
  api_main_t *am = &api_main;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  pem->vl_input_queue = am->shmem_hdr->vl_input_queue;
  pem->my_client_index = am->my_client_index;

  return 0;
}

int add_del_pppoe_session(u16 session_id,
			   const u8 *mac,
			   u16 subscriber_IP,
		           u8 is_add)
{
  ip4_main_t *im = &ip4_main;
  u32 decap_fib_index;
  int rv = 0;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (0));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }
  decap_fib_index = p[0];

  vnet_pppoe_add_del_session_args_t a = {
    .is_add = is_add,
    .is_ip6 = 0,
    .decap_fib_index = decap_fib_index,
    .session_id = ntohs (session_id),
    .client_ip = to_ip46 (0, (u8 *)&subscriber_IP),
  };
  clib_memcpy (a.client_mac, mac, 6);

  u32 sw_if_index = ~0;
  rv = vnet_pppoe_add_del_session (&a, &sw_if_index);

out:
  return rv;

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
