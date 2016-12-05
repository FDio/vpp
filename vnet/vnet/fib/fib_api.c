/*
 *------------------------------------------------------------------
 * fib_api.c - forwarding information base api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/api_errno.h>
#include <vnet/fib/fib_table.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(SW_INTERFACE_GET_TABLE, sw_interface_get_table)

static void
send_sw_interface_get_table_reply (unix_shared_memory_queue_t * q,
				   u32 context, int retval, u32 vrf_id)
{
  vl_api_sw_interface_get_table_reply_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_GET_TABLE_REPLY);
  mp->context = context;
  mp->retval = htonl (retval);
  mp->vrf_id = htonl (vrf_id);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_interface_get_table_t_handler (vl_api_sw_interface_get_table_t * mp)
{
  unix_shared_memory_queue_t *q;
  fib_table_t *fib_table = 0;
  u32 sw_if_index = ~0;
  u32 fib_index = ~0;
  u32 table_id = ~0;
  fib_protocol_t fib_proto = FIB_PROTOCOL_IP4;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  if (mp->is_ipv6)
    fib_proto = FIB_PROTOCOL_IP6;

  fib_index = fib_table_get_index_for_sw_if_index (fib_proto, sw_if_index);
  if (fib_index != ~0)
    {
      fib_table = fib_table_get (fib_index, fib_proto);
      table_id = fib_table->ft_table_id;
    }

  BAD_SW_IF_INDEX_LABEL;

  send_sw_interface_get_table_reply (q, mp->context, rv, table_id);
}


/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_fib;
#undef _
}

static clib_error_t *
fib_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (fib_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
