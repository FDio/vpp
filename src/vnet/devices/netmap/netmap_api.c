/*
 *------------------------------------------------------------------
 * netmap_api.c - netmap api
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/devices/netmap/netmap.h>

#include <net/if.h>
#include <vnet/devices/netmap/net_netmap.h>

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
_(NETMAP_CREATE, netmap_create)                                         \
_(NETMAP_DELETE, netmap_delete)                                         \
_(NETMAP_DUMP, netmap_dump)                                             \

static void
vl_api_netmap_create_t_handler (vl_api_netmap_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_netmap_create_reply_t *rmp;
  int rv = 0;
  u8 *if_name = NULL;
  u32 sw_if_index;

  if_name = format (0, "%s", mp->netmap_if_name);
  vec_add1 (if_name, 0);

  rv =
    netmap_create_if (vm, if_name, mp->use_random_hw_addr ? 0 : mp->hw_addr,
		      mp->is_pipe, mp->is_master, &sw_if_index);

  vec_free (if_name);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_NETMAP_CREATE_REPLY,
  ({
    rmp->sw_if_index = clib_host_to_net_u32(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_netmap_delete_t_handler (vl_api_netmap_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_netmap_delete_reply_t *rmp;
  int rv = 0;
  u8 *if_name = NULL;

  if_name = format (0, "%s", mp->netmap_if_name);
  vec_add1 (if_name, 0);

  rv = netmap_delete_if (vm, if_name);

  vec_free (if_name);

  REPLY_MACRO (VL_API_NETMAP_DELETE_REPLY);
}

static void
send_netmap_details (vl_api_registration_t *reg, netmap_if_t *nif, u32 context)
{
        vl_api_netmap_details_t *mp;
        u32 len;
        u32 nr_reg = nif->req->nr_flags & NR_REG_MASK;

        mp = vl_msg_api_alloc (sizeof (*mp));
        clib_memset (mp, 0, sizeof (*mp));
        mp->_vl_msg_id = htons (VL_API_NETMAP_DETAILS);
        mp->sw_if_index = htonl (nif->sw_if_index);

        mp->is_pipe = ((nr_reg == NR_REG_PIPE_MASTER) || (nr_reg == NR_REG_PIPE_SLAVE)) ? true : false;
        mp->is_master = (nr_reg == NR_REG_PIPE_MASTER) ? true : false;

        len = ((ARRAY_LEN (mp->netmap_if_name) - 1) < strlen ((const char *) nif->host_if_name)) ? (ARRAY_LEN (mp->netmap_if_name) - 1) : strlen ((const char *) nif->host_if_name);
        clib_memcpy (mp->netmap_if_name, nif->host_if_name, len);

        mp->context = context;
        vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_netmap_dump_t_handler (vl_api_netmap_dump_t * mp)
{
        netmap_main_t *nm = &netmap_main;
        netmap_if_t *nif;
        vl_api_registration_t *reg;

        reg = vl_api_client_index_to_registration (mp->client_index);
        if (!reg)
          return;

        /* *INDENT-OFF* */
        pool_foreach (nif, nm->interfaces,
          ({
            send_netmap_details (reg, nif, mp->context);
          }));
        /* *INDENT-ON* */
}

/*
 * netmap_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
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
  foreach_vl_msg_name_crc_netmap;
#undef _
}

static clib_error_t *
netmap_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (netmap_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
