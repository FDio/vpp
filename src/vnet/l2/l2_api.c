/*
 *------------------------------------------------------------------
 * l2_api.c - layer 2 forwarding api
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
#include <vnet/l2/l2_input.h>

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
_(L2_XCONNECT_DUMP, l2_xconnect_dump)

static void
send_l2_xconnect_details (unix_shared_memory_queue_t * q, u32 context,
			  u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vl_api_l2_xconnect_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_XCONNECT_DETAILS);
  mp->context = context;
  mp->rx_sw_if_index = htonl (rx_sw_if_index);
  mp->tx_sw_if_index = htonl (tx_sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_xconnect_dump_t_handler (vl_api_l2_xconnect_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  l2input_main_t *l2im = &l2input_main;
  vnet_sw_interface_t *swif;
  l2_input_config_t *config;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    config = vec_elt_at_index (l2im->configs, swif->sw_if_index);
    if (config->xconnect)
      send_l2_xconnect_details (q, mp->context, swif->sw_if_index,
                                config->output_sw_if_index);
  }));
  /* *INDENT-ON* */
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
  foreach_vl_msg_name_crc_l2;
#undef _
}

static clib_error_t *
l2_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (l2_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
