/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <rdma/rdma.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <rdma/rdma.api_enum.h>
#include <rdma/rdma.api_types.h>

#include <vlibapi/api_helper_macros.h>

static void
vl_api_rdma_create_t_handler (vl_api_rdma_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  rdma_main_t *rm = &rdma_main;
  vl_api_rdma_create_reply_t *rmp;
  rdma_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (rdma_create_if_args_t));

  args.ifname = mp->host_if;
  args.name = mp->name;
  args.rxq_num = ntohs (mp->rxq_num);
  args.rxq_size = ntohs (mp->rxq_size);
  args.txq_size = ntohs (mp->txq_size);

  rdma_create_if (vm, &args);
  rv = args.rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_RDMA_CREATE_REPLY + rm->msg_id_base,
    ({
      rmp->sw_if_index = ntohl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_rdma_delete_t_handler (vl_api_rdma_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *rm = &rdma_main;
  vl_api_rdma_delete_reply_t *rmp;
  rdma_device_t *rd;
  vnet_hw_interface_t *hw;
  int rv = 0;

  hw =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						   htonl (mp->sw_if_index));
  if (hw == NULL || rdma_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  rd = pool_elt_at_index (rm->devices, hw->dev_instance);

  rdma_delete_if (vm, rd);

reply:
  REPLY_MACRO (VL_API_RDMA_DELETE_REPLY + rm->msg_id_base);
}

/* set tup the API message handling tables */
#include <rdma/rdma.api.c>
static clib_error_t *
rdma_plugin_api_hookup (vlib_main_t * vm)
{
  rdma_main_t *rm = &rdma_main;

  /* ask for a correctly-sized block of API message decode slots */
  rm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (rdma_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
