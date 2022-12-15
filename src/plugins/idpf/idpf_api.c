/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <idpf/idpf.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <idpf/idpf.api_enum.h>
#include <idpf/idpf.api_types.h>

#define REPLY_MSG_ID_BASE (im->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_idpf_create_t_handler (vl_api_idpf_create_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  idpf_main_t *im = &idpf_main;
  vl_api_idpf_create_reply_t *rmp;
  idpf_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (idpf_create_if_args_t));

  args.addr.as_u32 = ntohl (mp->pci_addr);
  args.rxq_single = ntohs (mp->rxq_single);
  args.txq_single = ntohs (mp->txq_single);
  args.rxq_num = ntohs (mp->rxq_num);
  args.txq_num = ntohs (mp->txq_num);
  args.rxq_size = ntohs (mp->rxq_size);
  args.txq_size = ntohs (mp->txq_size);
  args.req_vport_nb = ntohs (mp->req_vport_nb);

  idpf_create_if (vm, &args);
  rv = args.rv;

  REPLY_MACRO2 (VL_API_IDPF_CREATE_REPLY,
		({ rmp->sw_if_index = ntohl (args.sw_if_index); }));
}

static void
vl_api_idpf_delete_t_handler (vl_api_idpf_delete_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  idpf_main_t *im = &idpf_main;
  vl_api_idpf_delete_reply_t *rmp;
  vnet_hw_interface_t *hw;
  int rv = 0;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						      htonl (mp->sw_if_index));
  if (hw == NULL || idpf_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  vlib_process_signal_event (vm, idpf_process_node.index,
			     IDPF_PROCESS_EVENT_DELETE_IF, hw->dev_instance);

reply:
  REPLY_MACRO (VL_API_IDPF_DELETE_REPLY);
}

/* set tup the API message handling tables */
#include <idpf/idpf.api.c>
static clib_error_t *
idpf_plugin_api_hookup (vlib_main_t *vm)
{
  idpf_main_t *ivm = &idpf_main;
  api_main_t *am = vlibapi_get_main ();

  /* ask for a correctly-sized block of API message decode slots */
  ivm->msg_id_base = setup_message_id_table ();

  vl_api_set_msg_thread_safe (am, ivm->msg_id_base + VL_API_IDPF_DELETE, 1);

  return 0;
}

VLIB_API_INIT_FUNCTION (idpf_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
