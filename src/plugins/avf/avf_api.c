/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <avf/avf.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <avf/avf.api_enum.h>
#include <avf/avf.api_types.h>

#include <vlibapi/api_helper_macros.h>

static void
vl_api_avf_create_t_handler (vl_api_avf_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  avf_main_t *am = &avf_main;
  vl_api_avf_create_reply_t *rmp;
  avf_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (avf_create_if_args_t));

  args.enable_elog = ntohl (mp->enable_elog);
  args.addr.as_u32 = ntohl (mp->pci_addr);
  args.rxq_num = ntohs (mp->rxq_num);
  args.rxq_size = ntohs (mp->rxq_size);
  args.txq_size = ntohs (mp->txq_size);

  avf_create_if (vm, &args);
  rv = args.rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_AVF_CREATE_REPLY + am->msg_id_base,
    ({
      rmp->sw_if_index = ntohl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_avf_delete_t_handler (vl_api_avf_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  vl_api_avf_delete_reply_t *rmp;
  avf_device_t *ad;
  vnet_hw_interface_t *hw;
  int rv = 0;

  hw =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						   htonl (mp->sw_if_index));
  if (hw == NULL || avf_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  avf_delete_if (vm, ad);

reply:
  REPLY_MACRO (VL_API_AVF_DELETE_REPLY + am->msg_id_base);
}

/* set tup the API message handling tables */
#include <avf/avf.api.c>
static clib_error_t *
avf_plugin_api_hookup (vlib_main_t * vm)
{
  avf_main_t *avm = &avf_main;

  /* ask for a correctly-sized block of API message decode slots */
  avm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (avf_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
