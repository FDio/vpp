/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Arm Limited.
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
#include <vnet/ethernet/ethernet.h>

#include <marvell/pp2/pp2.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <marvell/pp2/pp2.api_enum.h>
#include <marvell/pp2/pp2.api_types.h>

#include <vlibapi/api_helper_macros.h>

static void
vl_api_mrvl_pp2_create_t_handler (vl_api_mrvl_pp2_create_t * mp)
{
  mrvl_pp2_main_t *pp2 = &mrvl_pp2_main;
  mrvl_pp2_create_if_args_t args = { 0 };
  vl_api_mrvl_pp2_create_reply_t *rmp;
  int rv;

  args.name = format (0, "%s", mp->if_name);
  args.rx_q_sz = ntohs (mp->rx_q_sz);
  args.tx_q_sz = ntohs (mp->tx_q_sz);
  mrvl_pp2_create_if (&args);
  rv = args.rv;
  vec_free (args.name);
  if (args.error)
    {
      clib_error_free (args.error);
    }
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MRVL_PP2_CREATE_REPLY + pp2->msg_id_base,
    ({
      rmp->sw_if_index = ntohl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_mrvl_pp2_delete_t_handler (vl_api_mrvl_pp2_delete_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  mrvl_pp2_main_t *pp2 = &mrvl_pp2_main;
  vl_api_mrvl_pp2_delete_reply_t *rmp;
  mrvl_pp2_if_t *dif;
  int rv = 0;
  mp->sw_if_index = ntohl (mp->sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, mp->sw_if_index);
  if (hw == NULL || mrvl_pp2_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto reply;
    }

  dif = pool_elt_at_index (pp2->interfaces, hw->dev_instance);

  mrvl_pp2_delete_if (dif);

reply:
  REPLY_MACRO (VL_API_MRVL_PP2_DELETE_REPLY + pp2->msg_id_base);
}

#include <marvell/pp2/pp2.api.c>
/* set up the API message handling tables */
clib_error_t *
mrvl_pp2_plugin_api_hookup (vlib_main_t * vm)
{
  mrvl_pp2_main_t *pp2 = &mrvl_pp2_main;

  /* ask for a correctly-sized block of API message decode slots */
  pp2->msg_id_base = setup_message_id_table ();

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
