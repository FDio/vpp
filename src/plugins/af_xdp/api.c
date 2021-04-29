/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <af_xdp/af_xdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <af_xdp/af_xdp.api_enum.h>
#include <af_xdp/af_xdp.api_types.h>

#include <vlibapi/api_helper_macros.h>

static af_xdp_mode_t
af_xdp_api_mode (vl_api_af_xdp_mode_t mode)
{
  switch (mode)
    {
    case AF_XDP_API_MODE_AUTO:
      return AF_XDP_MODE_AUTO;
    case AF_XDP_API_MODE_COPY:
      return AF_XDP_MODE_COPY;
    case AF_XDP_API_MODE_ZERO_COPY:
      return AF_XDP_MODE_ZERO_COPY;
    }
  return AF_XDP_MODE_AUTO;
}

static af_xdp_create_flag_t
af_xdp_api_flags (vl_api_af_xdp_flag_t flags)
{
  af_xdp_create_flag_t cflags = 0;

  if (flags & AF_XDP_API_FLAGS_NO_SYSCALL_LOCK)
    cflags |= AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK;

  return cflags;
}

static void
vl_api_af_xdp_create_t_handler (vl_api_af_xdp_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  af_xdp_main_t *rm = &af_xdp_main;
  vl_api_af_xdp_create_reply_t *rmp;
  af_xdp_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (af_xdp_create_if_args_t));

  args.linux_ifname = mp->host_if[0] ? (char *) mp->host_if : 0;
  args.name = mp->name[0] ? (char *) mp->name : 0;
  args.prog = mp->prog[0] ? (char *) mp->prog : 0;
  args.mode = af_xdp_api_mode (mp->mode);
  args.flags = af_xdp_api_flags (mp->flags);
  args.rxq_size = ntohs (mp->rxq_size);
  args.txq_size = ntohs (mp->txq_size);
  args.rxq_num = ntohs (mp->rxq_num);

  af_xdp_create_if (vm, &args);
  rv = args.rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_AF_XDP_CREATE_REPLY + rm->msg_id_base,
    ({
      rmp->sw_if_index = ntohl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_af_xdp_delete_t_handler (vl_api_af_xdp_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  af_xdp_main_t *rm = &af_xdp_main;
  vl_api_af_xdp_delete_reply_t *rmp;
  af_xdp_device_t *rd;
  vnet_hw_interface_t *hw;
  int rv = 0;

  hw =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						   htonl (mp->sw_if_index));
  if (hw == NULL || af_xdp_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  rd = pool_elt_at_index (rm->devices, hw->dev_instance);

  af_xdp_delete_if (vm, rd);

reply:
  REPLY_MACRO (VL_API_AF_XDP_DELETE_REPLY + rm->msg_id_base);
}

/* set tup the API message handling tables */
#include <af_xdp/af_xdp.api.c>
static clib_error_t *
af_xdp_plugin_api_hookup (vlib_main_t * vm)
{
  af_xdp_main_t *rm = &af_xdp_main;

  /* ask for a correctly-sized block of API message decode slots */
  rm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (af_xdp_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
