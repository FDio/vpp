/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <af_xdp/af_xdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <af_xdp/af_xdp.api_enum.h>
#include <af_xdp/af_xdp.api_types.h>

#define REPLY_MSG_ID_BASE (rm->msg_id_base)
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
  if (flags & AF_XDP_API_FLAGS_MULTI_BUFFER)
    cflags |= AF_XDP_CREATE_FLAGS_MULTI_BUFFER;

  return cflags;
}

static void
vl_api_af_xdp_create_v3_t_handler (vl_api_af_xdp_create_v3_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  af_xdp_main_t *rm = &af_xdp_main;
  vl_api_af_xdp_create_v3_reply_t *rmp;
  af_xdp_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (af_xdp_create_if_args_t));

  args.linux_ifname = mp->host_if[0] ? (char *) mp->host_if : 0;
  args.name = mp->name[0] ? (char *) mp->name : 0;
  args.prog = mp->prog[0] ? (char *) mp->prog : 0;
  args.netns = mp->netns[0] ? (char *) mp->netns : 0;
  args.mode = af_xdp_api_mode (mp->mode);
  args.flags = af_xdp_api_flags (mp->flags);
  args.rxq_size = mp->rxq_size;
  args.txq_size = mp->txq_size;
  args.rxq_num = mp->rxq_num;

  af_xdp_create_if (vm, &args);
  rv = args.rv;

  /* clang-format off */
  REPLY_MACRO2_END (VL_API_AF_XDP_CREATE_V3_REPLY,
    ({
      rmp->sw_if_index = args.sw_if_index;
    }));
  /* clang-format on */
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
  REPLY_MACRO (VL_API_AF_XDP_DELETE_REPLY);
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
