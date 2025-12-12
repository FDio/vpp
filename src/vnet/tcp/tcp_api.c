/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

/*
 * tcp_api.c - vnet tcp-layer apis
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/tcp/tcp.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>

#include <vnet/tcp/tcp.api_enum.h>
#include <vnet/tcp/tcp.api_types.h>

#define REPLY_MSG_ID_BASE tcp_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_tcp_configure_src_addresses_t_handler
  (vl_api_tcp_configure_src_addresses_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_tcp_configure_src_addresses_reply_t *rmp;
  u32 vrf_id;
  int rv;
  ip46_address_t first_address, last_address;
  ip46_type_t fa_af, la_af;

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);

  fa_af = ip_address_decode (&mp->first_address, &first_address);
  la_af = ip_address_decode (&mp->last_address, &last_address);

  if (fa_af != la_af)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto error;
    }

  if (fa_af == IP46_TYPE_IP6)
    rv = tcp_configure_v6_source_address_range
      (vm, &first_address.ip6, &last_address.ip6, vrf_id);
  else
    rv = tcp_configure_v4_source_address_range
      (vm, &first_address.ip4, &last_address.ip4, vrf_id);

error:
  REPLY_MACRO (VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY);
}

#include <vnet/tcp/tcp.api.c>
static clib_error_t *
tcp_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (tcp_api_hookup);
