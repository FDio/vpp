/*
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
 */

#include <stddef.h>

#include <plugins/arp/arp.h>

#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <arp/arp.api_enum.h>
#include <arp/arp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 arp_base_msg_id;
#define REPLY_MSG_ID_BASE arp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_proxy_arp_add_del_t_handler (vl_api_proxy_arp_add_del_t * mp)
{
  vl_api_proxy_arp_add_del_reply_t *rmp;
  ip4_address_t lo, hi;
  u32 fib_index;
  int rv;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->proxy.table_id));

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  ip4_address_decode (mp->proxy.low, &lo);
  ip4_address_decode (mp->proxy.hi, &hi);

  if (mp->is_add)
    rv = arp_proxy_add (fib_index, &lo, &hi);
  else
    rv = arp_proxy_del (fib_index, &lo, &hi);

out:
  REPLY_MACRO (VL_API_PROXY_ARP_ADD_DEL_REPLY);
}

typedef struct proxy_arp_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} proxy_arp_walk_ctx_t;

static walk_rc_t
send_proxy_arp_details (const ip4_address_t * lo_addr,
			const ip4_address_t * hi_addr,
			u32 fib_index, void *data)
{
  vl_api_proxy_arp_details_t *mp;
  proxy_arp_walk_ctx_t *ctx;

  ctx = data;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_PROXY_ARP_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;
  mp->proxy.table_id = htonl (fib_index);

  ip4_address_encode (lo_addr, mp->proxy.low);
  ip4_address_encode (hi_addr, mp->proxy.hi);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_proxy_arp_dump_t_handler (vl_api_proxy_arp_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  proxy_arp_walk_ctx_t wctx = {
    .reg = reg,
    .context = mp->context,
  };

  proxy_arp_walk (send_proxy_arp_details, &wctx);
}

static walk_rc_t
send_proxy_arp_intfc_details (u32 sw_if_index, void *data)
{
  vl_api_proxy_arp_intfc_details_t *mp;
  proxy_arp_walk_ctx_t *ctx;

  ctx = data;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_PROXY_ARP_INTFC_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;
  mp->sw_if_index = htonl (sw_if_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_proxy_arp_intfc_dump_t_handler (vl_api_proxy_arp_intfc_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  proxy_arp_walk_ctx_t wctx = {
    .reg = reg,
    .context = mp->context,
  };

  proxy_arp_intfc_walk (send_proxy_arp_intfc_details, &wctx);
}

static void
  vl_api_proxy_arp_intfc_enable_disable_t_handler
  (vl_api_proxy_arp_intfc_enable_disable_t * mp)
{
  vl_api_proxy_arp_intfc_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->enable)
    rv = arp_proxy_enable (ntohl (mp->sw_if_index));
  else
    rv = arp_proxy_disable (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY);
}

#include <arp/arp.api.c>

static clib_error_t *
arp_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  arp_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (arp_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Address Resolution Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
