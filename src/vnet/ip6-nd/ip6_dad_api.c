/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip6-nd/ip6_dad.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <vnet/ip6-nd/ip6_dad.api_enum.h>
#include <vnet/ip6-nd/ip6_dad.api_types.h>

/**
 * Base message ID for the plugin
 */
static u32 ip6_dad_base_msg_id;
#define REPLY_MSG_ID_BASE ip6_dad_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_ip6_dad_enable_disable_t_handler (vl_api_ip6_dad_enable_disable_t *mp)
{
  vl_api_ip6_dad_enable_disable_reply_t *rmp;
  ip6_dad_main_t *dm = &ip6_dad_main;
  int rv = 0;

  /* Enable or disable DAD */
  ip6_dad_enable_disable (mp->enable);

  /* Update configuration if enabled */
  if (mp->enable)
    {
      dm->dad_transmits_default = mp->dad_transmits;
      dm->dad_retransmit_delay_default = mp->dad_retransmit_delay;
    }

  REPLY_MACRO (VL_API_IP6_DAD_ENABLE_DISABLE_REPLY);
}

static void
send_ip6_dad_details (vl_api_registration_t *reg, u32 context, ip6_dad_main_t *dm)
{
  vl_api_ip6_dad_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP6_DAD_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = context;
  mp->enabled = dm->dad_enabled;
  mp->dad_transmits = dm->dad_transmits_default;
  mp->dad_retransmit_delay = dm->dad_retransmit_delay_default;

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_ip6_dad_dump_t_handler (vl_api_ip6_dad_dump_t *mp)
{
  vl_api_registration_t *reg;
  ip6_dad_main_t *dm = &ip6_dad_main;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  send_ip6_dad_details (reg, mp->context, dm);
}

#include <vnet/ip6-nd/ip6_dad.api.c>

static clib_error_t *
ip6_dad_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  ip6_dad_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (ip6_dad_api_init);
