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

/**
 * Send DAD event to registered clients (overrides weak symbol from ip6_dad.c)
 */
void
ip6_dad_send_event (u32 sw_if_index, const ip6_address_t *address, ip6_dad_state_e state,
		    u8 dad_count, u8 dad_transmits)
{
  ip6_dad_main_t *dm = &ip6_dad_main;
  vl_api_ip6_dad_event_t *mp;
  ip6_dad_event_registration_t *reg;

  /* Send to all registered clients */
  pool_foreach (reg, dm->dad_event_registrations)
    {
      vl_api_registration_t *vl_reg;

      vl_reg = vl_api_client_index_to_registration (reg->client_index);
      if (!vl_reg)
	continue; /* Client disconnected */

      mp = vl_msg_api_alloc (sizeof (*mp));
      clib_memset (mp, 0, sizeof (*mp));

      mp->_vl_msg_id = ntohs (VL_API_IP6_DAD_EVENT + REPLY_MSG_ID_BASE);
      mp->client_index = reg->client_index;
      mp->pid = reg->client_pid;
      mp->state = state;
      mp->sw_if_index = htonl (sw_if_index);
      clib_memcpy (&mp->address, address, sizeof (mp->address));
      mp->dad_count = dad_count;
      mp->dad_transmits = dad_transmits;

      vl_api_send_msg (vl_reg, (u8 *) mp);
    }
}

static void
vl_api_ip6_dad_enable_disable_t_handler (vl_api_ip6_dad_enable_disable_t *mp)
{
  vl_api_ip6_dad_enable_disable_reply_t *rmp;
  ip6_dad_main_t *dm = &ip6_dad_main;
  int rv = 0;

  /* Validate parameters before applying (RFC 4862 defaults: 1 transmit, 1s delay) */
  if (mp->enable && mp->dad_transmits != 0)
    {
      if (mp->dad_transmits < 1 || mp->dad_transmits > 10)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto reply;
	}
    }

  if (mp->enable && mp->dad_retransmit_delay != 0.0)
    {
      if (mp->dad_retransmit_delay < 0.1 || mp->dad_retransmit_delay > 10.0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE_2;
	  goto reply;
	}
    }

  /* Enable or disable DAD */
  ip6_dad_enable_disable (mp->enable);

  /* Update configuration if enabled and parameters provided */
  if (mp->enable)
    {
      if (mp->dad_transmits != 0)
	dm->dad_transmits_default = mp->dad_transmits;
      if (mp->dad_retransmit_delay != 0.0)
	dm->dad_retransmit_delay_default = mp->dad_retransmit_delay;
    }

reply:
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

static void
vl_api_want_ip6_dad_events_t_handler (vl_api_want_ip6_dad_events_t *mp)
{
  vl_api_want_ip6_dad_events_reply_t *rmp;
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_event_registration_t *reg;
  int rv = 0;

  if (mp->enable_disable)
    {
      /* Register this client */
      bool already_registered = false;

      /* Check if already registered */
      pool_foreach (reg, dm->dad_event_registrations)
	{
	  if (reg->client_index == mp->client_index)
	    {
	      already_registered = true;
	      break;
	    }
	}

      if (!already_registered)
	{
	  pool_get (dm->dad_event_registrations, reg);
	  reg->client_index = mp->client_index;
	  reg->client_pid = mp->pid;

	  vlib_log_notice (dm->log_class, "Client %u registered for DAD events", mp->client_index);
	}
    }
  else
    {
      /* Unregister this client */
      pool_foreach (reg, dm->dad_event_registrations)
	{
	  if (reg->client_index == mp->client_index)
	    {
	      pool_put (dm->dad_event_registrations, reg);
	      vlib_log_notice (dm->log_class, "Client %u unregistered from DAD events",
			       mp->client_index);
	      break;
	    }
	}
    }

  REPLY_MACRO (VL_API_WANT_IP6_DAD_EVENTS_REPLY);
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
