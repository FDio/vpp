/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vnet/ip/ip_types_api.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <crypto_sw_scheduler/crypto_sw_scheduler.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <crypto_sw_scheduler/crypto_sw_scheduler.api_enum.h>
#include <crypto_sw_scheduler/crypto_sw_scheduler.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 crypto_sw_scheduler_base_msg_id;

#define REPLY_MSG_ID_BASE crypto_sw_scheduler_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_crypto_sw_scheduler_set_worker_t_handler
  (vl_api_crypto_sw_scheduler_set_worker_t * mp)
{
  vl_api_crypto_sw_scheduler_set_worker_reply_t *rmp;
  u32 worker_index;
  u8 crypto_enable;
  int rv;

  worker_index = ntohl (mp->worker_index);
  crypto_enable = mp->crypto_enable;

  rv = crypto_sw_scheduler_set_worker_crypto (worker_index, crypto_enable);

  REPLY_MACRO (VL_API_CRYPTO_SW_SCHEDULER_SET_WORKER_REPLY);
}

#include <crypto_sw_scheduler/crypto_sw_scheduler.api.c>

clib_error_t *
crypto_sw_scheduler_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  crypto_sw_scheduler_base_msg_id = setup_message_id_table ();

  return 0;
}
