/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <stddef.h>

#include <vnet/vnet.h>

#include <vnet/ip/ip_types_api.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/crypto/crypto.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <vnet/crypto/crypto.api_enum.h>
#include <vnet/crypto/crypto.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 crypto_base_msg_id;

#define REPLY_MSG_ID_BASE crypto_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_crypto_set_async_dispatch_t_handler (vl_api_crypto_set_async_dispatch_t
					    * mp)
{
  vl_api_crypto_set_async_dispatch_reply_t *rmp;
  int rv = 0;

  vnet_crypto_set_async_dispatch ((u8) mp->mode, 0);

  REPLY_MACRO (VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY);
}

static void
vl_api_crypto_set_async_dispatch_v2_t_handler (
  vl_api_crypto_set_async_dispatch_v2_t *mp)
{
  vl_api_crypto_set_async_dispatch_v2_reply_t *rmp;
  int rv = 0;

  vnet_crypto_set_async_dispatch ((u8) mp->mode, mp->adaptive ? 1 : 0);

  REPLY_MACRO (VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY);
}

static void
vl_api_crypto_set_handler_t_handler (vl_api_crypto_set_handler_t * mp)
{
  vl_api_crypto_set_handler_reply_t *rmp;
  int rv = 0;

  enum
  {
    CRYPTO_OP_SIMPLE,
    CRYPTO_OP_CHAINED,
    CRYPTO_OP_BOTH,
  } oct = (typeof (oct)) mp->oct;

  vnet_crypto_set_handlers_args_t args = {
    .engine = (char *) mp->engine,
    .handler_name = (char *) mp->alg_name,
    .set_async = mp->is_async != 0,
    .set_simple = oct == CRYPTO_OP_SIMPLE || oct == CRYPTO_OP_BOTH,
    .set_chained = oct == CRYPTO_OP_CHAINED || oct == CRYPTO_OP_BOTH,
  };

  rv = vnet_crypto_set_handlers (&args);

  REPLY_MACRO (VL_API_CRYPTO_SET_HANDLER_REPLY);
}

#include <vnet/crypto/crypto.api.c>

clib_error_t *
crypto_api_hookup (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  crypto_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (crypto_api_hookup);
