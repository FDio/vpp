/*
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

  vnet_crypto_set_async_dispatch_mode ((u8) mp->mode);

  REPLY_MACRO (VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY);
}

static void
vl_api_crypto_set_handler_t_handler (vl_api_crypto_set_handler_t * mp)
{
  vl_api_crypto_set_handler_reply_t *rmp;
  int rv = 0;
  char *engine;
  char *alg_name;
  crypto_op_class_type_t oct;

  engine = (char *) mp->engine;
  alg_name = (char *) mp->alg_name;
  oct = (crypto_op_class_type_t) mp->oct;

  if (mp->is_async)
    rv = vnet_crypto_set_async_handler2 (alg_name, engine);
  else
    rv = vnet_crypto_set_handler2 (alg_name, engine, oct);

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
