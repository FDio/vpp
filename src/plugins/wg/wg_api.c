/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibapi/api.h>

#include <wg/wg.api_enum.h>
#include <wg/wg.api_types.h>

#include <wg/wg_convert.h>
#include <wg/wg.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void
vl_api_wg_set_device_t_handler (vl_api_wg_set_device_t * mp)
{
  clib_error_t *error;
  vl_api_wg_set_device_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  error = wg_device_set (cm, (char *) mp->private_key, mp->port);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WG_SET_DEVICE_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wg_remove_device_t_handler (vl_api_wg_remove_device_t * mp)
{
  clib_error_t *error;
  vl_api_wg_remove_device_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  error = wg_device_clear (cm);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WG_REMOVE_DEVICE_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wg_set_peer_t_handler (vl_api_wg_set_peer_t * mp)
{
  clib_error_t *error;

  vl_api_wg_set_peer_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  ip4_address_t endpoint;
  ip4_address_t allowed_ip;
  ip4_address_decode (mp->endpoint, &endpoint);
  ip4_address_decode (mp->allowed_ip, &allowed_ip);

  error =
    wg_peer_set (cm, (char *) mp->public_key, endpoint, allowed_ip, mp->port,
		 mp->tun_sw_if_index, mp->persistent_keepalive);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WG_SET_PEER_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wg_remove_peer_t_handler (vl_api_wg_remove_peer_t * mp)
{
  clib_error_t *error;

  vl_api_wg_remove_peer_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  error = wg_peer_remove (cm, (char *) mp->public_key);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WG_REMOVE_PEER_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wg_genkey_t_handler (vl_api_wg_genkey_t * mp)
{
  vl_api_wg_genkey_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  u8 secret[NOISE_PUBLIC_KEY_LEN];
  char secret_64[NOISE_KEY_LEN_BASE64];

  curve25519_gen_secret (secret);
  key_to_base64 (secret_64, secret);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WG_GENKEY_REPLY,
  ({
       clib_memcpy(rmp->private_key, secret_64, NOISE_KEY_LEN_BASE64);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_wg_pubkey_t_handler (vl_api_wg_pubkey_t * mp)
{
  vl_api_wg_pubkey_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;
  int rv0 = 0;

  u8 secret[NOISE_PUBLIC_KEY_LEN];
  u8 public[NOISE_PUBLIC_KEY_LEN];
  char public_64[NOISE_KEY_LEN_BASE64];

  if (!(key_from_base64 (secret, (char *) mp->private_key)))
    rv0 = VNET_API_ERROR_UNSPECIFIED;
  rv = rv || rv0;

  if (!curve25519_gen_public (public, secret))
    rv0 = VNET_API_ERROR_UNSPECIFIED;
  rv = rv || rv0;

  key_to_base64 (public_64, public);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WG_PUBKEY_REPLY,
  ({
       clib_memcpy(rmp->public_key, public_64, NOISE_KEY_LEN_BASE64);
  }));

  /* *INDENT-ON* */
}

static void
vl_api_wg_peers_count_t_handler (vl_api_wg_peers_count_t * mp)
{
  vl_api_wg_peers_count_reply_t *rmp;
  wg_main_t *cm = &wg_main;
  int rv = 0;

  u64 count = clib_host_to_net_u64 (pool_elts (cm->peers));
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WG_PEERS_COUNT_REPLY,
  ({
       rmp->count = count;
  }));
  /* *INDENT-ON* */
}

/* set tup the API message handling tables */
#include <wg/wg.api.c>
static clib_error_t *
wg_api_hookup (vlib_main_t * vm)
{
  wg_main_t *wmp = &wg_main;
  wmp->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (wg_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
