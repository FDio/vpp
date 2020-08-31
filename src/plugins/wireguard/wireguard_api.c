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

#include <wireguard/wireguard.api_enum.h>
#include <wireguard/wireguard.api_types.h>

#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard.h>

#define REPLY_MSG_ID_BASE wmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void
vl_api_wireguard_set_device_t_handler (vl_api_wireguard_set_device_t * mp)
{
  clib_error_t *error;
  vl_api_wireguard_set_device_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  error =
    wg_device_set (wmp, mp->private_key, clib_net_to_host_u16 (mp->port));
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_SET_DEVICE_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_remove_device_t_handler (vl_api_wireguard_remove_device_t *
					  mp)
{
  clib_error_t *error;
  vl_api_wireguard_remove_device_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  error = wg_device_clear (wmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_REMOVE_DEVICE_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_device_dump_t_handler (vl_api_wireguard_device_dump_t * mp)
{
  vl_api_wireguard_device_details_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_DEVICE_DETAILS,
  ({
       rmp->is_inited = wmp->is_inited;
       if (!wmp->is_inited) {
           rmp->port = 0;
           clib_memset (rmp->private_key, 0, NOISE_KEY_LEN_BASE64);
       } else {
           u8 key_64[NOISE_KEY_LEN_BASE64];
           key_to_base64 (wmp->local.l_private, NOISE_PUBLIC_KEY_LEN,key_64);
           clib_memcpy(rmp->private_key, key_64, NOISE_KEY_LEN_BASE64);
           rmp->port = clib_host_to_net_u16 (wmp->port_src);
       }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_set_peer_t_handler (vl_api_wireguard_set_peer_t * mp)
{
  clib_error_t *error;

  vl_api_wireguard_set_peer_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  ip4_address_t endpoint;
  ip4_address_t allowed_ip;
  ip4_address_decode (mp->endpoint, &endpoint);
  ip4_address_decode (mp->allowed_ip, &allowed_ip);

  error =
    wg_peer_set (wmp, mp->public_key, endpoint, allowed_ip,
		 clib_net_to_host_u16 (mp->port),
		 clib_net_to_host_u32 (mp->tun_sw_if_index),
		 clib_net_to_host_u16 (mp->persistent_keepalive));
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_SET_PEER_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_remove_peer_t_handler (vl_api_wireguard_remove_peer_t * mp)
{
  clib_error_t *error;

  vl_api_wireguard_remove_peer_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  error = wg_peer_remove (wmp, mp->public_key);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_REMOVE_PEER_REPLY);
  /* *INDENT-ON* */
}

static void
send_wg_peers_details (wg_peer_t * peer, vl_api_registration_t * reg,
		       u32 context)
{
  vl_api_wireguard_peers_details_t *rmp;
  u8 key_64[NOISE_KEY_LEN_BASE64];

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_WIREGUARD_PEERS_DETAILS +
			  wg_main.msg_id_base);

  key_to_base64 (peer->remote.r_public, NOISE_PUBLIC_KEY_LEN, key_64);
  rmp->is_dead = peer->is_dead;
  clib_memcpy (rmp->public_key, key_64, NOISE_KEY_LEN_BASE64);
  clib_memcpy (rmp->ip4_address, peer->ip4_address.as_u8,
	       sizeof (ip4_address_t));

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_wireguard_peers_dump_t_handler (vl_api_wireguard_peers_dump_t * mp)
{
  vl_api_registration_t *reg;
  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (peer, wmp->peers,
  ({
    send_wg_peers_details (peer, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_genkey_t_handler (vl_api_wireguard_genkey_t * mp)
{
  vl_api_wireguard_genkey_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  u8 secret[NOISE_PUBLIC_KEY_LEN];
  u8 secret_64[NOISE_KEY_LEN_BASE64];

  curve25519_gen_secret (secret);
  key_to_base64 (secret, NOISE_PUBLIC_KEY_LEN, secret_64);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_GENKEY_REPLY,
  ({
       clib_memcpy(rmp->private_key, secret_64, NOISE_KEY_LEN_BASE64);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_pubkey_t_handler (vl_api_wireguard_pubkey_t * mp)
{
  vl_api_wireguard_pubkey_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;
  int rv0 = 0;

  u8 secret[NOISE_PUBLIC_KEY_LEN];
  u8 public[NOISE_PUBLIC_KEY_LEN];
  u8 public_64[NOISE_KEY_LEN_BASE64];

  if (!(key_from_base64 (mp->private_key, NOISE_KEY_LEN_BASE64, secret)))
    rv0 = VNET_API_ERROR_UNSPECIFIED;
  rv = rv || rv0;

  if (!curve25519_gen_public (public, secret))
    rv0 = VNET_API_ERROR_UNSPECIFIED;
  rv = rv || rv0;

  key_to_base64 (public, NOISE_PUBLIC_KEY_LEN, public_64);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_PUBKEY_REPLY,
  ({
       clib_memcpy(rmp->public_key, public_64, NOISE_KEY_LEN_BASE64);
  }));

  /* *INDENT-ON* */
}

static void
vl_api_wireguard_peers_count_t_handler (vl_api_wireguard_peers_count_t * mp)
{
  vl_api_wireguard_peers_count_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  u64 count = clib_host_to_net_u64 (pool_elts (wmp->peers));
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_PEERS_COUNT_REPLY,
  ({
       rmp->count = count;
  }));
  /* *INDENT-ON* */
}

/* set tup the API message handling tables */
#include <wireguard/wireguard.api.c>
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
