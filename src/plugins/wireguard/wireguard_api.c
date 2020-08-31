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
#include <wireguard/wireguard_itf.h>

#define REPLY_MSG_ID_BASE wmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
/* static void */
/* vl_api_wireguard_set_device_t_handler (vl_api_wireguard_set_device_t * mp) */
/* { */
/*   clib_error_t *error; */
/*   vl_api_wireguard_set_device_reply_t *rmp; */
/*   wg_main_t *wmp = &wg_main; */
/*   int rv = 0; */

/*   error = */
/*     wg_device_set (wmp, mp->private_key, clib_net_to_host_u16 (mp->port)); */
/*   if (error) */
/*     rv = VNET_API_ERROR_UNSPECIFIED; */

/*   /\* *INDENT-OFF* *\/ */
/*   REPLY_MACRO(VL_API_WIREGUARD_SET_DEVICE_REPLY); */
/*   /\* *INDENT-ON* *\/ */
/* } */

/* static void */
/* vl_api_wireguard_remove_device_t_handler (vl_api_wireguard_remove_device_t * */
/* 					  mp) */
/* { */
/*   clib_error_t *error; */
/*   vl_api_wireguard_remove_device_reply_t *rmp; */
/*   wg_main_t *wmp = &wg_main; */
/*   int rv = 0; */

/*   error = wg_device_clear (wmp); */
/*   if (error) */
/*     rv = VNET_API_ERROR_UNSPECIFIED; */

/*   /\* *INDENT-OFF* *\/ */
/*   REPLY_MACRO(VL_API_WIREGUARD_REMOVE_DEVICE_REPLY); */
/*   /\* *INDENT-ON* *\/ */
/* } */

/* static void */
/* vl_api_wireguard_device_dump_t_handler (vl_api_wireguard_device_dump_t * mp) */
/* { */
/*   vl_api_wireguard_device_details_t *rmp; */
/*   wg_main_t *wmp = &wg_main; */
/*   int rv = 0; */

/*   /\* *INDENT-OFF* *\/ */
/*   REPLY_MACRO2(VL_API_WIREGUARD_DEVICE_DETAILS, */
/*   ({ */
/*        rmp->is_inited = wmp->is_inited; */
/*        if (!wmp->is_inited) { */
/*            rmp->port = 0; */
/*            clib_memset (rmp->private_key, 0, NOISE_KEY_LEN_BASE64); */
/*        } else { */
/*            u8 key_64[NOISE_KEY_LEN_BASE64]; */
/*            key_to_base64 (wmp->local.l_private, NOISE_PUBLIC_KEY_LEN,key_64); */
/*            clib_memcpy(rmp->private_key, key_64, NOISE_KEY_LEN_BASE64); */
/*            rmp->port = clib_host_to_net_u16 (wmp->port_src); */
/*        } */
/*   })); */
/*   /\* *INDENT-ON* *\/ */
/* } */

static void
vl_api_wireguard_itf_create_t_handler (vl_api_wireguard_itf_create_t * mp)
{
  vl_api_wireguard_itf_create_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  u32 sw_if_index;
  int rv = 0;

  rv = wg_itf_create (ntohl (mp->itf.user_instance),
		      mp->itf.private_key,
		      ntohs (mp->itf.port), &sw_if_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_ITF_CREATE_REPLY,
  {
    rmp->sw_if_index = htonl(sw_if_index);
  });
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_itf_delete_t_handler (vl_api_wireguard_itf_delete_t * mp)
{
  vl_api_wireguard_itf_delete_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = wg_itf_delete (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_ITF_DELETE_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_itf_dump_t_handler (vl_api_wireguard_itf_dump_t * mp)
{
}

static void
vl_api_wireguard_peer_add_t_handler (vl_api_wireguard_peer_add_t * mp)
{
  vl_api_wireguard_peer_add_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  index_t peeri;
  int ii, rv = 0;

  ip_address_t endpoint;
  ip_address_t *allowed_ips = NULL;

  VALIDATE_SW_IF_INDEX (&(mp->peer));

  if (0 == mp->peer.n_allowed_ips)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  else if (mp->peer.n_allowed_ips > 1)
    {
      /* only one allowed_ip is currently supported */
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto done;
    }
  vec_validate (allowed_ips, mp->peer.n_allowed_ips - 1);
  ip_address_decode2 (&mp->peer.endpoint, &endpoint);

  for (ii = 0; ii < mp->peer.n_allowed_ips; ii++)
    ip_address_decode2 (&mp->peer.allowed_ips[ii], &allowed_ips[ii]);

  if (AF_IP6 == ip_addr_version (&endpoint) ||
      AF_IP6 == ip_addr_version (&allowed_ips[0]))
    /* ip6 currently not supported, but the API needs to support it
     * else we'll need to change it later, and that's a PITA */
    rv = VNET_API_ERROR_INVALID_PROTOCOL;
  else
    rv = wg_peer_add (ntohl (mp->peer.sw_if_index),
		      mp->peer.public_key,
		      ntohl (mp->peer.table_id),
		      ip_addr_v4 (&endpoint),
		      ip_addr_v4 (&allowed_ips[0]),
		      ntohs (mp->peer.port),
		      ntohs (mp->peer.persistent_keepalive), &peeri);

  vec_free (allowed_ips);
done:
  BAD_SW_IF_INDEX_LABEL;
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_PEER_ADD_REPLY,
  {
    rmp->peer_index = ntohl (peeri);
  });
  /* *INDENT-ON* */
}

static void
vl_api_wireguard_peer_remove_t_handler (vl_api_wireguard_peer_remove_t * mp)
{
  vl_api_wireguard_peer_remove_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  rv = wg_peer_remove (wmp, ntohl (mp->peer_index));

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_PEER_REMOVE_REPLY);
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
  if (peer->is_dead)
    rmp->peer.flags = WIREGUARD_PEER_STATUS_DEAD;
  clib_memcpy (rmp->peer.public_key, key_64, NOISE_KEY_LEN_BASE64);

  //  ip_address_encode2
  clib_memcpy (&rmp->peer.endpoint, peer->ip4_address.as_u8,
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
