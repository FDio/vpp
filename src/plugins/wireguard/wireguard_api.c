/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard_peer.h>

#define REPLY_MSG_ID_BASE wmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_wireguard_interface_create_t_handler
  (vl_api_wireguard_interface_create_t * mp)
{
  vl_api_wireguard_interface_create_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  u8 private_key[NOISE_PUBLIC_KEY_LEN];
  noise_local_t *local;
  wg_if_t *wgi;
  index_t wgii;
  ip_address_t src;
  u32 sw_if_index = ~0;
  int rv = 0;

  wg_feature_init (wmp);

  ip_address_decode2 (&mp->interface.src_ip, &src);

  if (AF_IP6 == ip_addr_version (&src))
    rv = VNET_API_ERROR_INVALID_PROTOCOL;
  else
    {
      if (mp->generate_key)
	curve25519_gen_secret (private_key);
      else
	clib_memcpy (private_key, mp->interface.private_key,
		     NOISE_PUBLIC_KEY_LEN);

      rv = wg_if_create (ntohl (mp->interface.user_instance), private_key,
			 ntohs (mp->interface.port), &src, &sw_if_index);
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_WIREGUARD_INTERFACE_CREATE_REPLY,
  {
    if (rv == 0)
      {
	/* return the public key in case we generated it */
	wgii = wg_if_find_by_sw_if_index (sw_if_index);
	wgi = wg_if_get (wgii);
	local = noise_local_get (wgi->local_idx);
	clib_memcpy (rmp->public_key, local->l_public, NOISE_PUBLIC_KEY_LEN);
      }
    rmp->sw_if_index = htonl(sw_if_index);
  });
  /* *INDENT-ON* */
}

static void
  vl_api_wireguard_interface_delete_t_handler
  (vl_api_wireguard_interface_delete_t * mp)
{
  vl_api_wireguard_interface_delete_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  int rv = 0;

  wg_feature_init (wmp);

  VALIDATE_SW_IF_INDEX (mp);

  rv = wg_if_delete (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_INTERFACE_DELETE_REPLY);
  /* *INDENT-ON* */
}

typedef struct wg_deatils_walk_t_
{
  vl_api_registration_t *reg;
  u32 context;
  u8 show_private_key;
} wg_deatils_walk_t;

static walk_rc_t
wireguard_if_send_details (index_t wgii, void *data)
{
  vl_api_wireguard_interface_details_t *rmp;
  wg_deatils_walk_t *ctx = data;
  const wg_if_t *wgi;
  const noise_local_t *local;

  wgi = wg_if_get (wgii);
  local = noise_local_get (wgi->local_idx);

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_WIREGUARD_INTERFACE_DETAILS +
			   wg_main.msg_id_base);

  if (ctx->show_private_key)
    clib_memcpy (rmp->interface.private_key,
		 local->l_private, NOISE_PUBLIC_KEY_LEN);
  clib_memcpy (rmp->interface.public_key,
	       local->l_public, NOISE_PUBLIC_KEY_LEN);
  rmp->interface.sw_if_index = htonl (wgi->sw_if_index);
  rmp->interface.port = htons (wgi->port);
  ip_address_encode2 (&wgi->src_ip, &rmp->interface.src_ip);

  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return (WALK_CONTINUE);
}

static void
vl_api_wireguard_interface_dump_t_handler (vl_api_wireguard_interface_dump_t *
					   mp)
{
  vl_api_registration_t *reg;
  wg_main_t *wmp = &wg_main;

  wg_feature_init (wmp);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  wg_deatils_walk_t ctx = {
    .reg = reg,
    .context = mp->context,
    .show_private_key = mp->show_private_key,
  };

  wg_if_walk (wireguard_if_send_details, &ctx);
}

static void
vl_api_wireguard_peer_add_t_handler (vl_api_wireguard_peer_add_t * mp)
{
  vl_api_wireguard_peer_add_reply_t *rmp;
  wg_main_t *wmp = &wg_main;
  index_t peeri = INDEX_INVALID;
  int ii, rv = 0;

  ip_address_t endpoint;
  fib_prefix_t *allowed_ips = NULL;

  VALIDATE_SW_IF_INDEX (&(mp->peer));

  if (0 == mp->peer.n_allowed_ips)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  wg_feature_init (wmp);

  vec_validate (allowed_ips, mp->peer.n_allowed_ips - 1);
  ip_address_decode2 (&mp->peer.endpoint, &endpoint);

  for (ii = 0; ii < mp->peer.n_allowed_ips; ii++)
    ip_prefix_decode (&mp->peer.allowed_ips[ii], &allowed_ips[ii]);

  if (AF_IP6 == ip_addr_version (&endpoint) ||
      FIB_PROTOCOL_IP6 == allowed_ips[0].fp_proto)
    /* ip6 currently not supported, but the API needs to support it
     * else we'll need to change it later, and that's a PITA */
    rv = VNET_API_ERROR_INVALID_PROTOCOL;
  else
    rv = wg_peer_add (ntohl (mp->peer.sw_if_index),
		      mp->peer.public_key,
		      ntohl (mp->peer.table_id),
		      &ip_addr_46 (&endpoint),
		      allowed_ips,
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

  wg_feature_init (wmp);

  rv = wg_peer_remove (ntohl (mp->peer_index));

  /* *INDENT-OFF* */
  REPLY_MACRO(VL_API_WIREGUARD_PEER_REMOVE_REPLY);
  /* *INDENT-ON* */
}

static walk_rc_t
send_wg_peers_details (index_t peeri, void *data)
{
  vl_api_wireguard_peers_details_t *rmp;
  wg_deatils_walk_t *ctx = data;
  const wg_peer_t *peer;
  u8 n_allowed_ips;
  size_t ss;

  peer = wg_peer_get (peeri);
  n_allowed_ips = vec_len (peer->allowed_ips);

  ss = (sizeof (*rmp) + (n_allowed_ips * sizeof (rmp->peer.allowed_ips[0])));

  rmp = vl_msg_api_alloc_zero (ss);

  rmp->_vl_msg_id = htons (VL_API_WIREGUARD_PEERS_DETAILS +
			   wg_main.msg_id_base);

  if (peer->is_dead)
    rmp->peer.flags = WIREGUARD_PEER_STATUS_DEAD;
  clib_memcpy (rmp->peer.public_key,
	       peer->remote.r_public, NOISE_PUBLIC_KEY_LEN);

  ip_address_encode (&peer->dst.addr, IP46_TYPE_ANY, &rmp->peer.endpoint);
  rmp->peer.port = htons (peer->dst.port);
  rmp->peer.n_allowed_ips = n_allowed_ips;
  rmp->peer.sw_if_index = htonl (peer->wg_sw_if_index);

  int ii;
  for (ii = 0; ii < n_allowed_ips; ii++)
    ip_prefix_encode (&peer->allowed_ips[ii].prefix,
		      &rmp->peer.allowed_ips[ii]);

  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return (WALK_CONTINUE);
}

static void
vl_api_wireguard_peers_dump_t_handler (vl_api_wireguard_peers_dump_t * mp)
{
  vl_api_registration_t *reg;
  wg_main_t *wmp = &wg_main;

  wg_feature_init (wmp);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  wg_deatils_walk_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  wg_peer_walk (send_wg_peers_details, &ctx);
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
