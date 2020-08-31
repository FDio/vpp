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
#include <vnet/plugin/plugin.h>
#include <vnet/ipip/ipip.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp.h>

#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard.h>

wg_main_t wg_main;

noise_remote_t *
wg_remote_get (uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
  wg_main_t *wmp = &wg_main;
  wg_peer_t *peer = NULL;
  wg_peer_t *peer_iter;
  /* *INDENT-OFF* */
  pool_foreach (peer_iter, wmp->peers,
  ({
    if (!memcmp (peer_iter->remote.r_public, public, NOISE_PUBLIC_KEY_LEN))
    {
      peer = peer_iter;
      break;
    }
  }));
  /* *INDENT-ON* */
  return peer ? &peer->remote : NULL;
}

uint32_t
wg_index_set (noise_remote_t * remote)
{
  wg_main_t *wmp = &wg_main;
  u32 rnd_seed = (u32) (vlib_time_now (wmp->vlib_main) * 1e6);
  u32 ret =
    wg_index_table_add (&wmp->index_table, remote->r_peer_idx, rnd_seed);
  return ret;
}

void
wg_index_drop (uint32_t key)
{
  wg_main_t *wmp = &wg_main;
  wg_index_table_del (&wmp->index_table, key);
}


static vnet_api_error_t
wg_register_udp_port (vlib_main_t * vm, u16 port)
{
  udp_dst_port_info_t *pi = udp_get_dst_port_info (&udp_main, port, UDP_IP4);
  if (pi)
    return VNET_API_ERROR_VALUE_EXIST;

  udp_register_dst_port (vm, port, wg_input_node.index, 1);
  return 0;
}

static vnet_api_error_t
wg_unregister_udp_port (vlib_main_t * vm, u16 port)
{
  if (port)
    {
      udp_unregister_dst_port (vm, port, 1);
    }
  return 0;
}

clib_error_t *
wg_device_set (wg_main_t * wmp, u8 private_key_64[NOISE_KEY_LEN_BASE64],
	       u16 port)
{
  clib_error_t *error = NULL;

  if (!wmp->is_inited)
    {
      u8 private_key[NOISE_PUBLIC_KEY_LEN];

      if (!key_from_base64
	  (private_key_64, NOISE_KEY_LEN_BASE64, private_key))
	{
	  error = clib_error_return (0, "Error parce private key");
	  return error;
	}

      vnet_api_error_t ret = wg_register_udp_port (wmp->vlib_main, port);
      if (ret == VNET_API_ERROR_VALUE_EXIST)
	{
	  error =
	    clib_error_return (0, "UDP port %d is already taken", (u16) port);
	  return error;
	}

      wmp->port_src = port;
      struct noise_upcall upcall;
      upcall.u_remote_get = wg_remote_get;
      upcall.u_index_set = wg_index_set;
      upcall.u_index_drop = wg_index_drop;

      noise_local_init (&wmp->local, &upcall);
      noise_local_set_private (&wmp->local, private_key);
      cookie_checker_update (&wmp->cookie_checker, wmp->local.l_public);
      wmp->is_inited = true;
    }
  else
    {
      error = clib_error_return (0, "Remove existing device before");
      return error;
    }

  return error;
}

clib_error_t *
wg_device_clear (wg_main_t * wmp)
{
  clib_error_t *error = NULL;

  u32 *remove_idxs = 0;
  wg_peer_t *peer;
  wg_unregister_udp_port (wmp->vlib_main, wmp->port_src);
  /* *INDENT-OFF* */
  pool_foreach (peer, wmp->peers,
  ({
    vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
             peer->tun_sw_if_index, 0, 0, 0);
    wg_peer_clear (wmp->vlib_main, peer);
    vec_add1 (remove_idxs, peer - wmp->peers);
  }));
  /* *INDENT-ON* */
  u32 *idx;
  vec_foreach (idx, remove_idxs)
  {
    pool_put_index (wmp->peers, *idx);
  }
  clib_memset (&wmp->cookie_checker, 0, sizeof (wmp->cookie_checker));
  clib_memset (&wmp->local, 0, sizeof (wmp->local));
  wmp->is_inited = false;

  return error;
}

clib_error_t *
wg_peer_set (wg_main_t * wmp, u8 public_key_64[NOISE_KEY_LEN_BASE64],
	     ip4_address_t endpoint, ip4_address_t allowed_ip,
	     u16 port, u32 tun_sw_if_index, u16 persistent_keepalive)
{
  clib_error_t *error = NULL;
  wg_peer_t *peer_pool = wmp->peers;
  wg_peer_t *peer;

  u8 public_key[NOISE_PUBLIC_KEY_LEN];
  if (!key_from_base64 (public_key_64, NOISE_KEY_LEN_BASE64, public_key))
    {
      error = clib_error_return (0, "Error parce public key");
      return error;
    }

  /* *INDENT-OFF* */
  pool_foreach (peer, peer_pool,
  ({
    if (!memcmp (peer->remote.r_public, public_key, NOISE_PUBLIC_KEY_LEN))
    {
      error = clib_error_return (0, "Peer already exist");
      break;
    }
  }));
  /* *INDENT-ON* */

  if (error)
    return error;

  if (tun_sw_if_index == ~0)
    {
      error = clib_error_return (0, "Tunnel is not specified");
      return error;
    }

  if (pool_elts (wmp->peers) > MAX_PEERS)
    {
      error = clib_error_return (0, "Max peers limit");
      return error;
    }

  if (!wmp->is_inited)
    {
      error = clib_error_return (0, "wg device parameters is not set");
      return error;
    }

  pool_get (wmp->peers, peer);

  wg_peer_init (wmp->vlib_main, peer);
  wg_peer_fill (wmp->vlib_main, peer, endpoint, (u16) port,
		persistent_keepalive, allowed_ip, tun_sw_if_index);
  noise_remote_init (&peer->remote, peer - wmp->peers, public_key,
		     &wmp->local);
  cookie_maker_init (&peer->cookie_maker, public_key);

  vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
			       tun_sw_if_index, 1, 0, 0);

  if (peer->persistent_keepalive_interval != 0)
    {
      wg_send_keepalive (wmp->vlib_main, peer);
    }

  return error;
}

clib_error_t *
wg_peer_remove (wg_main_t * wmp, u8 public_key_64[NOISE_KEY_LEN_BASE64])
{
  clib_error_t *error = NULL;

  wg_peer_t *peer_pool = wmp->peers;
  wg_peer_t *peer = NULL;
  u32 peerIdx = ~0;
  u8 public_key[NOISE_PUBLIC_KEY_LEN];

  if (!key_from_base64 (public_key_64, NOISE_KEY_LEN_BASE64, public_key))
    {
      error = clib_error_return (0, "Error parce public key");
      return error;
    }

  /* *INDENT-OFF* */
  pool_foreach (peer, peer_pool,
  ({
    if (!memcmp (peer->remote.r_public, public_key, NOISE_PUBLIC_KEY_LEN))
    {
      vnet_feature_enable_disable ("ip4-output", "wg-output-tun",
            peer->tun_sw_if_index, 0, 0, 0);
      wg_peer_clear (wmp->vlib_main, peer);
      peerIdx = peer - peer_pool;
      break;
    }
  }));
  /* *INDENT-ON* */
  pool_put_index (peer_pool, peerIdx);
  return error;
}

static clib_error_t *
wg_init (vlib_main_t * vm)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = 0;

  wmp->vlib_main = vm;
  wmp->is_inited = false;
  wmp->peers = 0;

  return error;
}

VLIB_INIT_FUNCTION (wg_init);

/* *INDENT-OFF* */

VNET_FEATURE_INIT (wg_output_tun, static) =
{
  .arc_name = "ip4-output",
  .node_name = "wg-output-tun",
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "WireGuard Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
