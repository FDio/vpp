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

#include <vnet/adj/adj_midchain.h>
#include <vnet/udp/udp.h>

#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard.h>
#include <wireguard/wireguard_peer.h>

/* pool of interfaces */
wg_if_t *wg_if_pool;

/* bitmap of Allocated WG_ITF instances */
static uword *wg_if_instances;

/* vector of interfaces key'd on their sw_if_index */
static index_t *wg_if_index_by_sw_if_index;

/* vector of interfaces key'd on their UDP port (in network order) */
index_t **wg_if_indexes_by_port;

/* pool of ratelimit entries */
static ratelimit_entry_t *wg_ratelimit_pool;

static u8 *
format_wg_if_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  wg_if_t *wgi = wg_if_get (dev_instance);
  return format (s, "wg%d", wgi->user_instance);
}

u8 *
format_wg_if (u8 * s, va_list * args)
{
  index_t wgii = va_arg (*args, u32);
  wg_if_t *wgi = wg_if_get (wgii);
  noise_local_t *local = noise_local_get (wgi->local_idx);
  u8 key[NOISE_KEY_LEN_BASE64];

  s = format (s, "[%d] %U src:%U port:%d",
	      wgii,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      wgi->sw_if_index, format_ip_address, &wgi->src_ip, wgi->port);

  key_to_base64 (local->l_private, NOISE_PUBLIC_KEY_LEN, key);

  s = format (s, " private-key:%s", key);
  s =
    format (s, " %U", format_hex_bytes, local->l_private,
	    NOISE_PUBLIC_KEY_LEN);

  key_to_base64 (local->l_public, NOISE_PUBLIC_KEY_LEN, key);

  s = format (s, " public-key:%s", key);

  s =
    format (s, " %U", format_hex_bytes, local->l_public,
	    NOISE_PUBLIC_KEY_LEN);

  s = format (s, " mac-key: %U", format_hex_bytes,
	      &wgi->cookie_checker.cc_mac1_key, NOISE_PUBLIC_KEY_LEN);

  return (s);
}

index_t
wg_if_find_by_sw_if_index (u32 sw_if_index)
{
  if (vec_len (wg_if_index_by_sw_if_index) <= sw_if_index)
    return INDEX_INVALID;
  u32 ti = wg_if_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return INDEX_INVALID;

  return (ti);
}

static walk_rc_t
wg_if_find_peer_by_public_key (index_t peeri, void *data)
{
  uint8_t *public = data;
  wg_peer_t *peer = wg_peer_get (peeri);

  if (!memcmp (peer->remote.r_public, public, NOISE_PUBLIC_KEY_LEN))
    return (WALK_STOP);
  return (WALK_CONTINUE);
}

static noise_remote_t *
wg_remote_get (const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
  index_t peeri;

  peeri = wg_peer_walk (wg_if_find_peer_by_public_key, (void *) public);

  if (INDEX_INVALID != peeri)
    return &wg_peer_get (peeri)->remote;

  return NULL;
}

static uint32_t
wg_index_set (vlib_main_t *vm, noise_remote_t *remote)
{
  wg_main_t *wmp = &wg_main;
  /* TODO: Make sure the same value cannot be generated twice in a row. */
  u32 rnd_seed = (u32) (vlib_time_now (wmp->vlib_main) * 1e6);
  u32 ret =
    wg_index_table_add (vm, &wmp->index_table, remote->r_peer_idx, rnd_seed);
  return ret;
}

static void
wg_index_drop (vlib_main_t *vm, uint32_t key)
{
  wg_main_t *wmp = &wg_main;
  wg_index_table_del (vm, &wmp->index_table, key);
}

static clib_error_t *
wg_if_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  index_t wgii;
  u32 hw_flags;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
	      VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  wgii = wg_if_find_by_sw_if_index (hi->sw_if_index);

  wg_if_peer_walk (wg_if_get (wgii), wg_peer_if_admin_state_change, NULL);

  return (NULL);
}

void
wg_if_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  index_t wgii;

  /* Convert any neighbour adjacency that has a next-hop reachable through
   * the wg interface into a midchain. This is to avoid sending ARP/ND to
   * resolve the next-hop address via the wg interface. Then, if one of the
   * peers has matching prefix among allowed prefixes, the midchain will be
   * updated to the corresponding one.
   */
  adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);

  wgii = wg_if_find_by_sw_if_index (sw_if_index);
  wg_if_peer_walk (wg_if_get (wgii), wg_peer_if_adj_change, &ai);
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (wg_if_device_class) = {
  .name = "Wireguard Tunnel",
  .format_device_name = format_wg_if_name,
  .admin_up_down_function = wg_if_admin_up_down,
};

VNET_HW_INTERFACE_CLASS(wg_hw_interface_class) = {
  .name = "Wireguard",
  .update_adjacency = wg_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated wg_if instance numbers.
 */
#define WG_ITF_MAX_INSTANCE		(16 * 1024)

static u32
wg_if_instance_alloc (u32 want)
{
  /*
   * Check for dynamically allocated instance number.
   */
  if (~0 == want)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (wg_if_instances);
      if (bit >= WG_ITF_MAX_INSTANCE)
	{
	  return ~0;
	}
      wg_if_instances = clib_bitmap_set (wg_if_instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= WG_ITF_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (wg_if_instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  wg_if_instances = clib_bitmap_set (wg_if_instances, want, 1);

  return want;
}

static int
wg_if_instance_free (u32 instance)
{
  if (instance >= WG_ITF_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (wg_if_instances, instance) == 0)
    {
      return -1;
    }

  wg_if_instances = clib_bitmap_set (wg_if_instances, instance, 0);
  return 0;
}


int
wg_if_create (u32 user_instance,
	      const u8 private_key[NOISE_PUBLIC_KEY_LEN],
	      u16 port, const ip_address_t * src_ip, u32 * sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 instance, hw_if_index;
  vnet_hw_interface_t *hi;
  wg_if_t *wg_if;
  noise_local_t *local;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  /*
   * Allocate a wg_if instance. Either select on dynamically
   * or try to use the desired user_instance number.
   */
  instance = wg_if_instance_alloc (user_instance);
  if (instance == ~0)
    return VNET_API_ERROR_INVALID_REGISTRATION;

  /* *INDENT-OFF* */
  struct noise_upcall upcall =  {
    .u_remote_get = wg_remote_get,
    .u_index_set = wg_index_set,
    .u_index_drop = wg_index_drop,
  };
  /* *INDENT-ON* */

  pool_get (noise_local_pool, local);

  noise_local_init (local, &upcall);
  if (!noise_local_set_private (local, private_key))
    {
      pool_put (noise_local_pool, local);
      wg_if_instance_free (instance);
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }

  pool_get_zero (wg_if_pool, wg_if);

  /* tunnel index (or instance) */
  u32 t_idx = wg_if - wg_if_pool;

  wg_if->user_instance = instance;
  if (~0 == wg_if->user_instance)
    wg_if->user_instance = t_idx;

  vec_validate_init_empty (wg_if_indexes_by_port, port, NULL);
  if (vec_len (wg_if_indexes_by_port[port]) == 0)
    {
      udp_register_dst_port (vlib_get_main (), port, wg4_input_node.index,
			     UDP_IP4);
      udp_register_dst_port (vlib_get_main (), port, wg6_input_node.index,
			     UDP_IP6);
    }

  vec_add1 (wg_if_indexes_by_port[port], t_idx);

  wg_if->port = port;
  wg_if->local_idx = local - noise_local_pool;
  cookie_checker_init (&wg_if->cookie_checker, wg_ratelimit_pool);
  cookie_checker_update (&wg_if->cookie_checker, local->l_public);

  hw_if_index = vnet_register_interface (vnm,
					 wg_if_device_class.index,
					 t_idx,
					 wg_hw_interface_class.index, t_idx);

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  vec_validate_init_empty (wg_if_index_by_sw_if_index, hi->sw_if_index,
			   INDEX_INVALID);
  wg_if_index_by_sw_if_index[hi->sw_if_index] = t_idx;

  ip_address_copy (&wg_if->src_ip, src_ip);
  wg_if->sw_if_index = *sw_if_indexp = hi->sw_if_index;
  vnet_set_interface_l3_output_node (vnm->vlib_main, hi->sw_if_index,
				     (u8 *) "tunnel-output");

  return 0;
}

int
wg_if_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != wg_if_device_class.index)
    return VNET_API_ERROR_INVALID_VALUE;

  wg_if_t *wg_if;
  index_t wgii = wg_if_find_by_sw_if_index (sw_if_index);
  wg_if = wg_if_get (wgii);
  if (NULL == wg_if)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX_2;

  if (wg_if_instance_free (wg_if->user_instance) < 0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  // Remove peers before interface deletion
  wg_if_peer_walk (wg_if, wg_peer_if_delete, NULL);

  hash_free (wg_if->peers);

  index_t *ii;
  index_t *ifs = wg_if_indexes_get_by_port (wg_if->port);
  vec_foreach (ii, ifs)
    {
      if (*ii == wgii)
	{
	  vec_del1 (ifs, ifs - ii);
	  break;
	}
    }
  if (vec_len (ifs) == 0)
    {
      udp_unregister_dst_port (vlib_get_main (), wg_if->port, 1);
      udp_unregister_dst_port (vlib_get_main (), wg_if->port, 0);
    }

  cookie_checker_deinit (&wg_if->cookie_checker);

  vnet_reset_interface_l3_output_node (vnm->vlib_main, sw_if_index);
  vnet_delete_hw_interface (vnm, hw->hw_if_index);
  pool_put_index (noise_local_pool, wg_if->local_idx);
  pool_put (wg_if_pool, wg_if);

  return 0;
}

void
wg_if_peer_add (wg_if_t * wgi, index_t peeri)
{
  hash_set (wgi->peers, peeri, peeri);

  if (1 == hash_elts (wgi->peers))
    {
      vnet_feature_enable_disable ("ip4-output", "wg4-output-tun",
				   wgi->sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "wg6-output-tun",
				   wgi->sw_if_index, 1, 0, 0);
    }
}

void
wg_if_peer_remove (wg_if_t * wgi, index_t peeri)
{
  hash_unset (wgi->peers, peeri);

  if (0 == hash_elts (wgi->peers))
    {
      vnet_feature_enable_disable ("ip4-output", "wg4-output-tun",
				   wgi->sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "wg6-output-tun",
				   wgi->sw_if_index, 0, 0, 0);
    }
}

void
wg_if_walk (wg_if_walk_cb_t fn, void *data)
{
  index_t wgii;

  /* *INDENT-OFF* */
  pool_foreach_index (wgii, wg_if_pool)
  {
    if (WALK_STOP == fn(wgii, data))
      break;
  }
  /* *INDENT-ON* */
}

index_t
wg_if_peer_walk (wg_if_t * wgi, wg_if_peer_walk_cb_t fn, void *data)
{
  index_t peeri, val;

  /* *INDENT-OFF* */
  hash_foreach (peeri, val, wgi->peers, {
    if (WALK_STOP == fn (peeri, data))
      return peeri;
  });
  /* *INDENT-ON* */

  return INDEX_INVALID;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
