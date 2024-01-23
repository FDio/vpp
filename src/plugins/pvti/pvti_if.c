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

#include <pvti/pvti.h>
#include <pvti/pvti_if.h>

static u8 *
format_pvti_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  // wg_if_t *wgi = wg_if_get (dev_instance);
  return format (s, "pvti%d", dev_instance);
}

u8 *
format_pvti_if (u8 *s, va_list *args)
{
  index_t pvtii = va_arg (*args, u32);
  pvti_if_t *pvti_if = pvti_if_get (pvtii);

  s = format (
    s, "[%d] %U local:%U:%d remote:%U:%d underlay_mtu:%d underlay_fib_idx:%d",
    pvtii, format_vnet_sw_if_index_name, vnet_get_main (),
    pvti_if->sw_if_index, format_ip46_address, &pvti_if->local_ip,
    IP46_TYPE_ANY, pvti_if->local_port, format_ip46_address,
    &pvti_if->remote_ip, IP46_TYPE_ANY, pvti_if->remote_port,
    pvti_if->underlay_mtu, pvti_if->underlay_fib_index);

  return (s);
}

index_t
pvti_if_find_by_sw_if_index (u32 sw_if_index)
{
  if (vec_len (pvti_main.if_index_by_sw_if_index) <= sw_if_index)
    return INDEX_INVALID;
  u32 ti = pvti_main.if_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return INDEX_INVALID;

  return (ti);
}

index_t
pvti_if_find_by_remote_ip4_and_port (ip4_address_t *remote_ip4,
				     u16 remote_port)
{
  pvti_if_t *ifc;
  pool_foreach (ifc, pvti_main.if_pool)
    {
      if ((ifc->remote_port == remote_port) &&
	  (ifc->remote_ip.version == AF_IP4) &&
	  ((ifc->remote_ip.ip.ip4.as_u32 == remote_ip4->as_u32) ||
	   ifc->peer_address_from_payload))
	{
	  return (ifc - pvti_main.if_pool);
	}
    }
  return INDEX_INVALID;
}

index_t
pvti_if_find_by_remote_ip_and_port (ip_address_t *remote_ip, u16 remote_port)
{
  pvti_if_t *ifc;
  pool_foreach (ifc, pvti_main.if_pool)
    {
      int res = ip_address_cmp (remote_ip, &ifc->remote_ip);
		    ifc->remote_port, remote_port,
		    ifc->peer_address_from_payload, format_ip_address,
		    remote_ip, format_ip_address, &ifc->remote_ip, res);
      if ((ifc->remote_port == remote_port) &&
	  (ifc->peer_address_from_payload ||
	   (0 == ip_address_cmp (remote_ip, &ifc->remote_ip))))
	{
	  return (ifc - pvti_main.if_pool);
	}
    }
  return INDEX_INVALID;
}

static void
pvti_add_tidx_by_port (index_t t_index, u16 port)
{
  pvti_main_t *pvm = &pvti_main;
  vec_validate_init_empty (pvm->if_indices_by_port, port, NULL);
  vec_add1 (pvm->if_indices_by_port[port], t_index);
}

static void
pvti_del_tidx_by_port (index_t t_index, u16 port)
{
  pvti_main_t *pvm = &pvti_main;
  index_t *ii;
  if (!pvm->if_indices_by_port)
    {
      return;
    }
  if (port >= vec_len (pvm->if_indices_by_port))
    {
      return;
    }
  if (vec_len (pvm->if_indices_by_port[port]) == 0)
    {
      ALWAYS_ASSERT (pvm->if_indices_by_port[port] > 0);
      /* not reached */
      return;
    }

  vec_foreach (ii, pvm->if_indices_by_port[port])
    {
      if (*ii == t_index)
	{
	  vec_del1 (pvm->if_indices_by_port[port],
		    pvm->if_indices_by_port[port] - ii);
	  break;
	}
    }
}

static u32
pvti_get_tunnel_count_by_port (u16 port)
{
  pvti_main_t *pvm = &pvti_main;
  if (!pvm->if_indices_by_port)
    {
      return 0;
    }
  return vec_len (vec_elt (pvm->if_indices_by_port, port));
}

static clib_error_t *
pvti_if_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  // vnet_hw_interface_t *hi;
  u32 hw_flags;

  // hi = vnet_get_hw_interface (vnm, hw_if_index);
  hw_flags =
    (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ? VNET_HW_INTERFACE_FLAG_LINK_UP :
					       0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return (NULL);
}

void
pvti_if_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{

  /* Convert any neighbour adjacency that has a next-hop reachable through
   * the wg interface into a midchain. This is to avoid sending ARP/ND to
   * resolve the next-hop address via the wg interface. Then, if one of the
   * peers has matching prefix among allowed prefixes, the midchain will be
   * updated to the corresponding one.
   */
  adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);

  // wgii = wg_if_find_by_sw_if_index (sw_if_index);
  // wg_if_peer_walk (wg_if_get (wgii), wg_peer_if_adj_change, &ai);
}

VNET_DEVICE_CLASS (pvti_if_device_class) = {
  .name = "Packet Vectorizer Tunnel",
  .format_device_name = format_pvti_if_name,
  .admin_up_down_function = pvti_if_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (pvti_hw_interface_class) = {
  .name = "PVTunnel",
  .update_adjacency = pvti_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
  // .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};

int
pvti_if_create (ip_address_t *local_ip, u16 local_port,
		ip_address_t *remote_ip, u16 remote_port,
		pvti_peer_address_method_t peer_address_method,
		u16 underlay_mtu, u32 underlay_fib_index, u32 *sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  pvti_main_t *pvm = &pvti_main;
  u32 hw_if_index;
  vnet_hw_interface_t *hi;
  pvti_verify_initialized (pvm);

  pvti_if_t *pvti_if;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~0;

  pool_get_zero (pvti_main.if_pool, pvti_if);
  pvti_if->local_ip = *local_ip;
  pvti_if->local_port = local_port;
  pvti_if->remote_ip = *remote_ip;
  if (peer_address_method == PVTI_PEER_ADDRESS_FROM_PAYLOAD)
    {
      pvti_if->peer_address_from_payload = 1;
    }
  pvti_if->remote_port = remote_port;
  pvti_if->underlay_mtu = underlay_mtu;
  pvti_if->underlay_fib_index = underlay_fib_index;
  pvti_if->created_at = clib_cpu_time_now ();

  /* tunnel index (or instance) */
  u32 t_idx = pvti_if - pvti_main.if_pool;

  hw_if_index =
    vnet_register_interface (vnm, pvti_if_device_class.index, t_idx,
			     pvti_hw_interface_class.index, t_idx);

  pvti_if->hw_if_index = hw_if_index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  pvti_if->sw_if_index = *sw_if_indexp = hi->sw_if_index;

  vec_validate_init_empty (pvm->if_index_by_sw_if_index, hi->sw_if_index,
			   INDEX_INVALID);

  vec_elt (pvm->if_index_by_sw_if_index, hi->sw_if_index) = t_idx;
  pvti_if_t *pvti_if0 = pool_elt_at_index (pvti_main.if_pool, t_idx);
  int i;
  for (i = 0; i < 256; i++)
    {
      pvti_if0->tx_streams[i].bi0 = INDEX_INVALID;
      pvti_if0->tx_streams[i].current_tx_seq = 42;

      pvti_if0->rx_streams[i].rx_bi0 = INDEX_INVALID;
      pvti_if0->rx_streams[i].rx_bi0_first = INDEX_INVALID;
    }

  /*
    int is_ip6 = 0;
    u32 encap_index = !is_ip6 ?
	  pvti4_output_node.index : pvti6_output_node.index;
    vnet_set_interface_output_node (vnm, pvti_if->hw_if_index, encap_index);
    */
  vnet_set_interface_l3_output_node (vnm->vlib_main, hi->sw_if_index,
				     (u8 *) "pvti4-output");

  pvti_add_tidx_by_port (t_idx, local_port);
  if (1 == pvti_get_tunnel_count_by_port (local_port))
    {
      clib_warning ("Registering local port %d", local_port);
      udp_register_dst_port (vlib_get_main (), local_port,
			     pvti4_input_node.index, UDP_IP4);
      udp_register_dst_port (vlib_get_main (), local_port,
			     pvti6_input_node.index, UDP_IP6);
    }
  else
    {
      clib_warning ("Not registering the port");
    }

  vnet_hw_interface_set_flags (vnm, pvti_if->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  return 0;
}

void
pvti_if_walk (pvti_if_walk_cb_t fn, void *data)
{
  index_t pvtii;

  pool_foreach_index (pvtii, pvti_main.if_pool)
    {
      if (WALK_STOP == fn (pvtii, data))
	break;
    }
}

int
pvti_if_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  pvti_main_t *pvm = &pvti_main;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != pvti_if_device_class.index)
    return VNET_API_ERROR_INVALID_VALUE;

  pvti_if_t *ifc;
  bool found = 0;
  pool_foreach (ifc, pvm->if_pool)
    {
      if (ifc->sw_if_index == sw_if_index)
	{
	  found = 1;
	  break;
	}
    }
  if (!found)
    {
      return VNET_API_ERROR_INVALID_VALUE_2;
    }
  index_t tidx = ifc - pvm->if_pool;

  u16 local_port = ifc->local_port;
  pvti_del_tidx_by_port (tidx, local_port);
  pvm->if_index_by_sw_if_index[sw_if_index] = INDEX_INVALID;

  if (0 == pvti_get_tunnel_count_by_port (local_port))
    {
      udp_unregister_dst_port (vlib_get_main (), local_port, 1);
      udp_unregister_dst_port (vlib_get_main (), local_port, 0);
    }

  vnet_reset_interface_l3_output_node (vnm->vlib_main, sw_if_index);
  vnet_delete_hw_interface (vnm, hw->hw_if_index);
  pool_put (pvti_main.if_pool, ifc);

  /* mark per-thread peers as deleted */
  pvti_per_thread_data_t *ptd;

  vec_foreach (ptd, pvm->per_thread_data[0])
    {
      pvti_tx_peer_t *peer;
      vec_foreach (peer, ptd->tx_peers)
	{
	  if (tidx == peer->pvti_if_index)
	    {
	      peer->deleted = 1;
	    }
	}
    }
  vec_foreach (ptd, pvm->per_thread_data[1])
    {
      pvti_tx_peer_t *peer;
      vec_foreach (peer, ptd->tx_peers)
	{
	  if (tidx == peer->pvti_if_index)
	    {
	      peer->deleted = 1;
	    }
	}
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
