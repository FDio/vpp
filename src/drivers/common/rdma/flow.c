/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <rdma/common.h>
#include <infiniband/verbs.h>
#include <vppinfra/pool.h>
#include <vnet/udp/udp_local.h>

static u32
rdma_flow_add_ip_spec (u8 *cmd, u16 ether_type, u8 ip_proto, u32 inner)
{
  if (ether_type == ETHERNET_TYPE_IP6)
    {
      struct ibv_flow_spec_ipv6 ip6 = {
	.type = IBV_FLOW_SPEC_IPV6 | inner,
	.size = sizeof (ip6),
	.val.next_hdr = ip_proto,
	.mask.next_hdr = ip_proto ? 0xff : 0,
      };

      clib_memcpy (cmd, &ip6, sizeof (ip6));
      return sizeof (ip6);
    }

  if (ip_proto)
    {
      struct ibv_flow_spec_ipv4_ext ip4 = {
	.type = IBV_FLOW_SPEC_IPV4_EXT | inner,
	.size = sizeof (ip4),
	.val.proto = ip_proto,
	.mask.proto = 0xff,
      };

      clib_memcpy (cmd, &ip4, sizeof (ip4));
      return sizeof (ip4);
    }
  else
    {
      struct ibv_flow_spec_ipv4 ip4 = {
	.type = IBV_FLOW_SPEC_IPV4 | inner,
	.size = sizeof (ip4),
      };

      clib_memcpy (cmd, &ip4, sizeof (ip4));
      return sizeof (ip4);
    }
}

/* the outer ether type selects ipv4 or ipv6, a transport, ip protocol or tunnel adds the outer ip
 * header, a transport spec also matches the ip protocol, a gre spec its protocol and a vxlan spec
 * its udp port. The inner headers follow the tunnel. */
vnet_dev_rv_t
rdma_rxq_add_eth_flow (struct ibv_qp *qp, rdma_rx_flow_t ***flows, u8 ibv_port, const u8 *mac,
		       const u8 *mask, const rdma_flow_match_t *match, u16 priority, u32 flags,
		       u32 *flow_index)
{
  u8 cmd[sizeof (struct ibv_flow_attr) + 2 * sizeof (struct ibv_flow_spec_eth) +
	 2 * sizeof (struct ibv_flow_spec_ipv6) + 2 * sizeof (struct ibv_flow_spec_tcp_udp) +
	 sizeof (struct ibv_flow_spec_gre)];
  struct ibv_flow_attr *attr = (struct ibv_flow_attr *) cmd;
  u32 len = sizeof (struct ibv_flow_attr) + sizeof (struct ibv_flow_spec_eth);
  u16 ether_type = match->ether_type;
  rdma_rx_flow_t *f, **fp;

  f = clib_mem_alloc (sizeof (rdma_rx_flow_t));
  if (f == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  f->attr = (struct ibv_flow_attr) {
    .num_of_specs = 1,
    .priority = priority,
    .port = ibv_port,
    .flags = flags,
  };
  f->spec.eth = (struct ibv_flow_spec_eth) {
    .type = IBV_FLOW_SPEC_ETH,
    .size = sizeof (struct ibv_flow_spec_eth),
    .val.ether_type = clib_host_to_net_u16 (ether_type),
    .mask.ether_type = ether_type ? 0xffff : 0,
  };
  f->match = *match;
  clib_memcpy (f->spec.eth.val.dst_mac, mac, sizeof (f->spec.eth.val.dst_mac));
  clib_memcpy (f->spec.eth.mask.dst_mac, mask, sizeof (f->spec.eth.mask.dst_mac));
  clib_memcpy (cmd + sizeof (struct ibv_flow_attr), &f->spec.eth, sizeof (f->spec.eth));

  if (match->l4_spec_type || match->ip_proto || match->tunnel != RDMA_TUNNEL_NONE)
    {
      ASSERT (ether_type == ETHERNET_TYPE_IP4 || ether_type == ETHERNET_TYPE_IP6);
      len += rdma_flow_add_ip_spec (cmd + len, ether_type, match->ip_proto, 0);
      f->attr.num_of_specs++;
    }

  if (match->l4_spec_type)
    {
      struct ibv_flow_spec_tcp_udp l4 = {
	.type = match->l4_spec_type,
	.size = sizeof (l4),
      };

      if (match->tunnel == RDMA_TUNNEL_VXLAN)
	{
	  l4.val.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan);
	  l4.mask.dst_port = 0xffff;
	}

      clib_memcpy (cmd + len, &l4, sizeof (l4));
      len += sizeof (l4);
      f->attr.num_of_specs++;
    }

  if (match->tunnel == RDMA_TUNNEL_GRE)
    {
      struct ibv_flow_spec_gre gre = {
	.type = IBV_FLOW_SPEC_GRE,
	.size = sizeof (gre),
	.val.protocol = clib_host_to_net_u16 (match->inner_ether_type),
	.mask.protocol = match->inner_ether_type ? 0xffff : 0,
      };

      clib_memcpy (cmd + len, &gre, sizeof (gre));
      len += sizeof (gre);
      f->attr.num_of_specs++;
    }

  if (match->tunnel == RDMA_TUNNEL_VXLAN)
    {
      struct ibv_flow_spec_tunnel vxlan = {
	.type = IBV_FLOW_SPEC_VXLAN_TUNNEL,
	.size = sizeof (vxlan),
      };

      clib_memcpy (cmd + len, &vxlan, sizeof (vxlan));
      len += sizeof (vxlan);
      f->attr.num_of_specs++;

      if (match->inner_ether_type)
	{
	  struct ibv_flow_spec_eth eth = {
	    .type = IBV_FLOW_SPEC_ETH | IBV_FLOW_SPEC_INNER,
	    .size = sizeof (eth),
	    .val.ether_type = clib_host_to_net_u16 (match->inner_ether_type),
	    .mask.ether_type = 0xffff,
	  };

	  clib_memcpy (cmd + len, &eth, sizeof (eth));
	  len += sizeof (eth);
	  f->attr.num_of_specs++;
	}
    }

  if (match->inner_ether_type)
    {
      len += rdma_flow_add_ip_spec (cmd + len, match->inner_ether_type, 0, IBV_FLOW_SPEC_INNER);
      f->attr.num_of_specs++;
    }

  if (match->inner_l4_spec_type)
    {
      struct ibv_flow_spec_tcp_udp l4 = {
	.type = match->inner_l4_spec_type | IBV_FLOW_SPEC_INNER,
	.size = sizeof (l4),
      };

      clib_memcpy (cmd + len, &l4, sizeof (l4));
      len += sizeof (l4);
      f->attr.num_of_specs++;
    }

  f->attr.size = len;
  clib_memcpy (attr, &f->attr, sizeof (f->attr));

  f->handle = ibv_create_flow (qp, attr);
  if (f->handle == 0)
    {
      clib_mem_free (f);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  pool_get_zero (*flows, fp);
  f->pool_index = fp - *flows;
  *fp = f;
  if (flow_index)
    *flow_index = f->pool_index;
  return VNET_DEV_OK;
}

u8
rdma_mac_in_addrs (vnet_dev_hw_addr_t *addrs, const u8 *mac)
{
  u32 i;

  vec_foreach_index (i, addrs)
    if (clib_memcmp (addrs[i].eth_mac, mac, 6) == 0)
      return 1;

  return 0;
}

i32
rdma_find_ucast_flow (rdma_rx_mac_flow_t *ucast_flows, const u8 *mac)
{
  u32 i;

  vec_foreach_index (i, ucast_flows)
    if (clib_memcmp (ucast_flows[i].mac, mac, 6) == 0)
      return i;

  return -1;
}

vnet_dev_rv_t
rdma_program_flow_state (struct ibv_qp *qp, rdma_rx_flow_t ***flows,
			 rdma_rx_mac_flow_t **ucast_flows, u32 *promisc_flow_index,
			 u32 *mcast_flow_index, vnet_dev_hw_addr_t *addrs, u8 promisc, u8 ibv_port,
			 const rdma_flow_match_t *match, u16 priority, u8 with_mcast)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  rdma_rx_mac_flow_t *f;
  u8 zero[6] = {};
  u8 ucast_mask[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  u8 mcast[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u8 mcast_mask[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u32 flow_index, i;

  if (promisc)
    {
      if (*promisc_flow_index == RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, zero, zero, match, priority, 0,
				      promisc_flow_index);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
      if (*mcast_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rdma_rxq_remove_flow_index (flows, *mcast_flow_index);
	  *mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
	}
      vec_foreach_index (i, *ucast_flows)
	rdma_rxq_remove_flow_index (flows, (*ucast_flows)[i].flow_index);
      vec_reset_length (*ucast_flows);
      return rv;
    }

  if (*promisc_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
    {
      rdma_rxq_remove_flow_index (flows, *promisc_flow_index);
      *promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
    }
  for (i = vec_len (*ucast_flows); i > 0; i--)
    {
      f = *ucast_flows + (i - 1);
      if (rdma_mac_in_addrs (addrs, f->mac))
	continue;
      rdma_rxq_remove_flow_index (flows, f->flow_index);
      vec_del1 (*ucast_flows, i - 1);
    }

  vec_foreach_index (i, addrs)
    {
      if (rdma_find_ucast_flow (*ucast_flows, addrs[i].eth_mac) >= 0)
	continue;
      rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, addrs[i].eth_mac, ucast_mask, match,
				  priority, 0, &flow_index);
      if (rv != VNET_DEV_OK)
	return rv;
      vec_add2 (*ucast_flows, f, 1);
      clib_memcpy (f->mac, addrs[i].eth_mac, sizeof (f->mac));
      f->flow_index = flow_index;
    }

  if (with_mcast && *mcast_flow_index == RDMA_RX_FLOW_INDEX_INVALID)
    {
      rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, mcast, mcast_mask, match, priority,
				  IBV_FLOW_ATTR_FLAGS_DONT_TRAP, mcast_flow_index);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  return rv;
}

void
rdma_rxq_remove_flow_index (rdma_rx_flow_t ***flows, u32 idx)
{
  rdma_rx_flow_t **fp, *f;

  if (*flows == 0 || pool_is_free_index (*flows, idx))
    return;

  fp = pool_elt_at_index (*flows, idx);
  f = fp[0];
  if (f == 0)
    return;
  if (f->handle)
    ibv_destroy_flow (f->handle);
  clib_mem_free (f);
  pool_put_index (*flows, idx);
}

void
rdma_rxq_destroy_flows (rdma_rx_flow_t ***flows)
{
  u32 i;

  if (*flows == 0)
    return;

  pool_foreach_index (i, *flows)
    {
      rdma_rx_flow_t **fp = pool_elt_at_index (*flows, i);
      rdma_rx_flow_t *f = fp[0];

      if (f == 0)
	continue;
      if (f->handle)
	ibv_destroy_flow (f->handle);
      clib_mem_free (f);
    }

  pool_free (*flows);
  *flows = 0;
}
