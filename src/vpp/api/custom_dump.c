/*
 * ------------------------------------------------------------------
 * custom_dump.c - pretty-print API messages for replay
 *
 * Copyright (c) 2014-2016 Cisco and/or its affiliates. Licensed under the
 * Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the
 * License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_api.h>
#include <vnet/unix/tuntap.h>
#include <vnet/mpls/mpls.h>
#include <vnet/l2/l2_input.h>
#include <vnet/srv6/sr.h>
#include <vnet/srmpls/sr_mpls.h>
#include <vnet/gre/gre.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/policer/xlate.h>
#include <vnet/policer/policer.h>
#include <vnet/classify/flow_classify.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/qos/qos_types.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/l2/l2_vtr.h>

#include <vpp/api/vpe_msg_enum.h>
#include <vpp/api/types.h>

#include <vnet/bonding/node.h>

#include <vnet/format_fns.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;


static void *vl_api_create_loopback_t_print
  (vl_api_create_loopback_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_loopback ");
  s = format (s, "mac %U ", format_ethernet_address, &mp->mac_address);

  FINISH;
}

static void *vl_api_create_loopback_instance_t_print
  (vl_api_create_loopback_instance_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_loopback ");
  s = format (s, "mac %U ", format_ethernet_address, &mp->mac_address);
  s = format (s, "instance %d ", mp->user_instance);

  FINISH;
}

static void *vl_api_delete_loopback_t_print
  (vl_api_delete_loopback_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_loopback ");
  s = format (s, "sw_if_index %d ", mp->sw_if_index);

  FINISH;
}

static void *vl_api_sw_interface_set_flags_t_print
  (vl_api_sw_interface_set_flags_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: sw_interface_set_flags ");

  s = format (s, "sw_if_index %d ", mp->sw_if_index);

  if ((mp->flags) & IF_STATUS_API_FLAG_ADMIN_UP)
    s = format (s, "admin-up ");
  else
    s = format (s, "admin-down ");

  FINISH;
}

__clib_unused
  static void *vl_api_sw_interface_set_rx_placement_t_print
  (vl_api_sw_interface_set_rx_placement_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: sw_interface_set_rx_placement ");

  s = format (s, "sw_if_index %d ", mp->sw_if_index);

  s = format (s, "queue %d ", mp->queue_id);
  if (mp->is_main)
    s = format (s, "main ");
  else
    s = format (s, "worker %d ", mp->worker_id);

  FINISH;
}

static void *vl_api_sw_interface_rx_placement_dump_t_print
  (vl_api_sw_interface_rx_placement_dump_t * mp, void *handle)
{
  u8 *s;
  u32 sw_if_index = (mp->sw_if_index);

  s = format (0, "SCRIPT: sw_interface_rx_placement_dump ");

  if (sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", sw_if_index);

  FINISH;
}

static void *vl_api_sw_interface_event_t_print
  (vl_api_sw_interface_event_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: sw_interface_event ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if ((mp->flags) & IF_STATUS_API_FLAG_ADMIN_UP)
    s = format (s, "admin-up ");
  else
    s = format (s, "admin-down ");

  if ((mp->flags) & IF_STATUS_API_FLAG_LINK_UP)
    s = format (s, "link-up");
  else
    s = format (s, "link-down");

  if (mp->deleted)
    s = format (s, " deleted");

  FINISH;
}


static void *vl_api_sw_interface_add_del_address_t_print
  (vl_api_sw_interface_add_del_address_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_add_del_address ");
  s = format (s, "sw_if_index %d ", mp->sw_if_index);
  s = format (s, "%U ", format_vl_api_prefix_t, &mp->prefix);
  if (mp->is_add == 0)
    s = format (s, "del ");
  if (mp->del_all)
    s = format (s, "del-all ");

  FINISH;
}

static void *vl_api_sw_interface_set_table_t_print
  (vl_api_sw_interface_set_table_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_table ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->vrf_id)
    s = format (s, "vrf %d ", (mp->vrf_id));

  if (mp->is_ipv6)
    s = format (s, "ipv6 ");

  FINISH;
}

static void *vl_api_sw_interface_set_mpls_enable_t_print
  (vl_api_sw_interface_set_mpls_enable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_mpls_enable ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->enable == 0)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_sw_interface_set_vpath_t_print
  (vl_api_sw_interface_set_vpath_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_vpath ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->enable)
    s = format (s, "enable ");
  else
    s = format (s, "disable ");

  FINISH;
}

static void *vl_api_sw_interface_set_vxlan_bypass_t_print
  (vl_api_sw_interface_set_vxlan_bypass_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_vxlan_bypass ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->is_ipv6)
    s = format (s, "ip6 ");

  if (mp->enable)
    s = format (s, "enable ");
  else
    s = format (s, "disable ");

  FINISH;
}

static void *vl_api_sw_interface_set_l2_xconnect_t_print
  (vl_api_sw_interface_set_l2_xconnect_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_l2_xconnect ");

  s = format (s, "sw_if_index %d ", (mp->rx_sw_if_index));

  if (mp->enable)
    {
      s = format (s, "tx_sw_if_index %d ", (mp->tx_sw_if_index));
    }
  else
    s = format (s, "delete ");

  FINISH;
}

static void *vl_api_sw_interface_set_l2_bridge_t_print
  (vl_api_sw_interface_set_l2_bridge_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_l2_bridge ");

  s = format (s, "sw_if_index %d ", (mp->rx_sw_if_index));

  if (mp->enable)
    {
      s = format (s, "bd_id %d shg %d ", (mp->bd_id), mp->shg);
      if (L2_API_PORT_TYPE_BVI == (mp->port_type))
	s = format (s, "bvi ");
      if (L2_API_PORT_TYPE_UU_FWD == (mp->port_type))
	s = format (s, "uu-fwd ");
      s = format (s, "enable");
    }
  else
    s = format (s, "disable ");

  FINISH;
}

static void *vl_api_bridge_domain_add_del_t_print
  (vl_api_bridge_domain_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bridge_domain_add_del ");

  s = format (s, "bd_id %d ", (mp->bd_id));

  if (mp->is_add)
    {
      if (mp->bd_tag[0])
	s = format (s, "bd_tag %s ", mp->bd_tag);
      s = format (s, "flood %d uu-flood %d ", mp->flood, mp->uu_flood);
      s = format (s, "forward %d learn %d ", mp->forward, mp->learn);
      s = format (s, "arp-term %d mac-age %d", mp->arp_term, mp->mac_age);
    }
  else
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_bridge_domain_set_mac_age_t_print
  (vl_api_bridge_domain_set_mac_age_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bridge_domain_set_mac_age ");

  s = format (s, "bd_id %d ", (mp->bd_id));

  s = format (s, "mac-age %d", mp->mac_age);

  FINISH;
}

static void *vl_api_bridge_domain_dump_t_print
  (vl_api_bridge_domain_dump_t * mp, void *handle)
{
  u8 *s;
  u32 bd_id = (mp->bd_id);

  s = format (0, "SCRIPT: bridge_domain_dump ");

  if (bd_id != ~0)
    s = format (s, "bd_id %d ", bd_id);

  FINISH;
}

static void *vl_api_l2fib_flush_all_t_print
  (vl_api_l2fib_flush_all_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2fib_flush_all ");

  FINISH;
}


static void *vl_api_l2fib_flush_bd_t_print
  (vl_api_l2fib_flush_bd_t * mp, void *handle)
{
  u8 *s;
  u32 bd_id = (mp->bd_id);

  s = format (0, "SCRIPT: l2fib_flush_bd ");
  s = format (s, "bd_id %d ", bd_id);

  FINISH;
}

static void *vl_api_l2fib_flush_int_t_print
  (vl_api_l2fib_flush_int_t * mp, void *handle)
{
  u8 *s;
  u32 sw_if_index = (mp->sw_if_index);

  s = format (0, "SCRIPT: l2fib_flush_int ");
  s = format (s, "sw_if_index %d ", sw_if_index);

  FINISH;
}

static void *vl_api_l2fib_add_del_t_print
  (vl_api_l2fib_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2fib_add_del ");

  s = format (s, "mac %U ", format_ethernet_address, mp->mac);

  s = format (s, "bd_id %d ", (mp->bd_id));


  if (mp->is_add)
    {
      s = format (s, "sw_if_index %d ", (mp->sw_if_index));
      if (mp->static_mac)
	s = format (s, "%s", "static ");
      if (mp->filter_mac)
	s = format (s, "%s", "filter ");
      if (mp->bvi_mac)
	s = format (s, "%s", "bvi ");
    }
  else
    {
      s = format (s, "del ");
    }

  FINISH;
}

static void *
vl_api_l2_flags_t_print (vl_api_l2_flags_t * mp, void *handle)
{
  u8 *s;
  u32 flags = (mp->feature_bitmap);

  s = format (0, "SCRIPT: l2_flags ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (flags & L2_LEARN)
    s = format (s, "learn ");
  if (flags & L2_FWD)
    s = format (s, "forward ");
  if (flags & L2_FLOOD)
    s = format (s, "flood ");
  if (flags & L2_UU_FLOOD)
    s = format (s, "uu-flood ");
  if (flags & L2_ARP_TERM)
    s = format (s, "arp-term ");

  if (mp->is_set == 0)
    s = format (s, "clear ");

  FINISH;
}

static void *vl_api_bridge_flags_t_print
  (vl_api_bridge_flags_t * mp, void *handle)
{
  u8 *s;
  u32 flags = (mp->flags);

  s = format (0, "SCRIPT: bridge_flags ");

  s = format (s, "bd_id %d ", (mp->bd_id));

  if (flags & BRIDGE_API_FLAG_LEARN)
    s = format (s, "learn ");
  if (flags & BRIDGE_API_FLAG_FWD)
    s = format (s, "forward ");
  if (flags & BRIDGE_API_FLAG_FLOOD)
    s = format (s, "flood ");
  if (flags & BRIDGE_API_FLAG_UU_FLOOD)
    s = format (s, "uu-flood ");
  if (flags & BRIDGE_API_FLAG_ARP_TERM)
    s = format (s, "arp-term ");

  if (mp->is_set == 0)
    s = format (s, "clear ");

  FINISH;
}

static void *vl_api_bd_ip_mac_add_del_t_print
  (vl_api_bd_ip_mac_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bd_ip_mac_add_del ");
  s = format (s, "bd_id %d ", (mp->entry.bd_id));

  s = format (s, "%U ", format_vl_api_address, &mp->entry.ip);
  s = format (s, "%U ", format_vl_api_mac_address, &mp->entry.mac);
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_bd_ip_mac_flush_t_print
  (vl_api_bd_ip_mac_flush_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bd_ip_mac_flush ");
  s = format (s, "bd_id %d ", (mp->bd_id));

  FINISH;
}

__clib_unused
  static void *vl_api_bd_ip_mac_dump_t_print
  (vl_api_bd_ip_mac_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bd_ip_mac_dump ");

  FINISH;
}

static void *vl_api_tap_create_v2_t_print
  (vl_api_tap_create_v2_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  clib_memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: tap_create_v2 ");
  s = format (s, "id %u ", (mp->id));
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac-address %U ",
		format_ethernet_address, mp->mac_address);
  if (memcmp (mp->host_mac_addr, null_mac, 6))
    s = format (s, "host-mac-addr %U ",
		format_ethernet_address, mp->host_mac_addr);
  if (mp->host_if_name_set)
    s = format (s, "host-if-name %s ", mp->host_if_name);
  if (mp->host_namespace_set)
    s = format (s, "host-ns %s ", mp->host_namespace);
  if (mp->host_bridge_set)
    s = format (s, "host-bridge %s ", mp->host_bridge);
  if (mp->host_ip4_prefix_set)
    s = format (s, "host-ip4-addr %U/%d ", format_ip4_address,
		mp->host_ip4_prefix.address, mp->host_ip4_prefix.len);
  if (mp->host_ip6_prefix_set)
    s = format (s, "host-ip6-addr %U/%d ", format_ip6_address,
		mp->host_ip6_prefix.address, mp->host_ip6_prefix.len);
  if (mp->host_ip4_gw_set)
    s =
      format (s, "host-ip4-gw %U ", format_ip4_address,
	      mp->host_ip4_prefix.address);
  if (mp->host_ip6_gw_set)
    s =
      format (s, "host-ip6-gw %U ", format_ip6_address,
	      mp->host_ip6_prefix.address);
  if (mp->num_rx_queues)
    s = format (s, "num_rx_queues %u ", mp->num_rx_queues);
  if (mp->tx_ring_sz)
    s = format (s, "tx-ring-size %u ", (mp->tx_ring_sz));
  if (mp->rx_ring_sz)
    s = format (s, "rx-ring-size %u ", (mp->rx_ring_sz));
  if (mp->host_mtu_set)
    s = format (s, "host-mtu-size %u ", (mp->host_mtu_size));
  if ((mp->tap_flags) & TAP_API_FLAG_GSO)
    s = format (s, "gso-enabled ");
  if ((mp->tap_flags) & TAP_API_FLAG_CSUM_OFFLOAD)
    s = format (s, "csum-offload-enabled ");
  if ((mp->tap_flags) & TAP_API_FLAG_PERSIST)
    s = format (s, "persist ");
  if ((mp->tap_flags) & TAP_API_FLAG_ATTACH)
    s = format (s, "attach ");
  if ((mp->tap_flags) & TAP_API_FLAG_TUN)
    s = format (s, "tun ");
  if ((mp->tap_flags) & TAP_API_FLAG_GRO_COALESCE)
    s = format (s, "gro-coalesce-enabled ");
  if ((mp->tap_flags) & TAP_API_FLAG_PACKED)
    s = format (s, "packed ");
  if ((mp->tap_flags) & TAP_API_FLAG_IN_ORDER)
    s = format (s, "in-order ");
  FINISH;
}

static void *vl_api_tap_delete_v2_t_print
  (vl_api_tap_delete_v2_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: tap_delete_v2 ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_tap_v2_dump_t_print
  (vl_api_sw_interface_tap_v2_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_tap_v2_dump ");

  FINISH;
}

__clib_unused
  static void *vl_api_virtio_pci_create_t_print
  (vl_api_virtio_pci_create_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  clib_memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: virtio_pci_create ");
  s = format (s, "pci_addr %U ", format_vlib_pci_addr, (mp->pci_addr));
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac-address %U ",
		format_ethernet_address, mp->mac_address);
  if (mp->features)
    s = format (s, "features 0x%llx ", clib_net_to_host_u64 (mp->features));
  if (mp->gso_enabled)
    s = format (s, "gso-enabled ");
  if (mp->checksum_offload_enabled)
    s = format (s, "checksum_offload_enabled");
  FINISH;
}

__clib_unused
  static void *vl_api_virtio_pci_create_v2_t_print
  (vl_api_virtio_pci_create_v2_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  clib_memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: virtio_pci_create_v2 ");
  s = format (s, "pci_addr %U ", format_vlib_pci_addr, (mp->pci_addr));
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac-address %U ",
		format_ethernet_address, mp->mac_address);
  if (mp->features)
    s = format (s, "features 0x%llx ", clib_net_to_host_u64 (mp->features));
  if (mp->virtio_flags & VIRTIO_API_FLAG_GSO)
    s = format (s, "gso-enabled ");
  if (mp->virtio_flags & VIRTIO_API_FLAG_CSUM_OFFLOAD)
    s = format (s, "checksum_offload_enabled ");
  if ((mp->virtio_flags) & VIRTIO_API_FLAG_GRO_COALESCE)
    s = format (s, "gro-coalesce-enabled ");
  if ((mp->virtio_flags) & VIRTIO_API_FLAG_PACKED)
    s = format (s, "packed ");
  if ((mp->virtio_flags) & VIRTIO_API_FLAG_IN_ORDER)
    s = format (s, "in-order ");
  if ((mp->virtio_flags) & VIRTIO_API_FLAG_BUFFERING)
    s = format (s, "buffering ");
  FINISH;
}

__clib_unused
  static void *vl_api_virtio_pci_delete_t_print
  (vl_api_virtio_pci_delete_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: virtio_pci_delete ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

__clib_unused
  static void *vl_api_sw_interface_virtio_pci_dump_t_print
  (vl_api_sw_interface_virtio_pci_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_virtio_pci_dump ");

  FINISH;
}

static void *vl_api_bond_create_t_print
  (vl_api_bond_create_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  clib_memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: bond_create ");
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac-address %U ",
		format_ethernet_address, mp->mac_address);
  if (mp->mode)
    s = format (s, "mode %U ", format_bond_mode, ntohl (mp->mode));
  if (mp->lb)
    s = format (s, "lb %U ", format_bond_load_balance, ntohl (mp->lb));
  if (mp->numa_only)
    s = format (s, "numa-only is set in lacp mode");
  if (mp->id != ~0)
    s = format (s, "id %u ", (mp->id));
  FINISH;
}

static void *vl_api_bond_create2_t_print
  (vl_api_bond_create2_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  clib_memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: bond_create2 ");
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac-address %U ",
		format_ethernet_address, mp->mac_address);
  if (mp->mode)
    s = format (s, "mode %U ", format_bond_mode, ntohl (mp->mode));
  if (mp->lb)
    s = format (s, "lb %U ", format_bond_load_balance, ntohl (mp->lb));
  if (mp->numa_only)
    s = format (s, "numa-only ");
  if (mp->enable_gso)
    s = format (s, "gso ");
  if (mp->id != ~0)
    s = format (s, "id %u ", (mp->id));
  FINISH;
}

static void *vl_api_bond_delete_t_print
  (vl_api_bond_delete_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bond_delete ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_bond_add_member_t_print
  (vl_api_bond_add_member_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bond_add_member ");
  s = format (s, "bond_sw_if_index %u ", (mp->bond_sw_if_index));
  s = format (s, "sw_if_index %u ", (mp->sw_if_index));
  if (mp->is_passive)
    s = format (s, "passive ");
  if (mp->is_long_timeout)
    s = format (s, "long-timeout ");

  FINISH;
}

static void *vl_api_sw_interface_set_bond_weight_t_print
  (vl_api_sw_interface_set_bond_weight_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_bond_weight ");
  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));
  s = format (s, "weight %u ", ntohl (mp->weight));

  FINISH;
}

static void *vl_api_bond_detach_member_t_print
  (vl_api_bond_detach_member_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bond_detach_member ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_bond_interface_dump_t_print
  (vl_api_sw_bond_interface_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_bond_interface_dump ");
  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_member_interface_dump_t_print
  (vl_api_sw_member_interface_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_member_interface_dump ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_ip_route_add_del_t_print
  (vl_api_ip_route_add_del_t * mp, void *handle)
{
  u8 *s, p;

  s = format (0, "SCRIPT: ip_route_add_del ");
  if (mp->is_add == 0)
    s = format (s, "del ");

  s = format (s, "%U", format_vl_api_prefix, &mp->route.prefix);

  for (p = 0; p < mp->route.n_paths; p++)
    s = format (s, " [%U]", format_vl_api_fib_path, &mp->route.paths[p]);

  FINISH;
}

static void *vl_api_mpls_route_add_del_t_print
  (vl_api_mpls_route_add_del_t * mp, void *handle)
{
  u8 *s, p;

  s = format (0, "SCRIPT: mpls_route_add_del ");

  if (mp->mr_is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");

  s = format (s, "table %d ", (mp->mr_route.mr_table_id));
  s = format (s, "%d ", (mp->mr_route.mr_label));

  if (mp->mr_route.mr_eos)
    s = format (s, "eos ");
  else
    s = format (s, "non-eos ");

  if (mp->mr_route.mr_is_multicast)
    s = format (s, "multicast ");

  for (p = 0; p < mp->mr_route.mr_n_paths; p++)
    s =
      format (s, " [%U]", format_vl_api_fib_path, &mp->mr_route.mr_paths[p]);


  FINISH;
}

static void *vl_api_ip_table_add_del_t_print
  (vl_api_ip_table_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_table_add_del ");
  if (mp->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");
  if (mp->table.is_ip6)
    s = format (s, "ip6 ");
  s = format (s, "table %d ", (mp->table.table_id));
  s = format (s, "%s ", mp->table.name);

  FINISH;
}

static void *vl_api_mpls_table_add_del_t_print
  (vl_api_mpls_table_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_table_add_del ");
  if (mp->mt_is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");
  s = format (s, "table %d ", (mp->mt_table.mt_table_id));

  FINISH;
}

static void *vl_api_mpls_tunnel_add_del_t_print
  (vl_api_mpls_tunnel_add_del_t * mp, void *handle)
{
  u8 *s, p;

  s = format (0, "SCRIPT: mpls_tunnel_add_del ");

  if (mp->mt_is_add == 0)
    s = format (s, "del sw_if_index %d ", (mp->mt_tunnel.mt_sw_if_index));
  else
    s = format (s, "sw_if_index %d ", (mp->mt_tunnel.mt_sw_if_index));


  if (mp->mt_tunnel.mt_l2_only)
    s = format (s, "l2-only ");
  if (mp->mt_tunnel.mt_is_multicast)
    s = format (s, "multicast ");
  if (mp->mt_tunnel.mt_tunnel_index)
    s = format (s, "tunnel-index ");

  for (p = 0; p < mp->mt_tunnel.mt_n_paths; p++)
    s = format (s, " [%U]", format_vl_api_fib_path,
		&mp->mt_tunnel.mt_paths[p]);

  FINISH;
}

static void *vl_api_sr_mpls_policy_add_t_print
  (vl_api_sr_mpls_policy_add_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sr_mpls_policy_add ");

  s = format (s, "bsid %d ", (mp->bsid));

  if (mp->weight != htonl ((u32) 1))
    s = format (s, "%d ", (mp->weight));

  if (mp->is_spray)
    s = format (s, "spray ");

  if (mp->n_segments)
    {
      int i;
      for (i = 0; i < mp->n_segments; i++)
	s = format (s, "next %d ", (mp->segments[i]));
    }

  FINISH;
}

static void *vl_api_sr_mpls_policy_del_t_print
  (vl_api_sr_mpls_policy_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sr_mpls_policy_del ");

  s = format (s, "bsid %d ", (mp->bsid));

  FINISH;
}

static void *vl_api_sw_interface_set_unnumbered_t_print
  (vl_api_sw_interface_set_unnumbered_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_unnumbered ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  s = format (s, "unnum_if_index %d ", (mp->unnumbered_sw_if_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_create_vlan_subif_t_print
  (vl_api_create_vlan_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_vlan_subif ");

  if (mp->sw_if_index)
    s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->vlan_id)
    s = format (s, "vlan_id %d ", (mp->vlan_id));

  FINISH;
}

#define foreach_create_subif_flag		\
_(0, "no_tags")					\
_(1, "one_tag")					\
_(2, "two_tags")				\
_(3, "dot1ad")					\
_(4, "exact_match")				\
_(5, "default_sub")				\
_(6, "outer_vlan_id_any")			\
_(7, "inner_vlan_id_any")

static void *vl_api_create_subif_t_print
  (vl_api_create_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_subif ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  s = format (s, "sub_id %d ", (mp->sub_id));

  if (mp->outer_vlan_id)
    s = format (s, "outer_vlan_id %d ", (mp->outer_vlan_id));

  if (mp->inner_vlan_id)
    s = format (s, "inner_vlan_id %d ", (mp->inner_vlan_id));

#define _(a,b) if (mp->sub_if_flags & (1 << a)) s = format (s, "%s ", b);
  foreach_create_subif_flag;
#undef _

  FINISH;
}

static void *vl_api_delete_subif_t_print
  (vl_api_delete_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_subif ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *
vl_api_ip_table_replace_begin_t_print (vl_api_ip_table_replace_begin_t * mp,
				       void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_table_replace_begin ");

  s = format (s, "v%s-table %d ",
	      mp->table.is_ip6 ? "6" : "4", (mp->table.table_id));

  FINISH;
}

static void *
vl_api_ip_table_flush_t_print (vl_api_ip_table_flush_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_table_flush ");

  s = format (s, "v%s-table %d ",
	      mp->table.is_ip6 ? "6" : "4", (mp->table.table_id));

  FINISH;
}

static void *
vl_api_ip_table_replace_end_t_print (vl_api_ip_table_replace_end_t * mp,
				     void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_table_replace_end ");

  s = format (s, "v%s-table %d ",
	      mp->table.is_ip6 ? "6" : "4", (mp->table.table_id));

  FINISH;
}

static void *vl_api_set_ip_flow_hash_t_print
  (vl_api_set_ip_flow_hash_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_ip_flow_hash ");

  s = format (s, "vrf_id %d ", (mp->vrf_id));

  if (mp->src)
    s = format (s, "src ");

  if (mp->dst)
    s = format (s, "dst ");

  if (mp->sport)
    s = format (s, "sport ");

  if (mp->dport)
    s = format (s, "dport ");

  if (mp->proto)
    s = format (s, "proto ");

  if (mp->reverse)
    s = format (s, "reverse ");

  if (mp->is_ipv6 != 0)
    s = format (s, "ipv6 ");

  FINISH;
}


static void *vl_api_l2_patch_add_del_t_print
  (vl_api_l2_patch_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_patch_add_del ");

  s = format (s, "rx_sw_if_index %d ", (mp->rx_sw_if_index));

  s = format (s, "tx_sw_if_index %d ", (mp->tx_sw_if_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_sr_localsid_add_del_t_print
  (vl_api_sr_localsid_add_del_t * mp, void *handle)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 *s;

  s = format (0, "SCRIPT: sr_localsid_add_del ");

  switch (mp->behavior)
    {
    case SR_BEHAVIOR_END:
      s = format (s, "Address: %U\nBehavior: End",
		  format_ip6_address, (ip6_address_t *) mp->localsid);
      s = format (s, (mp->end_psp ? "End.PSP: True" : "End.PSP: False"));
      break;
    case SR_BEHAVIOR_X:
      s =
	format (s,
		"Address: %U\nBehavior: X (Endpoint with Layer-3 cross-connect)"
		"\nIface: %U\nNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid,
		format_vnet_sw_if_index_name, vnm, (mp->sw_if_index),
		format_ip6_address, (ip6_address_t *) mp->nh_addr.un.ip6);
      s = format (s, (mp->end_psp ? "End.PSP: True" : "End.PSP: False"));
      break;
    case SR_BEHAVIOR_DX4:
      s =
	format (s,
		"Address: %U\nBehavior: DX4 (Endpoint with decapsulation with IPv4 cross-connect)"
		"\nIface: %U\nNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid,
		format_vnet_sw_if_index_name, vnm, (mp->sw_if_index),
		format_ip4_address, (ip4_address_t *) mp->nh_addr.un.ip4);
      break;
    case SR_BEHAVIOR_DX6:
      s =
	format (s,
		"Address: %U\nBehavior: DX6 (Endpoint with decapsulation with IPv6 cross-connect)"
		"\nIface: %UNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid,
		format_vnet_sw_if_index_name, vnm, (mp->sw_if_index),
		format_ip6_address, (ip6_address_t *) mp->nh_addr.un.ip6);
      break;
    case SR_BEHAVIOR_DX2:
      s =
	format (s,
		"Address: %U\nBehavior: DX2 (Endpoint with decapulation and Layer-2 cross-connect)"
		"\nIface: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid,
		format_vnet_sw_if_index_name, vnm, (mp->sw_if_index));
      break;
    case SR_BEHAVIOR_DT6:
      s =
	format (s,
		"Address: %U\nBehavior: DT6 (Endpoint with decapsulation and specific IPv6 table lookup)"
		"\nTable: %u", format_ip6_address,
		(ip6_address_t *) mp->localsid, (mp->fib_table));
      break;
    case SR_BEHAVIOR_DT4:
      s =
	format (s,
		"Address: %U\nBehavior: DT4 (Endpoint with decapsulation and specific IPv4 table lookup)"
		"\nTable: %u", format_ip6_address,
		(ip6_address_t *) mp->localsid, (mp->fib_table));
      break;
    default:
      if (mp->behavior >= SR_BEHAVIOR_LAST)
	{
	  s = format (s, "Address: %U\n Behavior: %u",
		      format_ip6_address, (ip6_address_t *) mp->localsid,
		      mp->behavior);
	}
      else
	//Should never get here...
	s = format (s, "Internal error");
      break;
    }
  FINISH;
}

static void *vl_api_sr_steering_add_del_t_print
  (vl_api_sr_steering_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sr_steering_add_del ");

  s = format (s, (mp->is_del ? "Del: True" : "Del: False"));

  switch (mp->traffic_type)
    {
    case SR_STEER_L2:
      s = format (s, "Traffic type: L2 iface: %u", (mp->sw_if_index));
      break;
    case SR_STEER_IPV4:
      s = format (s, "Traffic type: IPv4 %U/%u", format_ip4_address,
		  (ip4_address_t *) mp->prefix.address.un.ip4,
		  (mp->prefix.len));
      break;
    case SR_STEER_IPV6:
      s = format (s, "Traffic type: IPv6 %U/%u", format_ip6_address,
		  (ip6_address_t *) mp->prefix.address.un.ip6,
		  (mp->prefix.len));
      break;
    default:
      s = format (s, "Traffic type: Unknown(%u)", mp->traffic_type);
      break;
    }
  s = format (s, "BindingSID: %U", format_ip6_address,
	      (ip6_address_t *) mp->bsid_addr);

  s = format (s, "SR Policy Index: %u", (mp->sr_policy_index));

  s = format (s, "FIB_table: %u", (mp->table_id));

  FINISH;
}

static void *vl_api_sr_policy_add_t_print
  (vl_api_sr_policy_add_t * mp, void *handle)
{
  u8 *s;

  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->sids.sids;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  s = format (0, "SCRIPT: sr_policy_add ");

  s = format (s, "BSID: %U", format_ip6_address,
	      (ip6_address_t *) mp->bsid_addr);

  s =
    format (s,
	    (mp->is_encap ? "Behavior: Encapsulation" :
	     "Behavior: SRH insertion"));

  s = format (s, "FIB_table: %u", (mp->fib_table));

  s = format (s, (mp->is_spray ? "Type: Default" : "Type: Spray"));

  s = format (s, "SID list weight: %u", (mp->weight));

  s = format (s, "{");
  vec_foreach (seg, segments)
  {
    s = format (s, "%U, ", format_ip6_address, seg);
  }
  s = format (s, "\b\b } ");

  FINISH;
}

static void *vl_api_sr_policy_mod_t_print
  (vl_api_sr_policy_mod_t * mp, void *handle)
{
  u8 *s;

  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->sids.sids;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  s = format (0, "SCRIPT: sr_policy_mod ");

  s = format (s, "BSID: %U", format_ip6_address,
	      (ip6_address_t *) mp->bsid_addr);

  s = format (s, "SR Policy index: %u", (mp->sr_policy_index));

  s = format (s, "Operation: %u", mp->operation);

  s = format (s, "SID list index: %u", (mp->sl_index));

  s = format (s, "SID list weight: %u", (mp->weight));

  s = format (s, "{");
  vec_foreach (seg, segments)
  {
    s = format (s, "%U, ", format_ip6_address, seg);
  }
  s = format (s, "\b\b } ");

  FINISH;
}

static void *vl_api_sr_policy_del_t_print
  (vl_api_sr_policy_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sr_policy_del ");
  s = format (s, "To be delivered. Good luck.");
  FINISH;
}

static void *vl_api_classify_add_del_table_t_print
  (vl_api_classify_add_del_table_t * mp, void *handle)
{
  u8 *s;
  int i;

  s = format (0, "SCRIPT: classify_add_del_table ");

  if (mp->is_add == 0)
    {
      s = format (s, "table %d ", (mp->table_index));
      s = format (s, "%s ", mp->del_chain ? "del-chain" : "del");
    }
  else
    {
      s = format (s, "nbuckets %d ", (mp->nbuckets));
      s = format (s, "memory_size %d ", (mp->memory_size));
      s = format (s, "skip %d ", (mp->skip_n_vectors));
      s = format (s, "match %d ", (mp->match_n_vectors));
      s = format (s, "next-table %d ", (mp->next_table_index));
      s = format (s, "miss-next %d ", (mp->miss_next_index));
      s = format (s, "current-data-flag %d ", (mp->current_data_flag));
      if (mp->current_data_flag)
	s = format (s, "current-data-offset %d ", (mp->current_data_offset));
      s = format (s, "mask hex ");
      for (i = 0; i < (mp->match_n_vectors) * sizeof (u32x4); i++)
	s = format (s, "%02x", mp->mask[i]);
      vec_add1 (s, ' ');
    }

  FINISH;
}

static void *vl_api_classify_add_del_session_t_print
  (vl_api_classify_add_del_session_t * mp, void *handle)
{
  u8 *s;
  int i, limit = 0;

  s = format (0, "SCRIPT: classify_add_del_session ");

  s = format (s, "table_index %d ", (mp->table_index));
  s = format (s, "hit_next_index %d ", (mp->hit_next_index));
  s = format (s, "opaque_index %d ", (mp->opaque_index));
  s = format (s, "advance %d ", (mp->advance));
  s = format (s, "action %d ", mp->action);
  if (mp->action)
    s = format (s, "metadata %d ", (mp->metadata));
  if (mp->is_add == 0)
    s = format (s, "del ");

  s = format (s, "match hex ");
  for (i = 5 * sizeof (u32x4) - 1; i > 0; i--)
    {
      if (mp->match[i] != 0)
	{
	  limit = i + 1;
	  break;
	}
    }

  for (i = 0; i < limit; i++)
    s = format (s, "%02x", mp->match[i]);

  FINISH;
}

static void *vl_api_classify_set_interface_ip_table_t_print
  (vl_api_classify_set_interface_ip_table_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_set_interface_ip_table ");

  if (mp->is_ipv6)
    s = format (s, "ipv6 ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "table %d ", (mp->table_index));

  FINISH;
}

static void *vl_api_classify_set_interface_l2_tables_t_print
  (vl_api_classify_set_interface_l2_tables_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_set_interface_l2_tables ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "ip4-table %d ", (mp->ip4_table_index));
  s = format (s, "ip6-table %d ", (mp->ip6_table_index));
  s = format (s, "other-table %d ", (mp->other_table_index));
  s = format (s, "is-input %d ", mp->is_input);

  FINISH;
}

static void *vl_api_add_node_next_t_print
  (vl_api_add_node_next_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: add_node_next ");

  s = format (s, "node %s next %s ", mp->node_name, mp->next_name);

  FINISH;
}

static void *vl_api_vxlan_add_del_tunnel_t_print
  (vl_api_vxlan_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: vxlan_add_del_tunnel ");

  ip46_address_t src =
    to_ip46 (mp->src_address.af, (u8 *) & mp->src_address.un);
  ip46_address_t dst =
    to_ip46 (mp->dst_address.af, (u8 *) & mp->dst_address.un);

  u8 is_grp = ip46_address_is_multicast (&dst);
  char *dst_name = is_grp ? "group" : "dst";

  s = format (s, "src %U ", format_ip46_address, &src, IP46_TYPE_ANY);
  s = format (s, "%s %U ", dst_name, format_ip46_address,
	      &dst, IP46_TYPE_ANY);

  if (is_grp)
    s = format (s, "mcast_sw_if_index %d ", (mp->mcast_sw_if_index));

  if (mp->encap_vrf_id)
    s = format (s, "encap-vrf-id %d ", (mp->encap_vrf_id));

  s = format (s, "decap-next %d ", (mp->decap_next_index));

  s = format (s, "vni %d ", (mp->vni));

  s = format (s, "instance %d ", (mp->instance));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_vxlan_offload_rx_t_print
  (vl_api_vxlan_offload_rx_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: vxlan_offload_rx ");

  s = format (s, "hw hw_if_index %d ", (mp->hw_if_index));
  s = format (s, "rx sw_if_index %d ", (mp->sw_if_index));
  if (!mp->enable)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_vxlan_tunnel_dump_t_print
  (vl_api_vxlan_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_tunnel_dump ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_vxlan_gbp_tunnel_add_del_t_print
  (vl_api_vxlan_gbp_tunnel_add_del_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: vxlan_gbp_tunnel_add_del ");

  if (mp->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");

  s = format (s, "instance %d ", (mp->tunnel.instance));
  s = format (s, "src %U ", format_vl_api_address, &mp->tunnel.src);
  s = format (s, "dst %U ", format_vl_api_address, &mp->tunnel.dst);
  s = format (s, "mcast_sw_if_index %d ", (mp->tunnel.mcast_sw_if_index));
  s = format (s, "encap_table_id %d ", (mp->tunnel.encap_table_id));
  s = format (s, "vni %d ", (mp->tunnel.vni));
  s = format (s, "sw_if_index %d ", (mp->tunnel.sw_if_index));

  FINISH;
}

static void *vl_api_vxlan_gbp_tunnel_dump_t_print
  (vl_api_vxlan_gbp_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_gbp_tunnel_dump ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_set_vxlan_gbp_bypass_t_print
  (vl_api_sw_interface_set_vxlan_gbp_bypass_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_vxlan_gbp_bypass ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "%s ", (mp->is_ipv6 != 0) ? "ipv6" : "ipv4");
  s = format (s, "%s ", (mp->enable != 0) ? "enable" : "disable");

  FINISH;
}

static void *vl_api_gre_tunnel_add_del_t_print
  (vl_api_gre_tunnel_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gre_tunnel_add_del ");

  s = format (s, "dst %U ", format_vl_api_address, &mp->tunnel.dst);
  s = format (s, "src %U ", format_vl_api_address, &mp->tunnel.src);

  s = format (s, "instance %d ", (mp->tunnel.instance));

  if (mp->tunnel.type == GRE_API_TUNNEL_TYPE_TEB)
    s = format (s, "teb ");

  if (mp->tunnel.type == GRE_API_TUNNEL_TYPE_ERSPAN)
    s = format (s, "erspan %d ", (mp->tunnel.session_id));

  if (mp->tunnel.outer_table_id)
    s = format (s, "outer-table-id %d ", mp->tunnel.outer_table_id);

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_gre_tunnel_dump_t_print
  (vl_api_gre_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gre_tunnel_dump ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_l2_fib_clear_table_t_print
  (vl_api_l2_fib_clear_table_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_fib_clear_table ");

  FINISH;
}

static void *vl_api_l2_interface_efp_filter_t_print
  (vl_api_l2_interface_efp_filter_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_interface_efp_filter ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (mp->enable_disable)
    s = format (s, "enable ");
  else
    s = format (s, "disable ");

  FINISH;
}

static void *vl_api_l2_interface_vlan_tag_rewrite_t_print
  (vl_api_l2_interface_vlan_tag_rewrite_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_interface_vlan_tag_rewrite ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "vtr_op %d ", (mp->vtr_op));
  s = format (s, "push_dot1q %d ", (mp->push_dot1q));
  s = format (s, "tag1 %d ", (mp->tag1));
  s = format (s, "tag2 %d ", (mp->tag2));

  FINISH;
}

static void *vl_api_create_vhost_user_if_t_print
  (vl_api_create_vhost_user_if_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_vhost_user_if ");

  s = format (s, "socket %s ", mp->sock_filename);
  if (mp->is_server)
    s = format (s, "server ");
  if (mp->renumber)
    s = format (s, "renumber %d ", (mp->custom_dev_instance));
  if (mp->disable_mrg_rxbuf)
    s = format (s, "disable_mrg_rxbuf ");
  if (mp->disable_indirect_desc)
    s = format (s, "disable_indirect_desc ");
  if (mp->tag[0])
    s = format (s, "tag %s ", mp->tag);
  if (mp->enable_gso)
    s = format (s, "gso ");
  if (mp->enable_packed)
    s = format (s, "packed");

  FINISH;
}

static void *vl_api_modify_vhost_user_if_t_print
  (vl_api_modify_vhost_user_if_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: modify_vhost_user_if ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "socket %s ", mp->sock_filename);
  if (mp->is_server)
    s = format (s, "server ");
  if (mp->renumber)
    s = format (s, "renumber %d ", (mp->custom_dev_instance));
  if (mp->enable_gso)
    s = format (s, "gso ");
  if (mp->enable_packed)
    s = format (s, "packed");

  FINISH;
}

static void *vl_api_create_vhost_user_if_v2_t_print
  (vl_api_create_vhost_user_if_v2_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_vhost_user_if_v2 ");

  s = format (s, "socket %s ", mp->sock_filename);
  if (mp->is_server)
    s = format (s, "server ");
  if (mp->renumber)
    s = format (s, "renumber %d ", (mp->custom_dev_instance));
  if (mp->disable_mrg_rxbuf)
    s = format (s, "disable_mrg_rxbuf ");
  if (mp->disable_indirect_desc)
    s = format (s, "disable_indirect_desc ");
  if (mp->tag[0])
    s = format (s, "tag %s ", mp->tag);
  if (mp->enable_gso)
    s = format (s, "gso ");
  if (mp->enable_event_idx)
    s = format (s, "event-idx ");
  if (mp->enable_packed)
    s = format (s, "packed");

  FINISH;
}

static void *vl_api_modify_vhost_user_if_v2_t_print
  (vl_api_modify_vhost_user_if_v2_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: modify_vhost_user_if_v2 ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "socket %s ", mp->sock_filename);
  if (mp->is_server)
    s = format (s, "server ");
  if (mp->renumber)
    s = format (s, "renumber %d ", (mp->custom_dev_instance));
  if (mp->enable_gso)
    s = format (s, "gso ");
  if (mp->enable_event_idx)
    s = format (s, "event-idx ");
  if (mp->enable_packed)
    s = format (s, "packed");

  FINISH;
}

static void *vl_api_delete_vhost_user_if_t_print
  (vl_api_delete_vhost_user_if_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_vhost_user_if ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_vhost_user_dump_t_print
  (vl_api_sw_interface_vhost_user_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_vhost_user_dump ");
  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_dump_t_print
  (vl_api_sw_interface_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_dump ");

  if (mp->name_filter_valid)
    {
      u8 *v = vl_api_from_api_to_new_vec (mp, &mp->name_filter);
      s = format (s, "name_filter %v ", v);
      vec_free (v);
    }
  else
    s = format (s, "all ");

  FINISH;
}

static void *vl_api_l2_fib_table_dump_t_print
  (vl_api_l2_fib_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_fib_table_dump ");

  s = format (s, "bd_id %d ", (mp->bd_id));

  FINISH;
}

static void *vl_api_control_ping_t_print
  (vl_api_control_ping_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: control_ping ");

  FINISH;
}

static void *vl_api_want_interface_events_t_print
  (vl_api_want_interface_events_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: want_interface_events pid %d enable %d ",
	      (mp->pid), ntohl (mp->enable_disable));

  FINISH;
}

static void *
vl_api_cli_t_print (vl_api_cli_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: cli ");

  FINISH;
}

static void *vl_api_cli_inband_t_print
  (vl_api_cli_inband_t * mp, void *handle)
{
  u8 *s;
  u8 *cmd = 0;

  cmd = vl_api_from_api_to_new_vec (mp, &mp->cmd);

  s = format (0, "SCRIPT: exec %v ", cmd);

  vec_free (cmd);
  FINISH;
}

static void *vl_api_memclnt_create_t_print
  (vl_api_memclnt_create_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: memclnt_create name %s ", mp->name);

  FINISH;
}

static void *vl_api_sockclnt_create_t_print
  (vl_api_sockclnt_create_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sockclnt_create name %s ", mp->name);

  FINISH;
}

static void *vl_api_show_version_t_print
  (vl_api_show_version_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: show_version ");

  FINISH;
}

__clib_unused
  static void *vl_api_show_threads_t_print
  (vl_api_show_threads_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: show_threads ");

  FINISH;
}

static void *vl_api_vxlan_gpe_add_del_tunnel_t_print
  (vl_api_vxlan_gpe_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_gpe_add_del_tunnel ");

  ip46_address_t local, remote;

  ip_address_decode (&mp->local, &local);
  ip_address_decode (&mp->remote, &remote);

  u8 is_grp = ip46_address_is_multicast (&remote);
  char *remote_name = is_grp ? "group" : "remote";

  s = format (s, "local %U ", format_ip46_address, &local, IP46_TYPE_ANY);
  s = format (s, "%s %U ", remote_name, format_ip46_address,
	      &remote, IP46_TYPE_ANY);

  if (is_grp)
    s = format (s, "mcast_sw_if_index %d ", (mp->mcast_sw_if_index));
  s = format (s, "protocol %d ", (mp->protocol));

  s = format (s, "vni %d ", (mp->vni));

  if (mp->is_add == 0)
    s = format (s, "del ");

  if (mp->encap_vrf_id)
    s = format (s, "encap-vrf-id %d ", (mp->encap_vrf_id));

  if (mp->decap_vrf_id)
    s = format (s, "decap-vrf-id %d ", (mp->decap_vrf_id));

  FINISH;
}

static void *vl_api_vxlan_gpe_tunnel_dump_t_print
  (vl_api_vxlan_gpe_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_gpe_tunnel_dump ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_interface_name_renumber_t_print
  (vl_api_interface_name_renumber_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: interface_renumber ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  s = format (s, "new_show_dev_instance %d ", (mp->new_show_dev_instance));

  FINISH;
}

static void *vl_api_want_l2_macs_events_t_print
  (vl_api_want_l2_macs_events_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: want_l2_macs_events ");
  s = format (s, "learn-limit %d ", (mp->learn_limit));
  s = format (s, "scan-delay %d ", (u32) mp->scan_delay);
  s = format (s, "max-entries %d ", (u32) mp->max_macs_in_event * 10);
  if (mp->enable_disable == 0)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_input_acl_set_interface_t_print
  (vl_api_input_acl_set_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: input_acl_set_interface ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "ip4-table %d ", (mp->ip4_table_index));
  s = format (s, "ip6-table %d ", (mp->ip6_table_index));
  s = format (s, "l2-table %d ", (mp->l2_table_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_output_acl_set_interface_t_print
  (vl_api_output_acl_set_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: output_acl_set_interface ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "ip4-table %d ", (mp->ip4_table_index));
  s = format (s, "ip6-table %d ", (mp->ip6_table_index));
  s = format (s, "l2-table %d ", (mp->l2_table_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ip_address_dump_t_print
  (vl_api_ip_address_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip6_address_dump ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "is_ipv6 %d ", mp->is_ipv6 != 0);

  FINISH;
}

static void *
vl_api_ip_dump_t_print (vl_api_ip_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_dump ");
  s = format (s, "is_ipv6 %d ", mp->is_ipv6 != 0);

  FINISH;
}

static void *vl_api_cop_interface_enable_disable_t_print
  (vl_api_cop_interface_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: cop_interface_enable_disable ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (mp->enable_disable)
    s = format (s, "enable ");
  else
    s = format (s, "disable ");

  FINISH;
}

static void *vl_api_cop_whitelist_enable_disable_t_print
  (vl_api_cop_whitelist_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: cop_whitelist_enable_disable ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "fib-id %d ", (mp->fib_id));
  if (mp->ip4)
    s = format (s, "ip4 ");
  if (mp->ip6)
    s = format (s, "ip6 ");
  if (mp->default_cop)
    s = format (s, "default ");

  FINISH;
}

static void *vl_api_af_packet_create_t_print
  (vl_api_af_packet_create_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: af_packet_create ");
  s = format (s, "host_if_name %s ", mp->host_if_name);
  if (mp->use_random_hw_addr)
    s = format (s, "hw_addr random ");
  else
    s = format (s, "hw_addr %U ", format_ethernet_address, mp->hw_addr);

  FINISH;
}

static void *vl_api_af_packet_delete_t_print
  (vl_api_af_packet_delete_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: af_packet_delete ");
  s = format (s, "host_if_name %s ", mp->host_if_name);

  FINISH;
}

static void *vl_api_af_packet_dump_t_print
  (vl_api_af_packet_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: af_packet_dump ");

  FINISH;
}

static u8 *
format_policer_action (u8 * s, va_list * va)
{
  u32 action = va_arg (*va, u32);
  u32 dscp = va_arg (*va, u32);
  char *t = 0;

  if (action == SSE2_QOS_ACTION_DROP)
    s = format (s, "drop");
  else if (action == SSE2_QOS_ACTION_TRANSMIT)
    s = format (s, "transmit");
  else if (action == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    {
      s = format (s, "mark-and-transmit ");
      switch (dscp)
	{
#define _(v,f,str) case VNET_DSCP_##f: t = str; break;
	  foreach_vnet_dscp
#undef _
	default:
	  break;
	}
      s = format (s, "%s", t);
    }
  return s;
}

static void *vl_api_policer_add_del_t_print
  (vl_api_policer_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: policer_add_del ");
  s = format (s, "name %s ", mp->name);
  s = format (s, "cir %d ", mp->cir);
  s = format (s, "eir %d ", mp->eir);
  s = format (s, "cb %d ", mp->cb);
  s = format (s, "eb %d ", mp->eb);

  switch (mp->rate_type)
    {
    case SSE2_QOS_RATE_KBPS:
      s = format (s, "rate_type kbps ");
      break;
    case SSE2_QOS_RATE_PPS:
      s = format (s, "rate_type pps ");
      break;
    default:
      break;
    }

  switch (mp->round_type)
    {
    case SSE2_QOS_ROUND_TO_CLOSEST:
      s = format (s, "round_type closest ");
      break;
    case SSE2_QOS_ROUND_TO_UP:
      s = format (s, "round_type up ");
      break;
    case SSE2_QOS_ROUND_TO_DOWN:
      s = format (s, "round_type down ");
      break;
    default:
      break;
    }

  switch (mp->type)
    {
    case SSE2_QOS_POLICER_TYPE_1R2C:
      s = format (s, "type 1r2c ");
      break;
    case SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697:
      s = format (s, "type 1r3c ");
      break;
    case SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698:
      s = format (s, "type 2r3c-2698 ");
      break;
    case SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115:
      s = format (s, "type 2r3c-4115 ");
      break;
    case SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1:
      s = format (s, "type 2r3c-mef5cf1 ");
      break;
    default:
      break;
    }

  s = format (s, "conform_action %U ", format_policer_action,
	      mp->conform_action.type, mp->conform_action.dscp);
  s = format (s, "exceed_action %U ", format_policer_action,
	      mp->exceed_action.type, mp->exceed_action.dscp);
  s = format (s, "violate_action %U ", format_policer_action,
	      mp->violate_action.type, mp->violate_action.dscp);

  if (mp->color_aware)
    s = format (s, "color-aware ");
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_policer_dump_t_print
  (vl_api_policer_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: policer_dump ");
  if (mp->match_name_valid)
    s = format (s, "name %s ", mp->match_name);

  FINISH;
}

static void *vl_api_policer_classify_set_interface_t_print
  (vl_api_policer_classify_set_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: policer_classify_set_interface ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (mp->ip4_table_index != ~0)
    s = format (s, "ip4-table %d ", (mp->ip4_table_index));
  if (mp->ip6_table_index != ~0)
    s = format (s, "ip6-table %d ", (mp->ip6_table_index));
  if (mp->l2_table_index != ~0)
    s = format (s, "l2-table %d ", (mp->l2_table_index));
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_policer_classify_dump_t_print
  (vl_api_policer_classify_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: policer_classify_dump ");
  switch (mp->type)
    {
    case POLICER_CLASSIFY_API_TABLE_IP4:
      s = format (s, "type ip4 ");
      break;
    case POLICER_CLASSIFY_API_TABLE_IP6:
      s = format (s, "type ip6 ");
      break;
    case POLICER_CLASSIFY_API_TABLE_L2:
      s = format (s, "type l2 ");
      break;
    default:
      break;
    }

  FINISH;
}

static void *vl_api_sw_interface_clear_stats_t_print
  (vl_api_sw_interface_clear_stats_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_clear_stats ");
  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_mpls_tunnel_dump_t_print
  (vl_api_mpls_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_tunnel_dump ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_mpls_table_dump_t_print
  (vl_api_mpls_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_table_decap_dump ");

  FINISH;
}

static void *vl_api_mpls_route_dump_t_print
  (vl_api_mpls_route_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_route_decap_dump ");

  FINISH;
}

static void *vl_api_ip_table_dump_t_print
  (vl_api_ip_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_table_dump ");

  FINISH;
}

static void *vl_api_ip_route_dump_t_print
  (vl_api_ip_route_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_route_dump ");

  FINISH;
}

static void *vl_api_classify_table_ids_t_print
  (vl_api_classify_table_ids_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_table_ids ");

  FINISH;
}

static void *vl_api_classify_table_by_interface_t_print
  (vl_api_classify_table_by_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_table_by_interface ");
  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  FINISH;
}

static void *vl_api_classify_table_info_t_print
  (vl_api_classify_table_info_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_table_info ");
  if (mp->table_id != ~0)
    s = format (s, "table_id %d ", (mp->table_id));

  FINISH;
}

static void *vl_api_classify_session_dump_t_print
  (vl_api_classify_session_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_session_dump ");
  if (mp->table_id != ~0)
    s = format (s, "table_id %d ", (mp->table_id));

  FINISH;
}

static void *vl_api_set_ipfix_exporter_t_print
  (vl_api_set_ipfix_exporter_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_ipfix_exporter ");

  s = format (s, "collector-address %U ", format_ip4_address,
	      (ip4_address_t *) mp->collector_address.un.ip4);
  s = format (s, "collector-port %d ", (mp->collector_port));
  s = format (s, "src-address %U ", format_ip4_address,
	      (ip4_address_t *) mp->src_address.un.ip4);
  s = format (s, "vrf-id %d ", (mp->vrf_id));
  s = format (s, "path-mtu %d ", (mp->path_mtu));
  s = format (s, "template-interval %d ", (mp->template_interval));
  s = format (s, "udp-checksum %d ", mp->udp_checksum);

  FINISH;
}

static void *vl_api_ipfix_exporter_dump_t_print
  (vl_api_ipfix_exporter_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipfix_exporter_dump ");

  FINISH;
}

static void *vl_api_set_ipfix_classify_stream_t_print
  (vl_api_set_ipfix_classify_stream_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_ipfix_classify_stream ");

  s = format (s, "domain-id %d ", (mp->domain_id));
  s = format (s, "src-port %d ", (mp->src_port));

  FINISH;
}

static void *vl_api_ipfix_classify_stream_dump_t_print
  (vl_api_ipfix_classify_stream_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipfix_classify_stream_dump ");

  FINISH;
}

static void *vl_api_ipfix_classify_table_add_del_t_print
  (vl_api_ipfix_classify_table_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipfix_classify_table_add_del ");

  s = format (s, "table-id %d ", (mp->table_id));
  s = format (s, "ip-version %d ", mp->ip_version);
  s = format (s, "transport-protocol %d ", mp->transport_protocol);

  FINISH;
}

static void *vl_api_ipfix_classify_table_dump_t_print
  (vl_api_ipfix_classify_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipfix_classify_table_dump ");

  FINISH;
}

static void *vl_api_sw_interface_span_enable_disable_t_print
  (vl_api_sw_interface_span_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_span_enable_disable ");
  s = format (s, "src_sw_if_index %u ", (mp->sw_if_index_from));
  s = format (s, "dst_sw_if_index %u ", (mp->sw_if_index_to));

  if (mp->is_l2)
    s = format (s, "l2 ");

  switch (mp->state)
    {
    case 0:
      s = format (s, "disable ");
      break;
    case 1:
      s = format (s, "rx ");
      break;
    case 2:
      s = format (s, "tx ");
      break;
    case 3:
    default:
      s = format (s, "both ");
      break;
    }

  FINISH;
}

static void *
vl_api_sw_interface_span_dump_t_print (vl_api_sw_interface_span_dump_t * mp,
				       void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_span_dump ");

  if (mp->is_l2)
    s = format (s, "l2 ");

  FINISH;
}

static void *vl_api_get_next_index_t_print
  (vl_api_get_next_index_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: get_next_index ");
  s = format (s, "node-name %s ", mp->node_name);
  s = format (s, "next-node-name %s ", mp->next_name);

  FINISH;
}

static void *vl_api_pg_create_interface_t_print
  (vl_api_pg_create_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_create_interface ");
  s = format (s, "if_id %d ", (mp->interface_id));
  s = format (s, "gso-enabled %u ", mp->gso_enabled);
  s = format (s, "gso-size %u", (mp->gso_size));

  FINISH;
}

static void *vl_api_pg_capture_t_print
  (vl_api_pg_capture_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_capture ");
  s = format (s, "if_id %d ", (mp->interface_id));
  s = format (s, "pcap %s", mp->pcap_file_name);
  if (mp->count != ~0)
    s = format (s, "count %d ", (mp->count));
  if (!mp->is_enabled)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_pg_enable_disable_t_print
  (vl_api_pg_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_enable_disable ");
  if (vl_api_string_len (&mp->stream_name) > 0)
    s =
      format (s, "stream %s",
	      vl_api_from_api_to_new_c_string (&mp->stream_name));
  if (!mp->is_enabled)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_pg_interface_enable_disable_coalesce_t_print
  (vl_api_pg_interface_enable_disable_coalesce_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_interface_enable_disable_coalesce ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (!mp->coalesce_enabled)
    s = format (s, "disable");
  else
    s = format (s, "enable");
  FINISH;
}


static void *vl_api_ip_source_and_port_range_check_add_del_t_print
  (vl_api_ip_source_and_port_range_check_add_del_t * mp, void *handle)
{
  u8 *s;
  int i;

  s = format (0, "SCRIPT: ip_source_and_port_range_check_add_del ");
  s = format (s, "%U ", format_vl_api_prefix, &mp->prefix);

  for (i = 0; i < mp->number_of_ranges; i++)
    {
      s = format (s, "range %d - %d ", mp->low_ports[i], mp->high_ports[i]);
    }

  s = format (s, "vrf %d ", (mp->vrf_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ip_source_and_port_range_check_interface_add_del_t_print
  (vl_api_ip_source_and_port_range_check_interface_add_del_t * mp,
   void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_source_and_port_range_check_interface_add_del ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));

  if (mp->tcp_out_vrf_id != ~0)
    s = format (s, "tcp-out-vrf %d ", (mp->tcp_out_vrf_id));

  if (mp->udp_out_vrf_id != ~0)
    s = format (s, "udp-out-vrf %d ", (mp->udp_out_vrf_id));

  if (mp->tcp_in_vrf_id != ~0)
    s = format (s, "tcp-in-vrf %d ", (mp->tcp_in_vrf_id));

  if (mp->udp_in_vrf_id != ~0)
    s = format (s, "udp-in-vrf %d ", (mp->udp_in_vrf_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ipsec_tunnel_if_add_del_t_print
  (vl_api_ipsec_tunnel_if_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipsec_tunnel_if_add_del ");

  if (mp->esn)
    s = format (s, "esn");
  if (mp->anti_replay)
    s = format (s, "anti-replay");
  if (mp->udp_encap)
    s = format (s, "udp-encap");

  s = format (s, "local-ip %U ", format_vl_api_address, &mp->remote_ip);

  s = format (s, "remote-ip %U ", format_vl_api_address, &mp->local_ip);
  s = format (s, "tx-table-id %d ", (mp->tx_table_id));

  s = format (s, "local-spi %d ", (mp->local_spi));

  s = format (s, "remote-spi %d ", (mp->remote_spi));

  s = format (s, "local-crypto-key-len %d ", mp->local_crypto_key_len);
  s = format (s, "local-crypto-key %U ", format_hex_bytes,
	      mp->local_crypto_key, mp->local_crypto_key_len, 0);
  s = format (s, "remote-crypto-key-len %d ", mp->remote_crypto_key_len);
  s = format (s, "remote-crypto-key %U ", format_hex_bytes,
	      mp->remote_crypto_key, mp->remote_crypto_key_len, 0);
  s = format (s, "local-integ-key-len %d ", mp->local_integ_key_len);
  s = format (s, "local-integ-key %U ", format_hex_bytes,
	      mp->local_integ_key, mp->local_integ_key_len, 0);
  s = format (s, "remote-integ-key-len %d ", mp->remote_integ_key_len);
  s = format (s, "remote-integ-key %U ", format_hex_bytes,
	      mp->remote_integ_key, mp->remote_integ_key_len, 0);

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

/* static u8 * */
/* format_nsh_address_vat (u8 * s, va_list * args) */
/* { */
/*   nsh_t *a = va_arg (*args, nsh_t *); */
/*   return format (s, "SPI:%d SI:%d", clib_net_to_host_u32 (a->spi), a->si); */
/* } */

static const char *policy_strs[] = {
  "BYPASS",
  "DISCARD",
  "RESOLVE",
  "PROTECT",
};

static const char *algo_strs[] = {
  "NONE",
  "AES_CBC_128",
  "AES_CBC_192",
  "AES_CBC_256",
  "AES_CTR_128",
  "AES_CTR_192",
  "AES_CTR_256",
  "AES_GCM_128",
  "AES_GCM_192",
  "AES_GCM_256",
  "DES_CBC",
  "3DES_CBC",
};


static const char *integ_strs[] = {
  "NONE",
  "MD5_96",
  "SHA1_96",
  "SHA_256_96",
  "SHA_256_128",
  "SHA_384_192",
  "SHA_512_256",
};

static void *vl_api_ipsec_spd_entry_add_del_t_print
  (vl_api_ipsec_spd_entry_add_del_t * mp, void *handle)
{
  u8 *s;
  const char *str;
  vl_api_ipsec_spd_entry_t *ep;
  int policy_host_byte_order;

  ep = (vl_api_ipsec_spd_entry_t *) & mp->entry;

  s = format (0, "SCRIPT: ipsec_spd_entry ");
  s = format (s, "is_add %d spd_id %u priority %d is_outbound %d sa_id %u\n",
	      mp->is_add,
	      (ep->spd_id), ntohl (ep->priority), ep->is_outbound,
	      (ep->sa_id));

  policy_host_byte_order = (ep->policy);

  if (policy_host_byte_order < ARRAY_LEN (policy_strs))
    str = policy_strs[policy_host_byte_order];
  else
    str = "BOGUS!";

  s = format (s, "  policy: %s protocol %d\n", str, ep->protocol);

  s = format (s, "  remote_address_start %U remote_address_stop %U\n",
	      format_vl_api_address,
	      &ep->remote_address_start,
	      format_vl_api_address, &ep->remote_address_stop);

  s = format (s, "  local_address_start %U local_address_stop %U\n",
	      format_vl_api_address,
	      &ep->local_address_start,
	      format_vl_api_address, &ep->local_address_stop);

  s = format (s, "  remote_port_start %d remote_port_stop %d\n",
	      (ep->remote_port_start), ntohs (ep->remote_port_stop));

  s = format (s, "  local_port_start %d local_port_stop %d ",
	      (ep->local_port_start), ntohs (ep->local_port_stop));

  FINISH;
}

static void *vl_api_ipsec_interface_add_del_spd_t_print
  (vl_api_ipsec_interface_add_del_spd_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipsec_interface_add_del_spd ");
  s = format (s, "is_add %d sw_if_index %d spd_id %u ",
	      mp->is_add, (mp->sw_if_index), ntohl (mp->spd_id));
  FINISH;
}

static void *vl_api_ipsec_spd_add_del_t_print
  (vl_api_ipsec_spd_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipsec_spd_add_del ");
  s = format (s, "spd_id %u is_add %d ", (mp->spd_id), mp->is_add);
  FINISH;
}

static void *vl_api_ipsec_sad_entry_add_del_t_print
  (vl_api_ipsec_sad_entry_add_del_t * mp, void *handle)
{
  u8 *s;
  int tmp;
  vl_api_ipsec_sad_entry_t *ep;
  const char *protocol_str, *algo_str, *integ_str;

  protocol_str = "BOGUS protocol!";
  algo_str = "BOGUS crypto_algorithm!";
  integ_str = "BOGUS integrity_algorithm!";

  ep = (vl_api_ipsec_sad_entry_t *) & mp->entry;

  s = format (0, "SCRIPT: ipsec_sad_entry_add_del is_add %d ", mp->is_add);

  tmp = (ep->protocol);
  if (tmp == IPSEC_API_PROTO_ESP)
    protocol_str = "ESP";
  else if (tmp == IPSEC_API_PROTO_AH)
    protocol_str = "AH";

  tmp = (ep->crypto_algorithm);
  if (tmp < ARRAY_LEN (algo_strs))
    algo_str = algo_strs[tmp];

  tmp = (ep->integrity_algorithm);
  if (tmp < ARRAY_LEN (integ_strs))
    integ_str = integ_strs[tmp];

  s = format (s, "proto %s crypto alg %s integ alg %s\n",
	      protocol_str, algo_str, integ_str);
  s = format (s, " crypto_key len %d value %U\n",
	      ep->crypto_key.length, format_hex_bytes, ep->crypto_key.data,
	      (int) (ep->crypto_key.length));
  s = format (s, " integ_key len %d value %U\n",
	      ep->integrity_key.length, format_hex_bytes,
	      ep->integrity_key.data, (int) (ep->integrity_key.length));
  s = format (s, " flags 0x%x ", (ep->flags));

  s = format (s, "tunnel_src %U tunnel_dst %U\n",
	      format_vl_api_address,
	      &ep->tunnel_src, format_vl_api_address, &ep->tunnel_dst);
  s = format (s, " tx_table_id %u salt %u ",
	      (ep->tx_table_id), ntohl (ep->salt));
  FINISH;
}


static void *vl_api_l2_interface_pbb_tag_rewrite_t_print
  (vl_api_l2_interface_pbb_tag_rewrite_t * mp, void *handle)
{
  u8 *s;
  u32 vtr_op = (mp->vtr_op);

  s = format (0, "SCRIPT: l2_interface_pbb_tag_rewrite ");

  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "vtr_op %d ", vtr_op);
  if (vtr_op != L2_VTR_DISABLED && vtr_op != L2_VTR_POP_2)
    {
      if (vtr_op == L2_VTR_TRANSLATE_2_2)
	s = format (s, "%d ", (mp->outer_tag));
      s = format (s, "dmac %U ", format_ethernet_address, &mp->b_dmac);
      s = format (s, "smac %U ", format_ethernet_address, &mp->b_smac);
      s = format (s, "sid %d ", (mp->i_sid));
      s = format (s, "vlanid %d ", (mp->b_vlanid));
    }
  FINISH;
}

static void *vl_api_flow_classify_set_interface_t_print
  (vl_api_flow_classify_set_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: flow_classify_set_interface ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (mp->ip4_table_index != ~0)
    s = format (s, "ip4-table %d ", (mp->ip4_table_index));
  if (mp->ip6_table_index != ~0)
    s = format (s, "ip6-table %d ", (mp->ip6_table_index));
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *
vl_api_set_punt_t_print (vl_api_set_punt_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: punt ");

  switch (mp->punt.type)
    {
    case PUNT_API_TYPE_L4:
      s = format (s, "%U", format_vl_api_address_family, mp->punt.punt.l4.af);

      s = format (s, "protocol %d ", mp->punt.punt.l4.protocol);

      if (mp->punt.punt.l4.port != (u16) ~ 0)
	s = format (s, "port %d ", (mp->punt.punt.l4.port));
      break;
    default:
      break;

    }

  if (!mp->is_add)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_flow_classify_dump_t_print
  (vl_api_flow_classify_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: flow_classify_dump ");
  switch (mp->type)
    {
    case FLOW_CLASSIFY_API_TABLE_IP4:
      s = format (s, "type ip4 ");
      break;
    case FLOW_CLASSIFY_API_TABLE_IP6:
      s = format (s, "type ip6 ");
      break;
    default:
      break;
    }

  FINISH;
}

static void *vl_api_get_first_msg_id_t_print
  (vl_api_get_first_msg_id_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: get_first_msg_id %s ", mp->name);

  FINISH;
}

static void *vl_api_ioam_enable_t_print
  (vl_api_ioam_enable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ioam_enable ");

  if (mp->trace_enable)
    s = format (s, "trace enabled");

  if (mp->pot_enable)
    s = format (s, "POT enabled");

  if (mp->seqno)
    s = format (s, "Seqno enabled");

  if (mp->analyse)
    s = format (s, "Analyse enabled");

  FINISH;
}

static void *vl_api_ioam_disable_t_print
  (vl_api_ioam_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ioam_disable ");
  s = format (s, "trace disabled");
  s = format (s, "POT disabled");
  s = format (s, "Seqno disabled");
  s = format (s, "Analyse disabled");

  FINISH;
}

static void *vl_api_feature_enable_disable_t_print
  (vl_api_feature_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: feature_enable_disable ");
  s = format (s, "arc_name %s ", mp->arc_name);
  s = format (s, "feature_name %s ", mp->feature_name);
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (!mp->enable)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_feature_gso_enable_disable_t_print
  (vl_api_feature_gso_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: feature_gso_enable_disable ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  if (mp->enable_disable)
    s = format (s, "enable");
  if (!mp->enable_disable)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_sw_interface_tag_add_del_t_print
  (vl_api_sw_interface_tag_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_tag_add_del ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  if (mp->is_add)
    s = format (s, "tag %s ", mp->tag);
  else
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_hw_interface_set_mtu_t_print
  (vl_api_hw_interface_set_mtu_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_mtu ");
  s = format (s, "sw_if_index %d ", (mp->sw_if_index));
  s = format (s, "tag %d ", (mp->mtu));

  FINISH;
}

static void *vl_api_p2p_ethernet_add_t_print
  (vl_api_p2p_ethernet_add_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: p2p_ethernet_add ");
  s = format (s, "sw_if_index %d ", (mp->parent_if_index));
  s = format (s, "remote_mac %U ", format_ethernet_address, mp->remote_mac);

  FINISH;
}

static void *vl_api_p2p_ethernet_del_t_print
  (vl_api_p2p_ethernet_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: p2p_ethernet_del ");
  s = format (s, "sw_if_index %d ", (mp->parent_if_index));
  s = format (s, "remote_mac %U ", format_ethernet_address, mp->remote_mac);

  FINISH;
}

static void *vl_api_tcp_configure_src_addresses_t_print
  (vl_api_tcp_configure_src_addresses_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: tcp_configure_src_addresses ");
  s = format (s, "%U - %U ",
	      format_vl_api_address, &mp->first_address,
	      format_vl_api_address, &mp->last_address);

  if (mp->vrf_id)
    s = format (s, "vrf %d ", (mp->vrf_id));

  FINISH;
}

static void *vl_api_app_namespace_add_del_t_print
  (vl_api_app_namespace_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: app_namespace_add_del ");
  s = format (s, "ns-id %s secret %lu sw_if_index %d ipv4_fib_id %d "
	      "ipv6_fib_id %d",
	      vl_api_from_api_to_new_c_string (&mp->namespace_id),
	      mp->secret, (mp->sw_if_index), (mp->ip4_fib_id),
	      (mp->ip6_fib_id));
  FINISH;
}

static void *vl_api_session_rule_add_del_t_print
  (vl_api_session_rule_add_del_t * mp, void *handle)
{
  u8 *s;
  fib_prefix_t lcl, rmt;
  char *proto = mp->transport_proto == 0 ? "tcp" : "udp";
  s = format (0, "SCRIPT: session_rule_add_del ");
  mp->tag[sizeof (mp->tag) - 1] = 0;
  ip_prefix_decode (&mp->lcl, &lcl);
  ip_prefix_decode (&mp->rmt, &rmt);

  if (lcl.fp_proto == FIB_PROTOCOL_IP4)
    s = format (s, "appns %d scope %d %s %U/%d %d %U/%d %d action %u tag %s",
		mp->appns_index, mp->scope, proto, format_ip4_address,
		&lcl.fp_addr.ip4, lcl.fp_len,
		format_ip4_address, &rmt.fp_addr.ip4,
		rmt.fp_len, mp->action_index, mp->tag);
  else
    s = format (s, "appns %d scope %d %s %U/%d %d %U/%d %d action %u tag %s",
		mp->appns_index, mp->scope, proto, format_ip6_address,
		&lcl.fp_addr.ip6, lcl.fp_len,
		format_ip6_address, &rmt.fp_addr.ip6,
		rmt.fp_len, mp->action_index, mp->tag);
  FINISH;
}

__clib_unused
  static void *vl_api_ip_container_proxy_add_del_t_print
  (vl_api_ip_container_proxy_add_del_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: ip_container_proxy_add_del ");
  s = format (s, "is_add %d prefix %U sw_if_index %d",
	      mp->is_add, format_vl_api_prefix, mp->sw_if_index);

  FINISH;
}

static void *vl_api_qos_record_enable_disable_t_print
  (vl_api_qos_record_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: qos_record_enable_disable ");
  s = format (s, "sw_if_index %d ", (mp->record.sw_if_index));
  s = format (s, "input_source %U ", format_qos_source,
	      mp->record.input_source);

  if (!mp->enable)
    s = format (s, "disable ");

  FINISH;
}

#define foreach_no_print_function               \
_(memclnt_keepalive_reply)

#define _(f)                                    \
static void * vl_api_ ## f ## _t_print          \
  (vl_api_ ## f ## _t * mp, void * handle)      \
{                                               \
  return handle;                                \
}
foreach_no_print_function;
#undef _

#define foreach_custom_print_function                                   \
_(CREATE_LOOPBACK, create_loopback)                                     \
_(CREATE_LOOPBACK_INSTANCE, create_loopback_instance)                   \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)                       \
_(SW_INTERFACE_EVENT, sw_interface_event)                               \
_(SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address)           \
_(SW_INTERFACE_SET_TABLE, sw_interface_set_table)                       \
_(SW_INTERFACE_SET_MPLS_ENABLE, sw_interface_set_mpls_enable)           \
_(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath)                       \
_(SW_INTERFACE_SET_VXLAN_BYPASS, sw_interface_set_vxlan_bypass)         \
_(BOND_CREATE, bond_create)                                             \
_(BOND_CREATE2, bond_create2)                                           \
_(BOND_DELETE, bond_delete)                                             \
_(BOND_ADD_MEMBER, bond_add_member)                                     \
_(BOND_DETACH_MEMBER, bond_detach_member)                               \
_(SW_INTERFACE_SET_BOND_WEIGHT, sw_interface_set_bond_weight)           \
_(SW_MEMBER_INTERFACE_DUMP, sw_member_interface_dump)                   \
_(SW_BOND_INTERFACE_DUMP, sw_bond_interface_dump)                       \
_(SW_INTERFACE_RX_PLACEMENT_DUMP, sw_interface_rx_placement_dump)       \
_(TAP_CREATE_V2, tap_create_v2)                                         \
_(TAP_DELETE_V2, tap_delete_v2)                                         \
_(SW_INTERFACE_TAP_V2_DUMP, sw_interface_tap_v2_dump)                   \
_(IP_TABLE_ADD_DEL, ip_table_add_del)                                   \
_(MPLS_ROUTE_ADD_DEL, mpls_route_add_del)                               \
_(MPLS_TABLE_ADD_DEL, mpls_table_add_del)                               \
_(IP_ROUTE_ADD_DEL, ip_route_add_del)                                   \
_(MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del)		                \
_(SR_MPLS_POLICY_ADD, sr_mpls_policy_add)		                \
_(SR_MPLS_POLICY_DEL, sr_mpls_policy_del)		                \
_(SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered)             \
_(CREATE_VLAN_SUBIF, create_vlan_subif)                                 \
_(CREATE_SUBIF, create_subif)                                           \
_(IP_TABLE_REPLACE_BEGIN, ip_table_replace_begin)                       \
_(IP_TABLE_FLUSH, ip_table_flush)                                       \
_(IP_TABLE_REPLACE_END, ip_table_replace_end)                           \
_(SET_IP_FLOW_HASH, set_ip_flow_hash)                                   \
_(L2_PATCH_ADD_DEL, l2_patch_add_del)                                   \
_(SR_LOCALSID_ADD_DEL, sr_localsid_add_del)                             \
_(SR_STEERING_ADD_DEL, sr_steering_add_del)                             \
_(SR_POLICY_ADD, sr_policy_add)                                         \
_(SR_POLICY_MOD, sr_policy_mod)                                         \
_(SR_POLICY_DEL, sr_policy_del)                                         \
_(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect)           \
_(L2FIB_ADD_DEL, l2fib_add_del)                                         \
_(L2FIB_FLUSH_ALL, l2fib_flush_all)                                     \
_(L2FIB_FLUSH_BD, l2fib_flush_bd)                                       \
_(L2FIB_FLUSH_INT, l2fib_flush_int)                                     \
_(L2_FLAGS, l2_flags)                                                   \
_(BRIDGE_FLAGS, bridge_flags)                                           \
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)			\
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)			\
_(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge)		\
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)                         \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                               \
_(BRIDGE_DOMAIN_SET_MAC_AGE, bridge_domain_set_mac_age)                 \
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)	\
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)	\
_(ADD_NODE_NEXT, add_node_next)						\
_(VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel)                           \
_(VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump)                                 \
_(VXLAN_OFFLOAD_RX, vxlan_offload_rx)                                   \
_(GRE_TUNNEL_ADD_DEL, gre_tunnel_add_del)                               \
_(GRE_TUNNEL_DUMP, gre_tunnel_dump)                                     \
_(L2_FIB_CLEAR_TABLE, l2_fib_clear_table)                               \
_(L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter)                     \
_(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite)         \
_(CREATE_VHOST_USER_IF, create_vhost_user_if)				\
_(MODIFY_VHOST_USER_IF, modify_vhost_user_if)				\
_(CREATE_VHOST_USER_IF_V2, create_vhost_user_if_v2)			\
_(MODIFY_VHOST_USER_IF_V2, modify_vhost_user_if_v2)     		\
_(DELETE_VHOST_USER_IF, delete_vhost_user_if)				\
_(SW_INTERFACE_DUMP, sw_interface_dump)					\
_(CONTROL_PING, control_ping)						\
_(WANT_INTERFACE_EVENTS, want_interface_events)				\
_(CLI, cli)								\
_(CLI_INBAND, cli_inband)						\
_(MEMCLNT_CREATE, memclnt_create)					\
_(SOCKCLNT_CREATE, sockclnt_create)					\
_(SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump)           \
_(SHOW_VERSION, show_version)                                           \
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)                                 \
_(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel) 			\
_(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump)                         \
_(VXLAN_GBP_TUNNEL_ADD_DEL, vxlan_gbp_tunnel_add_del) 			\
_(VXLAN_GBP_TUNNEL_DUMP, vxlan_gbp_tunnel_dump)                         \
_(SW_INTERFACE_SET_VXLAN_GBP_BYPASS, sw_interface_set_vxlan_gbp_bypass) \
_(INTERFACE_NAME_RENUMBER, interface_name_renumber)			\
_(WANT_L2_MACS_EVENTS, want_l2_macs_events)                             \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_DUMP, ip_dump)                                                     \
_(DELETE_LOOPBACK, delete_loopback)                                     \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)					\
_(BD_IP_MAC_FLUSH, bd_ip_mac_flush)					\
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable) 		\
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)           \
_(AF_PACKET_CREATE, af_packet_create)					\
_(AF_PACKET_DELETE, af_packet_delete)					\
_(AF_PACKET_DUMP, af_packet_dump)                                       \
_(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)                   \
_(MPLS_TABLE_DUMP, mpls_table_dump)                                     \
_(MPLS_ROUTE_DUMP, mpls_route_dump)                                     \
_(MPLS_TUNNEL_DUMP, mpls_tunnel_dump)                                   \
_(CLASSIFY_TABLE_IDS,classify_table_ids)                                \
_(CLASSIFY_TABLE_BY_INTERFACE, classify_table_by_interface)             \
_(CLASSIFY_TABLE_INFO,classify_table_info)                              \
_(CLASSIFY_SESSION_DUMP,classify_session_dump)                          \
_(SET_IPFIX_EXPORTER, set_ipfix_exporter)                               \
_(IPFIX_EXPORTER_DUMP, ipfix_exporter_dump)                             \
_(SET_IPFIX_CLASSIFY_STREAM, set_ipfix_classify_stream)                 \
_(IPFIX_CLASSIFY_STREAM_DUMP, ipfix_classify_stream_dump)               \
_(IPFIX_CLASSIFY_TABLE_ADD_DEL, ipfix_classify_table_add_del)           \
_(IPFIX_CLASSIFY_TABLE_DUMP, ipfix_classify_table_dump)                 \
_(SW_INTERFACE_SPAN_ENABLE_DISABLE, sw_interface_span_enable_disable)   \
_(SW_INTERFACE_SPAN_DUMP, sw_interface_span_dump)                       \
_(GET_NEXT_INDEX, get_next_index)                                       \
_(PG_CREATE_INTERFACE,pg_create_interface)                              \
_(PG_CAPTURE, pg_capture)                                               \
_(PG_ENABLE_DISABLE, pg_enable_disable)                                 \
_(PG_INTERFACE_ENABLE_DISABLE_COALESCE, pg_interface_enable_disable_coalesce) \
_(POLICER_ADD_DEL, policer_add_del)                                     \
_(POLICER_DUMP, policer_dump)                                           \
_(POLICER_CLASSIFY_SET_INTERFACE, policer_classify_set_interface)       \
_(POLICER_CLASSIFY_DUMP, policer_classify_dump)                         \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL,                               \
  ip_source_and_port_range_check_add_del)                               \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL,                     \
  ip_source_and_port_range_check_interface_add_del)                     \
_(IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd)		\
_(IPSEC_SAD_ENTRY_ADD_DEL, ipsec_sad_entry_add_del)			\
_(IPSEC_SPD_ADD_DEL, ipsec_spd_add_del)					\
_(IPSEC_SPD_ENTRY_ADD_DEL, ipsec_spd_entry_add_del)			\
_(IPSEC_TUNNEL_IF_ADD_DEL, ipsec_tunnel_if_add_del)                     \
_(DELETE_SUBIF, delete_subif)                                           \
_(L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite)           \
_(SET_PUNT, set_punt)                                                   \
_(FLOW_CLASSIFY_SET_INTERFACE, flow_classify_set_interface)             \
_(FLOW_CLASSIFY_DUMP, flow_classify_dump)				\
_(GET_FIRST_MSG_ID, get_first_msg_id)                                   \
_(IOAM_ENABLE, ioam_enable)                                             \
_(IOAM_DISABLE, ioam_disable)                                           \
_(IP_TABLE_DUMP, ip_table_dump)                                         \
_(IP_ROUTE_DUMP, ip_route_dump)                                         \
_(FEATURE_ENABLE_DISABLE, feature_enable_disable)			\
_(FEATURE_GSO_ENABLE_DISABLE, feature_gso_enable_disable)		\
_(SW_INTERFACE_TAG_ADD_DEL, sw_interface_tag_add_del)			\
_(HW_INTERFACE_SET_MTU, hw_interface_set_mtu)                           \
_(P2P_ETHERNET_ADD, p2p_ethernet_add)                                   \
_(P2P_ETHERNET_DEL, p2p_ethernet_del)					\
_(TCP_CONFIGURE_SRC_ADDRESSES, tcp_configure_src_addresses)		\
_(APP_NAMESPACE_ADD_DEL, app_namespace_add_del)                         \
_(SESSION_RULE_ADD_DEL, session_rule_add_del)                           \
_(OUTPUT_ACL_SET_INTERFACE, output_acl_set_interface)                   \
_(QOS_RECORD_ENABLE_DISABLE, qos_record_enable_disable)			\
_(MEMCLNT_KEEPALIVE_REPLY, memclnt_keepalive_reply)

void
vl_msg_api_custom_dump_configure (api_main_t * am)
{
#define _(n,f) am->msg_print_handlers[VL_API_##n]       \
    = (void *) vl_api_##f##_t_print;
  foreach_custom_print_function;
#undef _
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
