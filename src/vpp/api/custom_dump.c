/*
 *------------------------------------------------------------------
 * custom_dump.c - pretty-print API messages for replay
 *
 * Copyright (c) 2014-2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/unix/tuntap.h>
#include <vnet/mpls/mpls.h>
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/l2tp/l2tp.h>
#include <vnet/l2/l2_input.h>
#include <vnet/srv6/sr.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/policer/xlate.h>
#include <vnet/policer/policer.h>
#include <vnet/classify/flow_classify.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/lisp-cp/lisp_types.h>

#include <vpp/stats/stats.h>
#include <vpp/oam/oam.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/l2/l2_vtr.h>

#include <vpp/api/vpe_msg_enum.h>

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
  s = format (s, "instance %d ", ntohl (mp->user_instance));

  FINISH;
}

static void *vl_api_delete_loopback_t_print
  (vl_api_delete_loopback_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_loopback ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_set_flags_t_print
  (vl_api_sw_interface_set_flags_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: sw_interface_set_flags ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->admin_up_down)
    s = format (s, "admin-up ");
  else
    s = format (s, "admin-down ");

  FINISH;
}

static void *vl_api_sw_interface_event_t_print
  (vl_api_sw_interface_event_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: sw_interface_event ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->admin_up_down)
    s = format (s, "admin-up ");
  else
    s = format (s, "admin-down ");

  if (mp->link_up_down)
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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->is_ipv6)
    s = format (s, "%U/%d ", format_ip6_address,
		(ip6_address_t *) mp->address, mp->address_length);
  else
    s = format (s, "%U/%d ", format_ip4_address,
		(ip4_address_t *) mp->address, mp->address_length);

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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  if (mp->is_ipv6)
    s = format (s, "ipv6 ");

  FINISH;
}

static void *vl_api_sw_interface_set_mpls_enable_t_print
  (vl_api_sw_interface_set_mpls_enable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_mpls_enable ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->enable == 0)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_sw_interface_set_vpath_t_print
  (vl_api_sw_interface_set_vpath_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_vpath ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

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

  s = format (s, "sw_if_index %d ", ntohl (mp->rx_sw_if_index));

  if (mp->enable)
    {
      s = format (s, "tx_sw_if_index %d ", ntohl (mp->tx_sw_if_index));
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

  s = format (s, "sw_if_index %d ", ntohl (mp->rx_sw_if_index));

  if (mp->enable)
    {
      s = format (s, "bd_id %d shg %d %senable ", ntohl (mp->bd_id),
		  mp->shg, ((mp->bvi) ? "bvi " : " "));
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

  s = format (s, "bd_id %d ", ntohl (mp->bd_id));

  if (mp->is_add)
    {
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

  s = format (s, "bd_id %d ", ntohl (mp->bd_id));

  s = format (s, "mac-age %d", mp->mac_age);

  FINISH;
}

static void *vl_api_bridge_domain_dump_t_print
  (vl_api_bridge_domain_dump_t * mp, void *handle)
{
  u8 *s;
  u32 bd_id = ntohl (mp->bd_id);

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
  u32 bd_id = ntohl (mp->bd_id);

  s = format (0, "SCRIPT: l2fib_flush_bd ");
  s = format (s, "bd_id %d ", bd_id);

  FINISH;
}

static void *vl_api_l2fib_flush_int_t_print
  (vl_api_l2fib_flush_int_t * mp, void *handle)
{
  u8 *s;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  s = format (0, "SCRIPT: l2fib_flush_int ");
  s = format (s, "sw_if_index %d ", sw_if_index);

  FINISH;
}

static void *vl_api_l2fib_add_del_t_print
  (vl_api_l2fib_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2fib_add_del ");

  s = format (s, "mac %U ", format_ethernet_address, &mp->mac);

  s = format (s, "bd_id %d ", ntohl (mp->bd_id));


  if (mp->is_add)
    {
      s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
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
  u32 flags = ntohl (mp->feature_bitmap);

  s = format (0, "SCRIPT: l2_flags ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

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
  u32 flags = ntohl (mp->feature_bitmap);

  s = format (0, "SCRIPT: bridge_flags ");

  s = format (s, "bd_id %d ", ntohl (mp->bd_id));

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

static void *vl_api_bd_ip_mac_add_del_t_print
  (vl_api_bd_ip_mac_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: bd_ip_mac_add_del ");
  s = format (s, "bd_id %d ", ntohl (mp->bd_id));

  if (mp->is_ipv6)
    s = format (s, "%U ", format_ip6_address,
		(ip6_address_t *) mp->ip_address);
  else
    s = format (s, "%U ", format_ip4_address,
		(ip4_address_t *) mp->ip_address);

  s = format (s, "%U ", format_ethernet_address, mp->mac_address);
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_tap_connect_t_print
  (vl_api_tap_connect_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: tap_connect ");
  s = format (s, "tapname %s ", mp->tap_name);
  if (mp->use_random_mac)
    s = format (s, "random-mac ");
  if (mp->tag[0])
    s = format (s, "tag %s ", mp->tag);
  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac %U ", format_ethernet_address, mp->mac_address);
  if (mp->ip4_address_set)
    s = format (s, "address %U/%d ", format_ip4_address, mp->ip4_address,
		mp->ip4_mask_width);
  if (mp->ip6_address_set)
    s = format (s, "address %U/%d ", format_ip6_address, mp->ip6_address,
		mp->ip6_mask_width);
  FINISH;
}

static void *vl_api_tap_modify_t_print
  (vl_api_tap_modify_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: tap_modify ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "tapname %s ", mp->tap_name);
  if (mp->use_random_mac)
    s = format (s, "random-mac ");

  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac %U ", format_ethernet_address, mp->mac_address);

  FINISH;
}

static void *vl_api_tap_delete_t_print
  (vl_api_tap_delete_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: tap_delete ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_tap_dump_t_print
  (vl_api_sw_interface_tap_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_tap_dump ");

  FINISH;
}


static void *vl_api_ip_add_del_route_t_print
  (vl_api_ip_add_del_route_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_add_del_route ");
  if (mp->is_add == 0)
    s = format (s, "del ");

  if (mp->next_hop_sw_if_index)
    s = format (s, "sw_if_index %d ", ntohl (mp->next_hop_sw_if_index));

  if (mp->is_ipv6)
    s = format (s, "%U/%d ", format_ip6_address, mp->dst_address,
		mp->dst_address_length);
  else
    s = format (s, "%U/%d ", format_ip4_address, mp->dst_address,
		mp->dst_address_length);
  if (mp->is_local)
    s = format (s, "local ");
  else if (mp->is_drop)
    s = format (s, "drop ");
  else if (mp->is_classify)
    s = format (s, "classify %d", ntohl (mp->classify_table_index));
  else
    {
      if (mp->is_ipv6)
	s = format (s, "via %U ", format_ip6_address, mp->next_hop_address);
      else
	s = format (s, "via %U ", format_ip4_address, mp->next_hop_address);
    }

  if (mp->table_id != 0)
    s = format (s, "vrf %d ", ntohl (mp->table_id));

  if (mp->next_hop_weight != 1)
    s = format (s, "weight %d ", mp->next_hop_weight);

  if (mp->not_last)
    s = format (s, "not-last ");

  if (mp->is_multipath)
    s = format (s, "multipath ");

  if (mp->is_multipath)
    s = format (s, "multipath ");

  if (mp->next_hop_table_id)
    s = format (s, "lookup-in-vrf %d ", ntohl (mp->next_hop_table_id));

  FINISH;
}

static void *vl_api_proxy_arp_add_del_t_print
  (vl_api_proxy_arp_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: proxy_arp_add_del ");

  s = format (s, "%U - %U ", format_ip4_address, mp->low_address,
	      format_ip4_address, mp->hi_address);

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_proxy_arp_intfc_enable_disable_t_print
  (vl_api_proxy_arp_intfc_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: proxy_arp_intfc_enable_disable ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "enable %d ", mp->enable_disable);

  FINISH;
}

static void *vl_api_mpls_tunnel_add_del_t_print
  (vl_api_mpls_tunnel_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_tunnel_add_del ");

  if (mp->mt_next_hop_sw_if_index)
    s = format (s, "sw_if_index %d ", ntohl (mp->mt_next_hop_sw_if_index));

  if (mp->mt_next_hop_proto_is_ip4)
    s = format (s, "%U ", format_ip4_address, mp->mt_next_hop);
  else
    s = format (s, "%U ", format_ip6_address, mp->mt_next_hop);

  if (mp->mt_l2_only)
    s = format (s, "l2-only ");

  if (mp->mt_is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_sw_interface_set_unnumbered_t_print
  (vl_api_sw_interface_set_unnumbered_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_unnumbered ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "unnum_if_index %d ", ntohl (mp->unnumbered_sw_if_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ip_neighbor_add_del_t_print
  (vl_api_ip_neighbor_add_del_t * mp, void *handle)
{
  u8 *s;
  u8 null_mac[6];

  memset (null_mac, 0, sizeof (null_mac));

  s = format (0, "SCRIPT: ip_neighbor_add_del ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->is_static)
    s = format (s, "is_static ");

  if (mp->is_no_adj_fib)
    s = format (s, "is_no_fib_entry ");

  if (memcmp (mp->mac_address, null_mac, 6))
    s = format (s, "mac %U ", format_ethernet_address, mp->mac_address);

  if (mp->is_ipv6)
    s =
      format (s, "dst %U ", format_ip6_address,
	      (ip6_address_t *) mp->dst_address);
  else
    s =
      format (s, "dst %U ", format_ip4_address,
	      (ip4_address_t *) mp->dst_address);

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *
vl_api_reset_vrf_t_print (vl_api_reset_vrf_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: reset_vrf ");

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  if (mp->is_ipv6 != 0)
    s = format (s, "ipv6 ");

  FINISH;
}

static void *vl_api_create_vlan_subif_t_print
  (vl_api_create_vlan_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_vlan_subif ");

  if (mp->sw_if_index)
    s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->vlan_id)
    s = format (s, "vlan_id %d ", ntohl (mp->vlan_id));

  FINISH;
}

#define foreach_create_subif_bit                \
_(no_tags)                                      \
_(one_tag)                                      \
_(two_tags)                                     \
_(dot1ad)                                       \
_(exact_match)                                  \
_(default_sub)                                  \
_(outer_vlan_id_any)                            \
_(inner_vlan_id_any)

static void *vl_api_create_subif_t_print
  (vl_api_create_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: create_subif ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "sub_id %d ", ntohl (mp->sub_id));

  if (mp->outer_vlan_id)
    s = format (s, "outer_vlan_id %d ", ntohs (mp->outer_vlan_id));

  if (mp->inner_vlan_id)
    s = format (s, "inner_vlan_id %d ", ntohs (mp->inner_vlan_id));

#define _(a) if (mp->a) s = format (s, "%s ", #a);
  foreach_create_subif_bit;
#undef _

  FINISH;
}

static void *vl_api_delete_subif_t_print
  (vl_api_delete_subif_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_subif ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_oam_add_del_t_print
  (vl_api_oam_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: oam_add_del ");

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  s = format (s, "src %U ", format_ip4_address, mp->src_address);

  s = format (s, "dst %U ", format_ip4_address, mp->dst_address);

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *
vl_api_reset_fib_t_print (vl_api_reset_fib_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: reset_fib ");

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  if (mp->is_ipv6 != 0)
    s = format (s, "ipv6 ");

  FINISH;
}

static void *vl_api_dhcp_proxy_config_t_print
  (vl_api_dhcp_proxy_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dhcp_proxy_config_2 ");

  s = format (s, "rx_vrf_id %d ", ntohl (mp->rx_vrf_id));
  s = format (s, "server_vrf_id %d ", ntohl (mp->server_vrf_id));

  if (mp->is_ipv6)
    {
      s = format (s, "svr %U ", format_ip6_address,
		  (ip6_address_t *) mp->dhcp_server);
      s = format (s, "src %U ", format_ip6_address,
		  (ip6_address_t *) mp->dhcp_src_address);
    }
  else
    {
      s = format (s, "svr %U ", format_ip4_address,
		  (ip4_address_t *) mp->dhcp_server);
      s = format (s, "src %U ", format_ip4_address,
		  (ip4_address_t *) mp->dhcp_src_address);
    }
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_dhcp_proxy_set_vss_t_print
  (vl_api_dhcp_proxy_set_vss_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dhcp_proxy_set_vss ");

  s = format (s, "tbl_id %d ", ntohl (mp->tbl_id));

  s = format (s, "fib_id %d ", ntohl (mp->fib_id));

  s = format (s, "oui %d ", ntohl (mp->oui));

  if (mp->is_ipv6 != 0)
    s = format (s, "ipv6 ");

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_dhcp_client_config_t_print
  (vl_api_dhcp_client_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: dhcp_client_config ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "hostname %s ", mp->hostname);

  s = format (s, "want_dhcp_event %d ", mp->want_dhcp_event);

  s = format (s, "pid %d ", ntohl (mp->pid));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}


static void *vl_api_set_ip_flow_hash_t_print
  (vl_api_set_ip_flow_hash_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_ip_flow_hash ");

  s = format (s, "vrf_id %d ", ntohl (mp->vrf_id));

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

static void *vl_api_sw_interface_ip6_set_link_local_address_t_print
  (vl_api_sw_interface_ip6_set_link_local_address_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_ip6_set_link_local_address ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "%U ", format_ip6_address, mp->address);

  FINISH;
}

static void *vl_api_sw_interface_ip6nd_ra_prefix_t_print
  (vl_api_sw_interface_ip6nd_ra_prefix_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_ip6nd_ra_prefix ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "%U/%d ", format_ip6_address, mp->address,
	      mp->address_length);

  s = format (s, "val_life %d ", ntohl (mp->val_lifetime));

  s = format (s, "pref_life %d ", ntohl (mp->pref_lifetime));

  if (mp->use_default)
    s = format (s, "def ");

  if (mp->no_advertise)
    s = format (s, "noadv ");

  if (mp->off_link)
    s = format (s, "offl ");

  if (mp->no_autoconfig)
    s = format (s, "noauto ");

  if (mp->no_onlink)
    s = format (s, "nolink ");

  if (mp->is_no)
    s = format (s, "isno ");

  FINISH;
}

static void *vl_api_sw_interface_ip6nd_ra_config_t_print
  (vl_api_sw_interface_ip6nd_ra_config_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_ip6nd_ra_config ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "maxint %d ", ntohl (mp->max_interval));

  s = format (s, "minint %d ", ntohl (mp->min_interval));

  s = format (s, "life %d ", ntohl (mp->lifetime));

  s = format (s, "count %d ", ntohl (mp->initial_count));

  s = format (s, "interval %d ", ntohl (mp->initial_interval));

  if (mp->suppress)
    s = format (s, "suppress ");

  if (mp->managed)
    s = format (s, "managed ");

  if (mp->other)
    s = format (s, "other ");

  if (mp->ll_option)
    s = format (s, "ll ");

  if (mp->send_unicast)
    s = format (s, "send ");

  if (mp->cease)
    s = format (s, "cease ");

  if (mp->is_no)
    s = format (s, "isno ");

  if (mp->default_router)
    s = format (s, "def ");

  FINISH;
}

static void *vl_api_set_arp_neighbor_limit_t_print
  (vl_api_set_arp_neighbor_limit_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_arp_neighbor_limit ");

  s = format (s, "arp_nbr_limit %d ", ntohl (mp->arp_neighbor_limit));

  if (mp->is_ipv6 != 0)
    s = format (s, "ipv6 ");

  FINISH;
}

static void *vl_api_l2_patch_add_del_t_print
  (vl_api_l2_patch_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_patch_add_del ");

  s = format (s, "rx_sw_if_index %d ", ntohl (mp->rx_sw_if_index));

  s = format (s, "tx_sw_if_index %d ", ntohl (mp->tx_sw_if_index));

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
		  format_ip6_address, (ip6_address_t *) mp->localsid_addr);
      s = format (s, (mp->end_psp ? "End.PSP: True" : "End.PSP: False"));
      break;
    case SR_BEHAVIOR_X:
      s =
	format (s,
		"Address: %U\nBehavior: X (Endpoint with Layer-3 cross-connect)"
		"\nIface: %U\nNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr,
		format_vnet_sw_if_index_name, vnm, ntohl (mp->sw_if_index),
		format_ip6_address, (ip6_address_t *) mp->nh_addr);
      s = format (s, (mp->end_psp ? "End.PSP: True" : "End.PSP: False"));
      break;
    case SR_BEHAVIOR_DX4:
      s =
	format (s,
		"Address: %U\nBehavior: DX4 (Endpoint with decapsulation with IPv4 cross-connect)"
		"\nIface: %U\nNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr,
		format_vnet_sw_if_index_name, vnm, ntohl (mp->sw_if_index),
		format_ip4_address, (ip4_address_t *) mp->nh_addr);
      break;
    case SR_BEHAVIOR_DX6:
      s =
	format (s,
		"Address: %U\nBehavior: DX6 (Endpoint with decapsulation with IPv6 cross-connect)"
		"\nIface: %UNext hop: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr,
		format_vnet_sw_if_index_name, vnm, ntohl (mp->sw_if_index),
		format_ip6_address, (ip6_address_t *) mp->nh_addr);
      break;
    case SR_BEHAVIOR_DX2:
      s =
	format (s,
		"Address: %U\nBehavior: DX2 (Endpoint with decapulation and Layer-2 cross-connect)"
		"\nIface: %U", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr,
		format_vnet_sw_if_index_name, vnm, ntohl (mp->sw_if_index));
      break;
    case SR_BEHAVIOR_DT6:
      s =
	format (s,
		"Address: %U\nBehavior: DT6 (Endpoint with decapsulation and specific IPv6 table lookup)"
		"\nTable: %u", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr, ntohl (mp->fib_table));
      break;
    case SR_BEHAVIOR_DT4:
      s =
	format (s,
		"Address: %U\nBehavior: DT4 (Endpoint with decapsulation and specific IPv4 table lookup)"
		"\nTable: %u", format_ip6_address,
		(ip6_address_t *) mp->localsid_addr, ntohl (mp->fib_table));
      break;
    default:
      if (mp->behavior >= SR_BEHAVIOR_LAST)
	{
	  s = format (s, "Address: %U\n Behavior: %u",
		      format_ip6_address, (ip6_address_t *) mp->localsid_addr,
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
      s = format (s, "Traffic type: L2 iface: %u", ntohl (mp->sw_if_index));
      break;
    case SR_STEER_IPV4:
      s = format (s, "Traffic type: IPv4 %U/%u", format_ip4_address,
		  (ip4_address_t *) mp->prefix_addr, ntohl (mp->mask_width));
      break;
    case SR_STEER_IPV6:
      s = format (s, "Traffic type: IPv6 %U/%u", format_ip6_address,
		  (ip6_address_t *) mp->prefix_addr, ntohl (mp->mask_width));
      break;
    default:
      s = format (s, "Traffic type: Unknown(%u)", mp->traffic_type);
      break;
    }
  s = format (s, "BindingSID: %U", format_ip6_address,
	      (ip6_address_t *) mp->bsid_addr);

  s = format (s, "SR Policy Index: %u", ntohl (mp->sr_policy_index));

  s = format (s, "FIB_table: %u", ntohl (mp->table_id));

  FINISH;
}

static void *vl_api_sr_policy_add_t_print
  (vl_api_sr_policy_add_t * mp, void *handle)
{
  u8 *s;

  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->segments;

  int i;
  for (i = 0; i < mp->n_segments; i++)
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

  s = format (s, "FIB_table: %u", ntohl (mp->fib_table));

  s = format (s, (mp->type ? "Type: Default" : "Type: Spray"));

  s = format (s, "SID list weight: %u", ntohl (mp->weight));

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
  ip6_address_t *this_address = (ip6_address_t *) mp->segments;

  int i;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  s = format (0, "SCRIPT: sr_policy_mod ");

  s = format (s, "BSID: %U", format_ip6_address,
	      (ip6_address_t *) mp->bsid_addr);

  s = format (s, "SR Policy index: %u", ntohl (mp->sr_policy_index));

  s = format (s, "Operation: %u", mp->operation);

  s = format (s, "SID list index: %u", ntohl (mp->sl_index));

  s = format (s, "SID list weight: %u", ntohl (mp->weight));

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
      s = format (s, "table %d ", ntohl (mp->table_index));
      s = format (s, "%s ", mp->del_chain ? "del-chain" : "del");
    }
  else
    {
      s = format (s, "nbuckets %d ", ntohl (mp->nbuckets));
      s = format (s, "memory_size %d ", ntohl (mp->memory_size));
      s = format (s, "skip %d ", ntohl (mp->skip_n_vectors));
      s = format (s, "match %d ", ntohl (mp->match_n_vectors));
      s = format (s, "next-table %d ", ntohl (mp->next_table_index));
      s = format (s, "miss-next %d ", ntohl (mp->miss_next_index));
      s = format (s, "current-data-flag %d ", ntohl (mp->current_data_flag));
      if (mp->current_data_flag)
	s = format (s, "current-data-offset %d ",
		    ntohl (mp->current_data_offset));
      s = format (s, "mask hex ");
      for (i = 0; i < ntohl (mp->match_n_vectors) * sizeof (u32x4); i++)
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

  s = format (s, "table_index %d ", ntohl (mp->table_index));
  s = format (s, "hit_next_index %d ", ntohl (mp->hit_next_index));
  s = format (s, "opaque_index %d ", ntohl (mp->opaque_index));
  s = format (s, "advance %d ", ntohl (mp->advance));
  s = format (s, "action %d ", mp->action);
  if (mp->action)
    s = format (s, "metadata %d ", ntohl (mp->metadata));
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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "table %d ", ntohl (mp->table_index));

  FINISH;
}

static void *vl_api_classify_set_interface_l2_tables_t_print
  (vl_api_classify_set_interface_l2_tables_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_set_interface_l2_tables ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "ip4-table %d ", ntohl (mp->ip4_table_index));
  s = format (s, "ip6-table %d ", ntohl (mp->ip6_table_index));
  s = format (s, "other-table %d ", ntohl (mp->other_table_index));
  s = format (s, "is-input %d ", mp->is_input);

  FINISH;
}

static void *vl_api_add_node_next_t_print
  (vl_api_add_node_next_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: add_node_next ");

  s = format (0, "node %s next %s ", mp->node_name, mp->next_name);

  FINISH;
}

static void *vl_api_l2tpv3_create_tunnel_t_print
  (vl_api_l2tpv3_create_tunnel_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2tpv3_create_tunnel ");

  s = format (s, "client_address %U our_address %U ",
	      format_ip6_address, (ip6_address_t *) (mp->client_address),
	      format_ip6_address, (ip6_address_t *) (mp->our_address));
  s = format (s, "local_session_id %d ", ntohl (mp->local_session_id));
  s = format (s, "remote_session_id %d ", ntohl (mp->remote_session_id));
  s = format (s, "local_cookie %lld ",
	      clib_net_to_host_u64 (mp->local_cookie));
  s = format (s, "remote_cookie %lld ",
	      clib_net_to_host_u64 (mp->remote_cookie));
  if (mp->l2_sublayer_present)
    s = format (s, "l2-sublayer-present ");

  FINISH;
}

static void *vl_api_l2tpv3_set_tunnel_cookies_t_print
  (vl_api_l2tpv3_set_tunnel_cookies_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2tpv3_set_tunnel_cookies ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "new_local_cookie %llu ",
	      clib_net_to_host_u64 (mp->new_local_cookie));

  s = format (s, "new_remote_cookie %llu ",
	      clib_net_to_host_u64 (mp->new_remote_cookie));

  FINISH;
}

static void *vl_api_l2tpv3_interface_enable_disable_t_print
  (vl_api_l2tpv3_interface_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2tpv3_interface_enable_disable ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->enable_disable == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_l2tpv3_set_lookup_key_t_print
  (vl_api_l2tpv3_set_lookup_key_t * mp, void *handle)
{
  u8 *s;
  char *str = "unknown";

  s = format (0, "SCRIPT: l2tpv3_set_lookup_key ");

  switch (mp->key)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      str = "lookup_v6_src";
      break;
    case L2T_LOOKUP_DST_ADDRESS:
      str = "lookup_v6_dst";
      break;
    case L2T_LOOKUP_SESSION_ID:
      str = "lookup_session_id";
      break;
    default:
      break;
    }

  s = format (s, "%s ", str);

  FINISH;
}

static void *vl_api_sw_if_l2tpv3_tunnel_dump_t_print
  (vl_api_sw_if_l2tpv3_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_if_l2tpv3_tunnel_dump ");

  FINISH;
}

static void *vl_api_vxlan_add_del_tunnel_t_print
  (vl_api_vxlan_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;
  s = format (0, "SCRIPT: vxlan_add_del_tunnel ");

  ip46_address_t src = to_ip46 (mp->is_ipv6, mp->src_address);
  ip46_address_t dst = to_ip46 (mp->is_ipv6, mp->dst_address);

  u8 is_grp = ip46_address_is_multicast (&dst);
  char *dst_name = is_grp ? "group" : "dst";

  s = format (s, "src %U ", format_ip46_address, &src, IP46_TYPE_ANY);
  s = format (s, "%s %U ", dst_name, format_ip46_address,
	      &dst, IP46_TYPE_ANY);

  if (is_grp)
    s = format (s, "mcast_sw_if_index %d ", ntohl (mp->mcast_sw_if_index));

  if (mp->encap_vrf_id)
    s = format (s, "encap-vrf-id %d ", ntohl (mp->encap_vrf_id));

  s = format (s, "decap-next %d ", ntohl (mp->decap_next_index));

  s = format (s, "vni %d ", ntohl (mp->vni));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_vxlan_tunnel_dump_t_print
  (vl_api_vxlan_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_tunnel_dump ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_gre_add_del_tunnel_t_print
  (vl_api_gre_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gre_add_del_tunnel ");

  s = format (s, "dst %U ", format_ip46_address,
	      (ip46_address_t *) & (mp->dst_address),
	      mp->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4);

  s = format (s, "src %U ", format_ip46_address,
	      (ip46_address_t *) & (mp->src_address),
	      mp->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4);

  if (mp->teb)
    s = format (s, "teb ");

  if (mp->outer_fib_id)
    s = format (s, "outer-fib-id %d ", ntohl (mp->outer_fib_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_gre_tunnel_dump_t_print
  (vl_api_gre_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gre_tunnel_dump ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "vtr_op %d ", ntohl (mp->vtr_op));
  s = format (s, "push_dot1q %d ", ntohl (mp->push_dot1q));
  s = format (s, "tag1 %d ", ntohl (mp->tag1));
  s = format (s, "tag2 %d ", ntohl (mp->tag2));

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
    s = format (s, "renumber %d ", ntohl (mp->custom_dev_instance));
  if (mp->tag[0])
    s = format (s, "tag %s", mp->tag);

  FINISH;
}

static void *vl_api_modify_vhost_user_if_t_print
  (vl_api_modify_vhost_user_if_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: modify_vhost_user_if ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "socket %s ", mp->sock_filename);
  if (mp->is_server)
    s = format (s, "server ");
  if (mp->renumber)
    s = format (s, "renumber %d ", ntohl (mp->custom_dev_instance));

  FINISH;
}

static void *vl_api_delete_vhost_user_if_t_print
  (vl_api_delete_vhost_user_if_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: delete_vhost_user_if ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_sw_interface_vhost_user_dump_t_print
  (vl_api_sw_interface_vhost_user_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_vhost_user_dump ");

  FINISH;
}

static void *vl_api_sw_interface_dump_t_print
  (vl_api_sw_interface_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_dump ");

  if (mp->name_filter_valid)
    s = format (s, "name_filter %s ", mp->name_filter);
  else
    s = format (s, "all ");

  FINISH;
}

static void *vl_api_l2_fib_table_dump_t_print
  (vl_api_l2_fib_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: l2_fib_table_dump ");

  s = format (s, "bd_id %d ", ntohl (mp->bd_id));

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
	      ntohl (mp->pid), ntohl (mp->enable_disable));

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

  s = format (0, "SCRIPT: cli_inband ");

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

static void *vl_api_vxlan_gpe_add_del_tunnel_t_print
  (vl_api_vxlan_gpe_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_gpe_add_del_tunnel ");

  ip46_address_t local = to_ip46 (mp->is_ipv6, mp->local);
  ip46_address_t remote = to_ip46 (mp->is_ipv6, mp->remote);

  u8 is_grp = ip46_address_is_multicast (&remote);
  char *remote_name = is_grp ? "group" : "remote";

  s = format (s, "local %U ", format_ip46_address, &local, IP46_TYPE_ANY);
  s = format (s, "%s %U ", remote_name, format_ip46_address,
	      &remote, IP46_TYPE_ANY);

  if (is_grp)
    s = format (s, "mcast_sw_if_index %d ", ntohl (mp->mcast_sw_if_index));
  s = format (s, "protocol %d ", ntohl (mp->protocol));

  s = format (s, "vni %d ", ntohl (mp->vni));

  if (mp->is_add == 0)
    s = format (s, "del ");

  if (mp->encap_vrf_id)
    s = format (s, "encap-vrf-id %d ", ntohl (mp->encap_vrf_id));

  if (mp->decap_vrf_id)
    s = format (s, "decap-vrf-id %d ", ntohl (mp->decap_vrf_id));

  FINISH;
}

static void *vl_api_vxlan_gpe_tunnel_dump_t_print
  (vl_api_vxlan_gpe_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: vxlan_gpe_tunnel_dump ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_interface_name_renumber_t_print
  (vl_api_interface_name_renumber_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: interface_renumber ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  s = format (s, "new_show_dev_instance %d ",
	      ntohl (mp->new_show_dev_instance));

  FINISH;
}

static void *vl_api_want_ip4_arp_events_t_print
  (vl_api_want_ip4_arp_events_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: want_ip4_arp_events ");
  s = format (s, "pid %d address %U ", ntohl (mp->pid),
	      format_ip4_address, &mp->address);
  if (mp->enable_disable == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_want_ip6_nd_events_t_print
  (vl_api_want_ip6_nd_events_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: want_ip6_nd_events ");
  s = format (s, "pid %d address %U ", ntohl (mp->pid),
	      format_ip6_address, mp->address);
  if (mp->enable_disable == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_want_l2_macs_events_t_print
  (vl_api_want_l2_macs_events_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: want_l2_macs_events ");
  s = format (s, "learn-limit %d ", ntohl (mp->learn_limit));
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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "ip4-table %d ", ntohl (mp->ip4_table_index));
  s = format (s, "ip6-table %d ", ntohl (mp->ip6_table_index));
  s = format (s, "l2-table %d ", ntohl (mp->l2_table_index));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ip_address_dump_t_print
  (vl_api_ip_address_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip6_address_dump ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
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
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
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
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "fib-id %d ", ntohl (mp->fib_id));
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
	      mp->conform_action_type, mp->conform_dscp);
  s = format (s, "exceed_action %U ", format_policer_action,
	      mp->exceed_action_type, mp->exceed_dscp);
  s = format (s, "violate_action %U ", format_policer_action,
	      mp->violate_action_type, mp->violate_dscp);

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
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  if (mp->ip4_table_index != ~0)
    s = format (s, "ip4-table %d ", ntohl (mp->ip4_table_index));
  if (mp->ip6_table_index != ~0)
    s = format (s, "ip6-table %d ", ntohl (mp->ip6_table_index));
  if (mp->l2_table_index != ~0)
    s = format (s, "l2-table %d ", ntohl (mp->l2_table_index));
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
    case POLICER_CLASSIFY_TABLE_IP4:
      s = format (s, "type ip4 ");
      break;
    case POLICER_CLASSIFY_TABLE_IP6:
      s = format (s, "type ip6 ");
      break;
    case POLICER_CLASSIFY_TABLE_L2:
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
    s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_mpls_tunnel_dump_t_print
  (vl_api_mpls_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_tunnel_dump ");

  s = format (s, "tunnel_index %d ", ntohl (mp->tunnel_index));

  FINISH;
}

static void *vl_api_mpls_fib_dump_t_print
  (vl_api_mpls_fib_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: mpls_fib_decap_dump ");

  FINISH;
}

static void *vl_api_ip_fib_dump_t_print
  (vl_api_ip_fib_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip_fib_dump ");

  FINISH;
}

static void *vl_api_ip6_fib_dump_t_print
  (vl_api_ip6_fib_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ip6_fib_dump ");

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
    s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_classify_table_info_t_print
  (vl_api_classify_table_info_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_table_info ");
  if (mp->table_id != ~0)
    s = format (s, "table_id %d ", ntohl (mp->table_id));

  FINISH;
}

static void *vl_api_classify_session_dump_t_print
  (vl_api_classify_session_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: classify_session_dump ");
  if (mp->table_id != ~0)
    s = format (s, "table_id %d ", ntohl (mp->table_id));

  FINISH;
}

static void *vl_api_set_ipfix_exporter_t_print
  (vl_api_set_ipfix_exporter_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: set_ipfix_exporter ");

  s = format (s, "collector-address %U ", format_ip4_address,
	      (ip4_address_t *) mp->collector_address);
  s = format (s, "collector-port %d ", ntohs (mp->collector_port));
  s = format (s, "src-address %U ", format_ip4_address,
	      (ip4_address_t *) mp->src_address);
  s = format (s, "vrf-id %d ", ntohl (mp->vrf_id));
  s = format (s, "path-mtu %d ", ntohl (mp->path_mtu));
  s = format (s, "template-interval %d ", ntohl (mp->template_interval));
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

  s = format (s, "domain-id %d ", ntohl (mp->domain_id));
  s = format (s, "src-port %d ", ntohs (mp->src_port));

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

  s = format (s, "table-id %d ", ntohl (mp->table_id));
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
  s = format (s, "src_sw_if_index %u ", ntohl (mp->sw_if_index_from));
  s = format (s, "dst_sw_if_index %u ", ntohl (mp->sw_if_index_to));

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
  s = format (0, "if_id %d", ntohl (mp->interface_id));

  FINISH;
}

static void *vl_api_pg_capture_t_print
  (vl_api_pg_capture_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_capture ");
  s = format (0, "if_id %d ", ntohl (mp->interface_id));
  s = format (0, "pcap %s", mp->pcap_file_name);
  if (mp->count != ~0)
    s = format (s, "count %d ", ntohl (mp->count));
  if (!mp->is_enabled)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_pg_enable_disable_t_print
  (vl_api_pg_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: pg_enable_disable ");
  if (ntohl (mp->stream_name_length) > 0)
    s = format (s, "stream %s", mp->stream_name);
  if (!mp->is_enabled)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_ip_source_and_port_range_check_add_del_t_print
  (vl_api_ip_source_and_port_range_check_add_del_t * mp, void *handle)
{
  u8 *s;
  int i;

  s = format (0, "SCRIPT: ip_source_and_port_range_check_add_del ");
  if (mp->is_ipv6)
    s = format (s, "%U/%d ", format_ip6_address, mp->address,
		mp->mask_length);
  else
    s = format (s, "%U/%d ", format_ip4_address, mp->address,
		mp->mask_length);

  for (i = 0; i < mp->number_of_ranges; i++)
    {
      s = format (s, "range %d - %d ", mp->low_ports[i], mp->high_ports[i]);
    }

  s = format (s, "vrf %d ", ntohl (mp->vrf_id));

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

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  if (mp->tcp_out_vrf_id != ~0)
    s = format (s, "tcp-out-vrf %d ", ntohl (mp->tcp_out_vrf_id));

  if (mp->udp_out_vrf_id != ~0)
    s = format (s, "udp-out-vrf %d ", ntohl (mp->udp_out_vrf_id));

  if (mp->tcp_in_vrf_id != ~0)
    s = format (s, "tcp-in-vrf %d ", ntohl (mp->tcp_in_vrf_id));

  if (mp->udp_in_vrf_id != ~0)
    s = format (s, "udp-in-vrf %d ", ntohl (mp->udp_in_vrf_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_lisp_enable_disable_t_print
  (vl_api_lisp_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_enable_disable %s",
	      mp->is_en ? "enable" : "disable");

  FINISH;
}

static void *vl_api_gpe_add_del_iface_t_print
  (vl_api_gpe_add_del_iface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gpe_add_del_iface ");

  s = format (s, "%s ", mp->is_add ? "up" : "down");
  s = format (s, "vni %d ", mp->vni);
  s = format (s, "%s %d ", mp->is_l2 ? "bd_id" : "table_id", mp->dp_table);

  FINISH;
}

static void *vl_api_lisp_pitr_set_locator_set_t_print
  (vl_api_lisp_pitr_set_locator_set_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_pitr_set_locator_set ");

  if (mp->is_add)
    s = format (s, "locator-set %s ", mp->ls_name);
  else
    s = format (s, "del");

  FINISH;
}

static u8 *
format_lisp_flat_eid (u8 * s, va_list * args)
{
  u32 type = va_arg (*args, u32);
  u8 *eid = va_arg (*args, u8 *);
  u32 eid_len = va_arg (*args, u32);

  switch (type)
    {
    case 0:
      return format (s, "%U/%d", format_ip4_address, eid, eid_len);
    case 1:
      return format (s, "%U/%d", format_ip6_address, eid, eid_len);
    case 3:
      return format (s, "%U", format_ethernet_address, eid);
    }
  return 0;
}

static void *vl_api_lisp_add_del_remote_mapping_t_print
  (vl_api_lisp_add_del_remote_mapping_t * mp, void *handle)
{
  u8 *s;
  u32 rloc_num = 0;

  s = format (0, "SCRIPT: lisp_add_del_remote_mapping ");

  if (mp->del_all)
    s = format (s, "del-all ");

  s = format (s, "%s ", mp->is_add ? "add" : "del");
  s = format (s, "vni %d ", clib_net_to_host_u32 (mp->vni));

  s = format (s, "eid %U ", format_lisp_flat_eid,
	      mp->eid_type, mp->eid, mp->eid_len);

  if (mp->is_src_dst)
    {
      s = format (s, "seid %U ", format_lisp_flat_eid,
		  mp->eid_type, mp->seid, mp->seid_len);
    }

  rloc_num = clib_net_to_host_u32 (mp->rloc_num);

  if (0 == rloc_num)
    s = format (s, "action %d", mp->action);

  FINISH;
}

static void *vl_api_lisp_add_del_adjacency_t_print
  (vl_api_lisp_add_del_adjacency_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_adjacency ");

  s = format (s, "%s ", mp->is_add ? "add" : "del");
  s = format (s, "vni %d ", clib_net_to_host_u32 (mp->vni));
  s = format (s, "reid %U leid %U ",
	      format_lisp_flat_eid, mp->eid_type, mp->reid, mp->reid_len,
	      format_lisp_flat_eid, mp->eid_type, mp->leid, mp->leid_len);

  FINISH;
}

static void *vl_api_lisp_add_del_map_request_itr_rlocs_t_print
  (vl_api_lisp_add_del_map_request_itr_rlocs_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_map_request_itr_rlocs ");

  if (mp->is_add)
    s = format (s, "%s", mp->locator_set_name);
  else
    s = format (s, "del");

  FINISH;
}

static void *vl_api_lisp_eid_table_add_del_map_t_print
  (vl_api_lisp_eid_table_add_del_map_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_eid_table_add_del_map ");

  if (!mp->is_add)
    s = format (s, "del ");

  s = format (s, "vni %d ", clib_net_to_host_u32 (mp->vni));
  s = format (s, "%s %d ",
	      mp->is_l2 ? "bd_index" : "vrf",
	      clib_net_to_host_u32 (mp->dp_table));
  FINISH;
}

static void *vl_api_lisp_add_del_local_eid_t_print
  (vl_api_lisp_add_del_local_eid_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_local_eid ");

  if (!mp->is_add)
    s = format (s, "del ");

  s = format (s, "vni %d ", clib_net_to_host_u32 (mp->vni));
  s = format (s, "eid %U ", format_lisp_flat_eid, mp->eid_type, mp->eid,
	      mp->prefix_len);
  s = format (s, "locator-set %s ", mp->locator_set_name);
  if (*mp->key)
    {
      u32 key_id = mp->key_id;
      s = format (s, "key-id %U", format_hmac_key_id, key_id);
      s = format (s, "secret-key %s", mp->key);
    }
  FINISH;
}

static void *vl_api_gpe_add_del_fwd_entry_t_print
  (vl_api_gpe_add_del_fwd_entry_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gpe_add_del_fwd_entry TODO");

  FINISH;
}

static void *vl_api_lisp_add_del_map_resolver_t_print
  (vl_api_lisp_add_del_map_resolver_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_map_resolver ");

  if (!mp->is_add)
    s = format (s, "del ");

  if (mp->is_ipv6)
    s = format (s, "%U ", format_ip6_address, mp->ip_address);
  else
    s = format (s, "%U ", format_ip4_address, mp->ip_address);

  FINISH;
}

static void *vl_api_gpe_enable_disable_t_print
  (vl_api_gpe_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: gpe_enable_disable ");

  s = format (s, "%s ", mp->is_en ? "enable" : "disable");

  FINISH;
}

static void *vl_api_lisp_add_del_locator_set_t_print
  (vl_api_lisp_add_del_locator_set_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_locator_set ");

  if (!mp->is_add)
    s = format (s, "del ");

  s = format (s, "locator-set %s ", mp->locator_set_name);

  FINISH;
}

static void *vl_api_lisp_add_del_locator_t_print
  (vl_api_lisp_add_del_locator_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_add_del_locator ");

  if (!mp->is_add)
    s = format (s, "del ");

  s = format (s, "locator-set %s ", mp->locator_set_name);
  s = format (s, "sw_if_index %d ", mp->sw_if_index);
  s = format (s, "p %d w %d ", mp->priority, mp->weight);

  FINISH;
}

static void *vl_api_lisp_locator_set_dump_t_print
  (vl_api_lisp_locator_set_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_locator_set_dump ");
  if (mp->filter == 1)
    s = format (s, "local");
  else if (mp->filter == 2)
    s = format (s, "remote");

  FINISH;
}

static void *vl_api_lisp_locator_dump_t_print
  (vl_api_lisp_locator_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_locator_dump ");
  if (mp->is_index_set)
    s = format (s, "ls_index %d", clib_net_to_host_u32 (mp->ls_index));
  else
    s = format (s, "ls_name %s", mp->ls_name);

  FINISH;
}

static void *vl_api_lisp_map_request_mode_t_print
  (vl_api_lisp_map_request_mode_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_map_request_mode ");

  switch (mp->mode)
    {
    case 0:
      s = format (s, "dst-only");
      break;
    case 1:
      s = format (s, "src-dst");
    default:
      break;
    }

  FINISH;
}

static void *vl_api_lisp_eid_table_dump_t_print
  (vl_api_lisp_eid_table_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_eid_table_dump ");

  if (mp->eid_set)
    {
      s = format (s, "vni %d ", clib_net_to_host_u32 (mp->vni));
      s = format (s, "eid %U ", format_lisp_flat_eid, mp->eid_type,
		  mp->eid, mp->prefix_length);
      switch (mp->filter)
	{
	case 1:
	  s = format (s, "local ");
	  break;
	case 2:
	  s = format (s, "remote ");
	  break;
	}
    }

  FINISH;
}

static void *vl_api_lisp_rloc_probe_enable_disable_t_print
  (vl_api_lisp_rloc_probe_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_rloc_probe_enable_disable ");
  if (mp->is_enabled)
    s = format (s, "enable");
  else
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_lisp_map_register_enable_disable_t_print
  (vl_api_lisp_map_register_enable_disable_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_map_register_enable_disable ");
  if (mp->is_enabled)
    s = format (s, "enable");
  else
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_lisp_adjacencies_get_t_print
  (vl_api_lisp_adjacencies_get_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_adjacencies_get ");
  s = format (s, "vni %d", clib_net_to_host_u32 (mp->vni));

  FINISH;
}

static void *vl_api_lisp_eid_table_map_dump_t_print
  (vl_api_lisp_eid_table_map_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: lisp_eid_table_map_dump ");

  if (mp->is_l2)
    s = format (s, "l2");
  else
    s = format (s, "l3");

  FINISH;
}

static void *vl_api_ipsec_gre_add_del_tunnel_t_print
  (vl_api_ipsec_gre_add_del_tunnel_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipsec_gre_add_del_tunnel ");

  s = format (s, "dst %U ", format_ip4_address,
	      (ip4_address_t *) & (mp->dst_address));

  s = format (s, "src %U ", format_ip4_address,
	      (ip4_address_t *) & (mp->src_address));

  s = format (s, "local_sa %d ", ntohl (mp->local_sa_id));

  s = format (s, "remote_sa %d ", ntohl (mp->remote_sa_id));

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_ipsec_gre_tunnel_dump_t_print
  (vl_api_ipsec_gre_tunnel_dump_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: ipsec_gre_tunnel_dump ");

  if (mp->sw_if_index != ~0)
    s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));

  FINISH;
}

static void *vl_api_l2_interface_pbb_tag_rewrite_t_print
  (vl_api_l2_interface_pbb_tag_rewrite_t * mp, void *handle)
{
  u8 *s;
  u32 vtr_op = ntohl (mp->vtr_op);

  s = format (0, "SCRIPT: l2_interface_pbb_tag_rewrite ");

  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "vtr_op %d ", vtr_op);
  if (vtr_op != L2_VTR_DISABLED && vtr_op != L2_VTR_POP_2)
    {
      if (vtr_op == L2_VTR_TRANSLATE_2_2)
	s = format (s, "%d ", ntohs (mp->outer_tag));
      s = format (s, "dmac %U ", format_ethernet_address, &mp->b_dmac);
      s = format (s, "smac %U ", format_ethernet_address, &mp->b_smac);
      s = format (s, "sid %d ", ntohl (mp->i_sid));
      s = format (s, "vlanid %d ", ntohs (mp->b_vlanid));
    }

  FINISH;
}

static void *vl_api_flow_classify_set_interface_t_print
  (vl_api_flow_classify_set_interface_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: flow_classify_set_interface ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  if (mp->ip4_table_index != ~0)
    s = format (s, "ip4-table %d ", ntohl (mp->ip4_table_index));
  if (mp->ip6_table_index != ~0)
    s = format (s, "ip6-table %d ", ntohl (mp->ip6_table_index));
  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *
vl_api_punt_t_print (vl_api_punt_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: punt ");

  if (mp->ipv != (u8) ~ 0)
    s = format (s, "ip %d ", mp->ipv);

  s = format (s, "protocol %d ", mp->l4_protocol);

  if (mp->l4_port != (u16) ~ 0)
    s = format (s, "port %d ", ntohs (mp->l4_port));

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
    case FLOW_CLASSIFY_TABLE_IP4:
      s = format (s, "type ip4 ");
      break;
    case FLOW_CLASSIFY_TABLE_IP6:
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
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  if (!mp->enable)
    s = format (s, "disable");

  FINISH;
}

static void *vl_api_sw_interface_tag_add_del_t_print
  (vl_api_sw_interface_tag_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_tag_add_del ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  if (mp->is_add)
    s = format (s, "tag %s ", mp->tag);
  else
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_sw_interface_set_mtu_t_print
  (vl_api_sw_interface_set_mtu_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_mtu ");
  s = format (s, "sw_if_index %d ", ntohl (mp->sw_if_index));
  s = format (s, "tag %d ", ntohs (mp->mtu));

  FINISH;
}

static void *vl_api_p2p_ethernet_add_t_print
  (vl_api_p2p_ethernet_add_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: p2p_ethernet_add ");
  s = format (s, "sw_if_index %d ", ntohl (mp->parent_if_index));
  s = format (s, "remote_mac %U ", format_ethernet_address, mp->remote_mac);

  FINISH;
}

static void *vl_api_p2p_ethernet_del_t_print
  (vl_api_p2p_ethernet_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: p2p_ethernet_del ");
  s = format (s, "sw_if_index %d ", ntohl (mp->parent_if_index));
  s = format (s, "remote_mac %U ", format_ethernet_address, mp->remote_mac);

  FINISH;
}

static void *vl_api_tcp_configure_src_addresses_t_print
  (vl_api_tcp_configure_src_addresses_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: tcp_configure_src_addresses ");
  if (mp->is_ipv6)
    s = format (s, "%U - %U ",
		format_ip6_address, (ip6_address_t *) mp->first_address,
		format_ip6_address, (ip6_address_t *) mp->last_address);
  else
    s = format (s, "%U - %U ",
		format_ip4_address, (ip4_address_t *) mp->first_address,
		format_ip4_address, (ip4_address_t *) mp->last_address);

  if (mp->vrf_id)
    s = format (s, "vrf %d ", ntohl (mp->vrf_id));

  FINISH;
}

#define foreach_custom_print_no_arg_function                            \
_(lisp_eid_table_vni_dump)                                              \
_(lisp_map_resolver_dump)                                               \
_(lisp_map_server_dump)                                                 \
_(show_lisp_rloc_probe_state)                                           \
_(show_lisp_map_register_state)                                         \
_(show_lisp_map_request_mode)

#define _(f)                                                            \
static void * vl_api_ ## f ## _t_print                                  \
  (vl_api_ ## f ## _t * mp, void * handle)                              \
{                                                                       \
  u8 * s;                                                               \
  s = format (0, "SCRIPT: " #f );                                       \
  FINISH;                                                               \
}
foreach_custom_print_no_arg_function
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
_(TAP_CONNECT, tap_connect)                                             \
_(TAP_MODIFY, tap_modify)                                               \
_(TAP_DELETE, tap_delete)                                               \
_(SW_INTERFACE_TAP_DUMP, sw_interface_tap_dump)                         \
_(IP_ADD_DEL_ROUTE, ip_add_del_route)                                   \
_(PROXY_ARP_ADD_DEL, proxy_arp_add_del)                                 \
_(PROXY_ARP_INTFC_ENABLE_DISABLE, proxy_arp_intfc_enable_disable)       \
_(MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del)		                \
_(SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered)             \
_(IP_NEIGHBOR_ADD_DEL, ip_neighbor_add_del)                             \
_(RESET_VRF, reset_vrf)                                                 \
_(CREATE_VLAN_SUBIF, create_vlan_subif)                                 \
_(CREATE_SUBIF, create_subif)                                           \
_(OAM_ADD_DEL, oam_add_del)                                             \
_(RESET_FIB, reset_fib)                                                 \
_(DHCP_PROXY_CONFIG, dhcp_proxy_config)                                 \
_(DHCP_PROXY_SET_VSS, dhcp_proxy_set_vss)                               \
_(SET_IP_FLOW_HASH, set_ip_flow_hash)                                   \
_(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS,                              \
  sw_interface_ip6_set_link_local_address)                              \
_(SW_INTERFACE_IP6ND_RA_PREFIX, sw_interface_ip6nd_ra_prefix)           \
_(SW_INTERFACE_IP6ND_RA_CONFIG, sw_interface_ip6nd_ra_config)           \
_(SET_ARP_NEIGHBOR_LIMIT, set_arp_neighbor_limit)                       \
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
_(DHCP_CLIENT_CONFIG, dhcp_client_config)	                        \
_(L2TPV3_CREATE_TUNNEL, l2tpv3_create_tunnel)                           \
_(L2TPV3_SET_TUNNEL_COOKIES, l2tpv3_set_tunnel_cookies)                 \
_(L2TPV3_INTERFACE_ENABLE_DISABLE, l2tpv3_interface_enable_disable)     \
_(L2TPV3_SET_LOOKUP_KEY, l2tpv3_set_lookup_key)                         \
_(SW_IF_L2TPV3_TUNNEL_DUMP, sw_if_l2tpv3_tunnel_dump)                   \
_(VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel)                           \
_(VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump)                                 \
_(GRE_ADD_DEL_TUNNEL, gre_add_del_tunnel)                               \
_(GRE_TUNNEL_DUMP, gre_tunnel_dump)                                     \
_(L2_FIB_CLEAR_TABLE, l2_fib_clear_table)                               \
_(L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter)                     \
_(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite)         \
_(CREATE_VHOST_USER_IF, create_vhost_user_if)				\
_(MODIFY_VHOST_USER_IF, modify_vhost_user_if)				\
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
_(INTERFACE_NAME_RENUMBER, interface_name_renumber)			\
_(WANT_IP4_ARP_EVENTS, want_ip4_arp_events)                             \
_(WANT_IP6_ND_EVENTS, want_ip6_nd_events)                               \
_(WANT_L2_MACS_EVENTS, want_l2_macs_events)                             \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_DUMP, ip_dump)                                                     \
_(DELETE_LOOPBACK, delete_loopback)                                     \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)					\
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable) 		\
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)           \
_(AF_PACKET_CREATE, af_packet_create)					\
_(AF_PACKET_DELETE, af_packet_delete)					\
_(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)                   \
_(MPLS_FIB_DUMP, mpls_fib_dump)                                         \
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
_(POLICER_ADD_DEL, policer_add_del)                                     \
_(POLICER_DUMP, policer_dump)                                           \
_(POLICER_CLASSIFY_SET_INTERFACE, policer_classify_set_interface)       \
_(POLICER_CLASSIFY_DUMP, policer_classify_dump)                         \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL,                               \
  ip_source_and_port_range_check_add_del)                               \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL,                     \
  ip_source_and_port_range_check_interface_add_del)                     \
_(LISP_ENABLE_DISABLE, lisp_enable_disable)                             \
_(GPE_ENABLE_DISABLE, gpe_enable_disable)                               \
_(GPE_ADD_DEL_IFACE, gpe_add_del_iface)                                 \
_(LISP_PITR_SET_LOCATOR_SET, lisp_pitr_set_locator_set)                 \
_(LISP_MAP_REQUEST_MODE, lisp_map_request_mode)                         \
_(SHOW_LISP_MAP_REQUEST_MODE, show_lisp_map_request_mode)               \
_(LISP_ADD_DEL_REMOTE_MAPPING, lisp_add_del_remote_mapping)             \
_(LISP_ADD_DEL_ADJACENCY, lisp_add_del_adjacency)                       \
_(LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS,                                   \
  lisp_add_del_map_request_itr_rlocs)                                   \
_(LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map)               \
_(LISP_ADD_DEL_LOCAL_EID, lisp_add_del_local_eid)                       \
_(GPE_ADD_DEL_FWD_ENTRY, gpe_add_del_fwd_entry)                         \
_(LISP_ADD_DEL_LOCATOR_SET, lisp_add_del_locator_set)                   \
_(LISP_ADD_DEL_MAP_RESOLVER, lisp_add_del_map_resolver)                 \
_(LISP_ADD_DEL_LOCATOR, lisp_add_del_locator)                           \
_(LISP_EID_TABLE_DUMP, lisp_eid_table_dump)                             \
_(LISP_EID_TABLE_MAP_DUMP, lisp_eid_table_map_dump)                     \
_(LISP_EID_TABLE_VNI_DUMP, lisp_eid_table_vni_dump)                     \
_(LISP_MAP_RESOLVER_DUMP, lisp_map_resolver_dump)                       \
_(LISP_MAP_SERVER_DUMP, lisp_map_server_dump)                           \
_(LISP_LOCATOR_SET_DUMP, lisp_locator_set_dump)                         \
_(LISP_LOCATOR_DUMP, lisp_locator_dump)                                 \
_(LISP_ADJACENCIES_GET, lisp_adjacencies_get)                           \
_(SHOW_LISP_RLOC_PROBE_STATE, show_lisp_rloc_probe_state)               \
_(SHOW_LISP_MAP_REGISTER_STATE, show_lisp_map_register_state)           \
_(LISP_RLOC_PROBE_ENABLE_DISABLE, lisp_rloc_probe_enable_disable)       \
_(LISP_MAP_REGISTER_ENABLE_DISABLE, lisp_map_register_enable_disable)   \
_(IPSEC_GRE_ADD_DEL_TUNNEL, ipsec_gre_add_del_tunnel)                   \
_(IPSEC_GRE_TUNNEL_DUMP, ipsec_gre_tunnel_dump)                         \
_(DELETE_SUBIF, delete_subif)                                           \
_(L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite)           \
_(PUNT, punt)                                                           \
_(FLOW_CLASSIFY_SET_INTERFACE, flow_classify_set_interface)             \
_(FLOW_CLASSIFY_DUMP, flow_classify_dump)				\
_(GET_FIRST_MSG_ID, get_first_msg_id)                                   \
_(IOAM_ENABLE, ioam_enable)                                             \
_(IOAM_DISABLE, ioam_disable)                                           \
_(IP_FIB_DUMP, ip_fib_dump)                                             \
_(IP6_FIB_DUMP, ip6_fib_dump)                                           \
_(FEATURE_ENABLE_DISABLE, feature_enable_disable)			\
_(SW_INTERFACE_TAG_ADD_DEL, sw_interface_tag_add_del)			\
_(SW_INTERFACE_SET_MTU, sw_interface_set_mtu)                           \
_(P2P_ETHERNET_ADD, p2p_ethernet_add)                                   \
_(P2P_ETHERNET_DEL, p2p_ethernet_del)					\
_(TCP_CONFIGURE_SRC_ADDRESSES, tcp_configure_src_addresses)
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
