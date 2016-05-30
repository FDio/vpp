/*
 *------------------------------------------------------------------
 * custom_dump.c - pretty-print API messages for replay
 * 
 * Copyright (c) 2014 Cisco and/or its affiliates.
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
#include <vnet/mpls-gre/mpls.h>
#include <vnet/dhcp/proxy.h>
#include <vnet/dhcpv6/proxy.h>
#include <vnet/l2tp/l2tp.h>
#include <vnet/l2/l2_input.h>
#include <vnet/sr/sr_packet.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <stats/stats.h>
#include <oam/oam.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/l2/l2_vtr.h>

#include <api/vpe_msg_enum.h>

#define vl_typedefs             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;


static void *vl_api_create_loopback_t_print
(vl_api_create_loopback_t *mp, void *handle)
{
   u8 * s;

   s = format (0, "SCRIPT: create_loopback ");
   s = format (s, "mac %U ", format_ethernet_address, &mp->mac_address);

   FINISH;
}

static void *vl_api_delete_loopback_t_print
(vl_api_delete_loopback_t *mp, void *handle)
{
   u8 * s;

   s = format (0, "SCRIPT: delete_loopback ");
   s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

   FINISH;
}

static void *vl_api_sw_interface_set_flags_t_print
(vl_api_sw_interface_set_flags_t * mp, void *handle)
{
    u8 * s;
    s = format (0, "SCRIPT: sw_interface_set_flags ");
    
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->admin_up_down)
        s = format (s, "admin-up ");
    else
        s = format (s, "admin-down ");

    if (mp->link_up_down)
        s = format (s, "link-up");
    else
        s = format (s, "link-down");
        
    FINISH;
}

static void *vl_api_sw_interface_add_del_address_t_print
(vl_api_sw_interface_add_del_address_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_add_del_address ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

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
(vl_api_sw_interface_set_table_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_set_table ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->vrf_id)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));

    if (mp->is_ipv6)
        s = format (s, "ipv6 ");

    FINISH;
}

static void *vl_api_sw_interface_set_vpath_t_print
(vl_api_sw_interface_set_vpath_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_set_vpath ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->enable)
        s = format (s, "vPath enable ");
    else
        s = format (s, "vPath disable ");

    FINISH;
}

static void *vl_api_sw_interface_set_l2_xconnect_t_print
(vl_api_sw_interface_set_l2_xconnect_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_set_l2_xconnect ");

    s = format (s, "sw_if_index %d ", ntohl(mp->rx_sw_if_index));

    if (mp->enable) {
        s = format (s, "tx_sw_if_index %d ", ntohl(mp->tx_sw_if_index));
    } else s = format (s, "delete ");
    
    FINISH;
}

static void *vl_api_sw_interface_set_l2_bridge_t_print
(vl_api_sw_interface_set_l2_bridge_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_set_l2_bridge ");

    s = format (s, "sw_if_index %d ", ntohl(mp->rx_sw_if_index));

    if (mp->enable) {
        s = format (s, "bd_id %d shg %d %senable ", ntohl(mp->bd_id), 
                    mp->shg, ((mp->bvi)?"bvi ":" "));
    } else s = format (s, "disable ");
    
    FINISH;
}

static void * vl_api_bridge_domain_add_del_t_print
(vl_api_bridge_domain_add_del_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: bridge_domain_add_del ");

    s = format (s, "bd_id %d ", ntohl(mp->bd_id));

    if (mp->is_add) {
        s = format (s, "flood %d uu-flood %d forward %d learn %d arp-term %d",
                    mp->flood, mp->uu_flood, mp->forward, mp->learn, 
		    mp->arp_term);
    } else s = format (s, "del ");

    FINISH;
}

static void *vl_api_bridge_domain_dump_t_print
(vl_api_bridge_domain_dump_t * mp, void *handle)
{
    u8 * s;
    u32 bd_id = ntohl (mp->bd_id);

    s = format (0, "SCRIPT: bridge_domain_dump ");

    if (bd_id != ~0)
        s = format (s, "bd_id %d ", bd_id);
    
    FINISH;
}

static void *vl_api_l2fib_add_del_t_print
(vl_api_l2fib_add_del_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2fib_add_del ");

    s = format (s, "mac %U ", format_ethernet_address, &mp->mac);

    s = format (s, "bd_id %d ", ntohl(mp->bd_id));


    if (mp->is_add) {
	s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
        if (mp->static_mac) s = format (s, "%s", "static ");
        if (mp->filter_mac) s = format (s, "%s", "filter ");
    } else {
	s = format (s, "del ");
    }
    
    FINISH;
}

static void *vl_api_l2_flags_t_print
(vl_api_l2_flags_t * mp, void *handle)
{
    u8 * s;
    u32 flags = ntohl(mp->feature_bitmap);

    s = format (0, "SCRIPT: l2_flags ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

#define _(a,b) \
    if (flags & L2INPUT_FEAT_ ## a) s = format (s, #a " ");
    foreach_l2input_feat;
#undef _
    
    FINISH;
}

static void *vl_api_bridge_flags_t_print
(vl_api_bridge_flags_t * mp, void *handle)
{
    u8 * s;
    u32 flags = ntohl(mp->feature_bitmap);

    s = format (0, "SCRIPT: bridge_flags ");

    s = format (s, "bd_id %d ", ntohl(mp->bd_id));

    if (flags & L2_LEARN) s = format (s, "learn ");
    if (flags & L2_FWD)   s = format (s, "forward ");
    if (flags & L2_FLOOD) s = format (s, "flood ");
    if (flags & L2_UU_FLOOD) s = format (s, "uu-flood ");
    if (flags & L2_ARP_TERM) s = format (s, "arp-term ");

    if (mp->is_set == 0) s = format (s, "clear ");
    
    FINISH;
}

static void *vl_api_bd_ip_mac_add_del_t_print
(vl_api_bd_ip_mac_add_del_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: bd_ip_mac_add_del ");
    s = format (s, "bd_id %d ", ntohl(mp->bd_id));

    if (mp->is_ipv6) 
	 s = format (s, "%U ", format_ip6_address, 
		     (ip6_address_t *) mp->ip_address);
    else s = format (s, "%U ", format_ip4_address, 
		     (ip4_address_t *) mp->ip_address);

    s = format (s, "%U ", format_ethernet_address, mp->mac_address);
    if (mp->is_add == 0) s = format (s, "del ");
    
    FINISH;
}

static void *vl_api_tap_connect_t_print
(vl_api_tap_connect_t * mp, void *handle)
{
    u8 * s;
    u8 null_mac[6];

    memset(null_mac, 0, sizeof (null_mac));

    s = format (0, "SCRIPT: tap_connect ");
    s = format (s, "tapname %s ", mp->tap_name);
    if (mp->use_random_mac)
        s = format (s, "random-mac ");

    if (memcmp (mp->mac_address, null_mac, 6))
        s = format (s, "mac %U ", format_ethernet_address, mp->mac_address);
    
    FINISH;
}

static void *vl_api_tap_modify_t_print
(vl_api_tap_modify_t * mp, void *handle)
{
    u8 * s;
    u8 null_mac[6];

    memset(null_mac, 0, sizeof (null_mac));

    s = format (0, "SCRIPT: tap_modify ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
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
    u8 * s;

    s = format (0, "SCRIPT: tap_delete ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

static void *vl_api_sw_interface_tap_dump_t_print
(vl_api_sw_interface_tap_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_tap_dump ");

    FINISH;
}


static void *vl_api_ip_add_del_route_t_print
(vl_api_ip_add_del_route_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: ip_add_del_route ");
    if (mp->is_add == 0)
        s = format (s, "del ");

    if (mp->next_hop_sw_if_index)
        s = format (s, "sw_if_index %d ", ntohl(mp->next_hop_sw_if_index));

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
    else {
        if (mp->is_ipv6)
            s = format (s, "via %U ", format_ip6_address,
                        mp->next_hop_address);
        else
            s = format (s, "via %U ", format_ip4_address,
                        mp->next_hop_address);
    }

    if (mp->vrf_id != 0)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));
    
    if (mp->create_vrf_if_needed)
        s = format (s, "create-vrf ");

    if (mp->resolve_attempts != 0)                
        s = format (s, "resolve-attempts %d ", ntohl(mp->resolve_attempts));

    if (mp->next_hop_weight != 1)
        s = format (s, "weight %d ", mp->next_hop_weight);

    if (mp->not_last)
        s = format (s, "not-last ");

    if (mp->is_multipath)
        s = format (s, "multipath ");
            
    if (mp->is_multipath)
        s = format (s, "multipath ");

    if (mp->lookup_in_vrf)
        s = format (s, "lookup-in-vrf %d ", ntohl (mp->lookup_in_vrf));

    FINISH;
}

static void *vl_api_proxy_arp_add_del_t_print
(vl_api_proxy_arp_add_del_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: proxy_arp_add_del ");

    s = format (s, "%U - %U ", format_ip4_address, mp->low_address,
		format_ip4_address, mp->hi_address);

    if (mp->vrf_id)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_proxy_arp_intfc_enable_disable_t_print
(vl_api_proxy_arp_intfc_enable_disable_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: proxy_arp_intfc_enable_disable ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "enable %d ", mp->enable_disable);

    FINISH;
}

static void *vl_api_mpls_add_del_decap_t_print
(vl_api_mpls_add_del_decap_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: mpls_add_del_decap ");

    s = format (s, "rx_vrf_id %d ", ntohl(mp->rx_vrf_id));

    s = format (s, "tx_vrf_id %d ", ntohl(mp->tx_vrf_id));

    s = format (s, "label %d ", ntohl(mp->label));

    s = format (s, "next-index %d ", ntohl(mp->next_index));

    if (mp->s_bit == 0)
        s = format (s, "s-bit-clear ");

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_mpls_add_del_encap_t_print
(vl_api_mpls_add_del_encap_t * mp, void * handle)
{
    u8 * s;
    int i;

    s = format (0, "SCRIPT: mpls_add_del_encap ");

    s = format (s, "vrf_id %d ", ntohl(mp->vrf_id));

    s = format (s, "dst %U ", format_ip4_address, mp->dst_address);

    for (i = 0; i < mp->nlabels; i++) 
        s = format (s, "label %d ", ntohl(mp->labels[i]));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_mpls_gre_add_del_tunnel_t_print
(vl_api_mpls_gre_add_del_tunnel_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: mpls_gre_add_del_tunnel ");

    s = format (s, "src %U ", format_ip4_address, mp->src_address);

    s = format (s, "dst %U ", format_ip4_address, mp->dst_address);

    s = format (s, "adj %U/%d ", format_ip4_address, 
                (ip4_address_t *) mp->intfc_address, mp->intfc_address_length);
    
    s = format (s, "inner-vrf_id %d ", ntohl(mp->inner_vrf_id));

    s = format (s, "outer-vrf_id %d ", ntohl(mp->outer_vrf_id));

    if (mp->is_add == 0)
        s = format (s, "del ");

    if (mp->l2_only)
        s = format (s, "l2-only ");

    FINISH;
}

static void *vl_api_mpls_ethernet_add_del_tunnel_t_print
(vl_api_mpls_ethernet_add_del_tunnel_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: mpls_ethernet_add_del_tunnel ");

    s = format (s, "tx_sw_if_index %d ", ntohl(mp->tx_sw_if_index));

    s = format (s, "dst %U", format_ethernet_address, mp->dst_mac_address);
    
    s = format (s, "adj %U/%d ", format_ip4_address, 
                (ip4_address_t *) mp->adj_address, mp->adj_address_length);
    
    s = format (s, "vrf_id %d ", ntohl(mp->vrf_id));

    if (mp->l2_only)
        s = format (s, "l2-only ");

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_mpls_ethernet_add_del_tunnel_2_t_print
(vl_api_mpls_ethernet_add_del_tunnel_2_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: mpls_ethernet_add_del_tunnel_2 ");
    
    s = format (s, "adj %U/%d ", format_ip4_address, 
                (ip4_address_t *) mp->adj_address, mp->adj_address_length);
    
    s = format (s, "next-hop %U ", format_ip4_address, 
                (ip4_address_t *) mp->next_hop_ip4_address_in_outer_vrf);

    s = format (s, "inner_vrf_id %d ", ntohl(mp->inner_vrf_id));

    s = format (s, "outer_vrf_id %d ", ntohl(mp->outer_vrf_id));

    s = format (s, "resolve-if-needed %d ", mp->resolve_if_needed);
    
    s = format (s, "resolve-attempts %d ", ntohl(mp->resolve_attempts));

    if (mp->l2_only)
        s = format (s, "l2-only ");

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_sw_interface_set_unnumbered_t_print
(vl_api_sw_interface_set_unnumbered_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_set_unnumbered ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "unnum_if_index %d ", ntohl(mp->unnumbered_sw_if_index));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_ip_neighbor_add_del_t_print
(vl_api_ip_neighbor_add_del_t * mp, void *handle)
{
    u8 * s;
    u8 null_mac[6];

    memset(null_mac, 0, sizeof (null_mac));

    s = format (0, "SCRIPT: ip_neighbor_add_del ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->is_static)
        s = format (s, "is_static ");

    s = format (s, "vrf_id %d ", ntohl(mp->vrf_id));

    if (memcmp (mp->mac_address, null_mac, 6))
        s = format (s, "mac %U ", format_ethernet_address, mp->mac_address);

    if (mp->is_ipv6)
        s = format (s, "dst %U ", format_ip6_address, (ip6_address_t *) mp->dst_address);
    else
        s = format (s, "dst %U ", format_ip4_address, (ip4_address_t *) mp->dst_address);
    
    if (mp->is_add == 0)
        s = format (s, "del ");
    
    FINISH;
}

static void *vl_api_reset_vrf_t_print
(vl_api_reset_vrf_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: reset_vrf ");

    if (mp->vrf_id)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));

    if (mp->is_ipv6 != 0)
        s = format (s, "ipv6 ");

    FINISH;
}

static void *vl_api_create_vlan_subif_t_print
(vl_api_create_vlan_subif_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: create_vlan_subif ");

    if (mp->sw_if_index)
        s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->vlan_id)
        s = format (s, "vlan_id %d ", ntohl(mp->vlan_id));

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
(vl_api_create_subif_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: create_subif ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "sub_id %d ", ntohl(mp->sub_id));

    if (mp->outer_vlan_id)
        s = format (s, "outer_vlan_id %d ", ntohs (mp->outer_vlan_id));

    if (mp->outer_vlan_id)
        s = format (s, "inner_vlan_id %d ", ntohs (mp->inner_vlan_id));

#define _(a) if (mp->a) s = format (s, "%s ", #a);
    foreach_create_subif_bit;
#undef _


    FINISH;
}

static void *vl_api_oam_add_del_t_print
(vl_api_oam_add_del_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: oam_add_del ");

    if (mp->vrf_id)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));

    s = format (s, "src %U ", format_ip4_address, mp->src_address);

    s = format (s, "dst %U ", format_ip4_address, mp->dst_address);

    if (mp->is_add == 0)
        s = format (s, "del ");
    
    FINISH;
}

static void *vl_api_reset_fib_t_print
(vl_api_reset_fib_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: reset_fib ");

    if (mp->vrf_id)
        s = format (s, "vrf %d ", ntohl(mp->vrf_id));

    if (mp->is_ipv6 != 0)
        s = format (s, "ipv6 ");

    FINISH;
}

static void *vl_api_dhcp_proxy_config_t_print
(vl_api_dhcp_proxy_config_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: dhcp_proxy_config ");

    s = format (s, "vrf_id %d ", ntohl(mp->vrf_id));

    if (mp->is_ipv6) {
        s = format (s, "svr %U ", format_ip6_address, 
                    (ip6_address_t *) mp->dhcp_server);
        s = format (s, "src %U ", format_ip6_address,
                    (ip6_address_t *) mp->dhcp_src_address);
    } else {
        s = format (s, "svr %U ", format_ip4_address, 
                    (ip4_address_t *) mp->dhcp_server);
        s = format (s, "src %U ", format_ip4_address,
                    (ip4_address_t *) mp->dhcp_src_address);
    }
    if (mp->is_add == 0)
        s = format (s, "del ");

    s = format (s, "insert-cid %d ", mp->insert_circuit_id);

    FINISH;
}

static void *vl_api_dhcp_proxy_config_2_t_print
(vl_api_dhcp_proxy_config_2_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: dhcp_proxy_config_2 ");

    s = format (s, "rx_vrf_id %d ", ntohl(mp->rx_vrf_id));
    s = format (s, "server_vrf_id %d ", ntohl(mp->server_vrf_id));

    if (mp->is_ipv6) {
        s = format (s, "svr %U ", format_ip6_address, 
                    (ip6_address_t *) mp->dhcp_server);
        s = format (s, "src %U ", format_ip6_address,
                    (ip6_address_t *) mp->dhcp_src_address);
    } else {
        s = format (s, "svr %U ", format_ip4_address, 
                    (ip4_address_t *) mp->dhcp_server);
        s = format (s, "src %U ", format_ip4_address,
                    (ip4_address_t *) mp->dhcp_src_address);
    }
    if (mp->is_add == 0)
        s = format (s, "del ");

    s = format (s, "insert-cid %d ", mp->insert_circuit_id);

    FINISH;
}

static void *vl_api_dhcp_proxy_set_vss_t_print
(vl_api_dhcp_proxy_set_vss_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: dhcp_proxy_set_vss ");

    s = format (s, "tbl_id %d ", ntohl(mp->tbl_id));

    s = format (s, "fib_id %d ", ntohl(mp->fib_id));

    s = format (s, "oui %d ", ntohl(mp->oui));

    if (mp->is_ipv6 != 0)
        s = format (s, "ipv6 ");

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_dhcp_client_config_t_print
(vl_api_dhcp_client_config_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: dhcp_client_config ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "hostname %s ", mp->hostname);

    s = format (s, "want_dhcp_event %d ", mp->want_dhcp_event);

    s = format (s, "pid %d ", mp->pid);

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}


static void *vl_api_set_ip_flow_hash_t_print
(vl_api_set_ip_flow_hash_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: set_ip_flow_hash ");

    s = format (s, "vrf_id %d ", ntohl(mp->vrf_id));

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
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_ip6_set_link_local_address ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "%U/%d ", format_ip6_address, mp->address,
                mp->address_length);

    FINISH;
}

static void *vl_api_sw_interface_ip6nd_ra_prefix_t_print
(vl_api_sw_interface_ip6nd_ra_prefix_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_ip6nd_ra_prefix ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "%U/%d ", format_ip6_address, mp->address,
                mp->address_length);

    s = format (s, "val_life %d ", ntohl(mp->val_lifetime));

    s = format (s, "pref_life %d ", ntohl(mp->pref_lifetime));

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
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_ip6nd_ra_config ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "maxint %d ", ntohl(mp->max_interval));

    s = format (s, "minint %d ", ntohl(mp->min_interval));

    s = format (s, "life %d ", ntohl(mp->lifetime));

    s = format (s, "count %d ", ntohl(mp->initial_count));

    s = format (s, "interval %d ", ntohl(mp->initial_interval));

    if (mp->surpress)
        s = format (s, "surpress ");

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
(vl_api_set_arp_neighbor_limit_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: set_arp_neighbor_limit ");

    s = format (s, "arp_nbr_limit %d ", ntohl(mp->arp_neighbor_limit));

    if (mp->is_ipv6 != 0)
        s = format (s, "ipv6 ");

    FINISH;
}

static void *vl_api_l2_patch_add_del_t_print
(vl_api_l2_patch_add_del_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2_patch_add_del ");

    s = format (s, "rx_sw_if_index %d ", ntohl(mp->rx_sw_if_index));

    s = format (s, "tx_sw_if_index %d ", ntohl(mp->tx_sw_if_index));

    if (mp->is_add == 0)
        s = format (s, "del ");
    
    FINISH;
}

static void *vl_api_sr_tunnel_add_del_t_print
(vl_api_sr_tunnel_add_del_t * mp, void *handle)
{
    u8 * s;
    ip6_address_t * this_address;
    int i;
    u16 flags_host_byte_order;
    u8 pl_flag;

    s = format (0, "SCRIPT: sr_tunnel_add_del ");

    if (mp->name[0])
      s = format (s, "name %s ", mp->name);

    s = format (s, "src %U dst %U/%d ", format_ip6_address, 
                (ip6_address_t *) mp->src_address,
                format_ip6_address,
                (ip6_address_t *) mp->dst_address, mp->dst_mask_width);
    
    this_address = (ip6_address_t *)mp->segs_and_tags;
    for (i = 0; i < mp->n_segments; i++) {
        s = format (s, "next %U ", format_ip6_address, this_address);
        this_address++;
    }
    for (i = 0; i < mp->n_tags; i++) {
        s = format (s, "tag %U ", format_ip6_address, this_address);
        this_address++;
    }
                
    flags_host_byte_order = clib_net_to_host_u16 (mp->flags_net_byte_order);

    if (flags_host_byte_order & IP6_SR_HEADER_FLAG_CLEANUP)
        s = format (s, " clean ");

    if (flags_host_byte_order & IP6_SR_HEADER_FLAG_PROTECTED)
        s = format (s, "protected ");

    for (i = 1; i <= 4; i++) {
        pl_flag = ip6_sr_policy_list_flags (flags_host_byte_order, i);
        
        switch (pl_flag) {
        case IP6_SR_HEADER_FLAG_PL_ELT_NOT_PRESENT:
            continue;

        case IP6_SR_HEADER_FLAG_PL_ELT_INGRESS_PE:
            s = format (s, "InPE %d ", i);
            break;

        case IP6_SR_HEADER_FLAG_PL_ELT_EGRESS_PE:
            s = format (s, "EgPE %d ", i);
            break;
            
        case IP6_SR_HEADER_FLAG_PL_ELT_ORIG_SRC_ADDR:
            s = format (s, "OrgSrc %d ", i);
            break;

        default:
            clib_warning ("BUG: pl elt %d value %d", i, pl_flag);
            break;
        }
    }

    if (mp->policy_name[0])
      s = format (s, "policy_name %s ", mp->policy_name);

    if (mp->is_add == 0)
        s = format (s, "del ");
    
    FINISH;
}

static void *vl_api_sr_policy_add_del_t_print
(vl_api_sr_policy_add_del_t * mp, void *handle)
{
  u8 * s;
  int i;

  s = format (0, "SCRIPT: sr_policy_add_del ");

  if (mp->name[0])
    s = format (s, "name %s ", mp->name);


  if (mp->tunnel_names[0])
    {
    // start deserializing tunnel_names
    int num_tunnels = mp->tunnel_names[0]; //number of tunnels
    u8 * deser_tun_names = mp->tunnel_names;
    deser_tun_names += 1; //moving along

    u8 * tun_name = 0;
    int tun_name_len = 0;

    for (i=0; i < num_tunnels; i++)
      {
	tun_name_len= *deser_tun_names;
	deser_tun_names += 1;
	vec_resize (tun_name, tun_name_len);
	memcpy(tun_name, deser_tun_names, tun_name_len);
	s = format (s, "tunnel %s ", tun_name);
	deser_tun_names += tun_name_len;
	tun_name = 0;
      }
    }

  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}

static void *vl_api_sr_multicast_map_add_del_t_print
(vl_api_sr_multicast_map_add_del_t * mp, void *handle)
{

  u8 * s = 0;
  /* int i; */

  s = format (0, "SCRIPT: sr_multicast_map_add_del ");

  if (mp->multicast_address[0])
    s = format (s, "address %U ", format_ip6_address, &mp->multicast_address);

  if (mp->policy_name[0])
    s = format (s, "sr-policy %s ", &mp->policy_name);


  if (mp->is_add == 0)
    s = format (s, "del ");

  FINISH;
}


static void *vl_api_classify_add_del_table_t_print
(vl_api_classify_add_del_table_t * mp, void *handle)
{
    u8 * s;
    int i;

    s = format (0, "SCRIPT: classify_add_del_table ");

    if (mp->is_add == 0) {
        s = format (s, "table %d ", ntohl(mp->table_index));
        s = format (s, "del ");
    } else {
        s = format (s, "nbuckets %d ", ntohl(mp->nbuckets));
        s = format (s, "memory_size %d ", ntohl(mp->memory_size));
        s = format (s, "skip %d ", ntohl(mp->skip_n_vectors));
        s = format (s, "match %d ", ntohl(mp->match_n_vectors));
        s = format (s, "next-table %d ", ntohl(mp->next_table_index));
        s = format (s, "miss-next %d ", ntohl(mp->miss_next_index));
        s = format (s, "mask hex ");
        for (i = 0; i < ntohl(mp->match_n_vectors) * sizeof (u32x4); i++)
            s = format (s, "%02x", mp->mask[i]);
        vec_add1 (s, ' ');
    }
    
    FINISH;
}

static void *vl_api_classify_add_del_session_t_print
(vl_api_classify_add_del_session_t * mp, void *handle)
{
    u8 * s;
    int i, limit=0;

    s = format (0, "SCRIPT: classify_add_del_session ");

    s = format (s, "table_index %d ", ntohl (mp->table_index));
    s = format (s, "hit_next_index %d ", ntohl (mp->hit_next_index));
    s = format (s, "opaque_index %d ", ntohl (mp->opaque_index));
    s = format (s, "advance %d ", ntohl (mp->advance));
    if (mp->is_add == 0)
        s = format (s, "del ");
    
    s = format (s, "match hex ");
    for (i = 5 * sizeof(u32x4)-1; i > 0; i--) {
        if (mp->match[i] != 0) {
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
    u8 * s;

    s = format (0, "SCRIPT: classify_set_interface_ip_table ");

    if (mp->is_ipv6) 
        s = format (s, "ipv6 ");
        
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "table %d ", ntohl(mp->table_index));

    FINISH;
}

static void *vl_api_classify_set_interface_l2_tables_t_print
(vl_api_classify_set_interface_l2_tables_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: classify_set_interface_l2_tables ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "ip4-table %d ", ntohl(mp->ip4_table_index));
    s = format (s, "ip6-table %d ", ntohl(mp->ip6_table_index));
    s = format (s, "other-table %d ", ntohl(mp->other_table_index));

    FINISH;
}

static void *vl_api_add_node_next_t_print
(vl_api_add_node_next_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: add_node_next ");

    s = format (0, "node %s next %s ", mp->node_name, mp->next_name);

    FINISH;
}

static void *vl_api_l2tpv3_create_tunnel_t_print
(vl_api_l2tpv3_create_tunnel_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2tpv3_create_tunnel ");

    s = format (s, "client_address %U our_address %U ",
                format_ip6_address, (ip6_address_t *)(mp->client_address),
                format_ip6_address, (ip6_address_t *)(mp->our_address));
    s = format (s, "local_session_id %d ", ntohl(mp->local_session_id));
    s = format (s, "remote_session_id %d ", ntohl(mp->remote_session_id));
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
    u8 * s;

    s = format (0, "SCRIPT: l2tpv3_set_tunnel_cookies ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "new_local_cookie %llu ", 
                clib_net_to_host_u64 (mp->new_local_cookie));
    
    s = format (s, "new_remote_cookie %llu ", 
                clib_net_to_host_u64 (mp->new_remote_cookie));

    FINISH;
}

static void *vl_api_l2tpv3_interface_enable_disable_t_print
(vl_api_l2tpv3_interface_enable_disable_t *mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2tpv3_interface_enable_disable ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    if (mp->enable_disable == 0)
        s = format (s, "del ");

    FINISH;
}

static void * vl_api_l2tpv3_set_lookup_key_t_print
(vl_api_l2tpv3_set_lookup_key_t * mp, void *handle)
{
    u8 * s;
    char * str = "unknown";

    s = format (0, "SCRIPT: l2tpv3_set_lookup_key ");

    switch (mp->key) {
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

static void * vl_api_sw_if_l2tpv3_tunnel_dump_t_print
(vl_api_sw_if_l2tpv3_tunnel_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_if_l2tpv3_tunnel_dump ");

    FINISH;
}

static void * vl_api_vxlan_add_del_tunnel_t_print
(vl_api_vxlan_add_del_tunnel_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: vxlan_add_del_tunnel ");

    s = format (s, "dst %U ", format_ip46_address,
                (ip46_address_t *)&(mp->dst_address));

    s = format (s, "src %U ", format_ip46_address,
                (ip46_address_t *)&(mp->src_address));

    if (mp->encap_vrf_id)
        s = format (s, "encap-vrf-id %d ", ntohl(mp->encap_vrf_id));

    s = format (s, "decap-next %d ", ntohl(mp->decap_next_index));

    s = format (s, "vni %d ", ntohl(mp->vni));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void * vl_api_vxlan_tunnel_dump_t_print
(vl_api_vxlan_tunnel_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: vxlan_tunnel_dump ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

static void * vl_api_gre_add_del_tunnel_t_print
(vl_api_gre_add_del_tunnel_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: gre_add_del_tunnel ");

    s = format (s, "dst %U ", format_ip4_address,
                (ip4_address_t *)&(mp->dst_address));

    s = format (s, "src %U ", format_ip4_address,
                (ip4_address_t *)&(mp->src_address));

    if (mp->outer_table_id)
        s = format (s, "outer-fib-id %d ", ntohl(mp->outer_table_id));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void * vl_api_gre_tunnel_dump_t_print
(vl_api_gre_tunnel_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: gre_tunnel_dump ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

static void *vl_api_l2_fib_clear_table_t_print
(vl_api_l2_fib_clear_table_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2_fib_clear_table ");

    FINISH;
}

static void *vl_api_l2_interface_efp_filter_t_print
(vl_api_l2_interface_efp_filter_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2_interface_efp_filter ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    if (mp->enable_disable)
        s = format (s, "enable ");
    else
        s = format (s, "disable ");

    FINISH;
}

static void *vl_api_l2_interface_vlan_tag_rewrite_t_print
(vl_api_l2_interface_vlan_tag_rewrite_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: l2_interface_vlan_tag_rewrite ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "vtr_op %d ", ntohl(mp->vtr_op));
    s = format (s, "push_dot1q %d ", ntohl(mp->push_dot1q));
    s = format (s, "tag1 %d ", ntohl(mp->tag1));
    s = format (s, "tag2 %d ", ntohl(mp->tag2));

    FINISH;
}

static void *vl_api_create_vhost_user_if_t_print
(vl_api_create_vhost_user_if_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: create_vhost_user_if ");

    s = format (s, "socket %s ", mp->sock_filename);
    if (mp->is_server)
        s = format (s, "server ");
    if (mp->renumber)
        s = format (s, "renumber %d ", ntohl(mp->custom_dev_instance));

    FINISH;
}

static void *vl_api_modify_vhost_user_if_t_print
(vl_api_modify_vhost_user_if_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: modify_vhost_user_if ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "socket %s ", mp->sock_filename);
    if (mp->is_server)
        s = format (s, "server ");
    if (mp->renumber)
        s = format (s, "renumber %d ", ntohl(mp->custom_dev_instance));

    FINISH;
}

static void *vl_api_delete_vhost_user_if_t_print
(vl_api_delete_vhost_user_if_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: delete_vhost_user_if ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

static void *vl_api_sw_interface_vhost_user_dump_t_print
(vl_api_sw_interface_vhost_user_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_vhost_user_dump ");

    FINISH;
}

static void *vl_api_sw_interface_dump_t_print
(vl_api_sw_interface_dump_t * mp, void *handle)
{
    u8 * s;

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
    u8 * s;

    s = format (0, "SCRIPT: l2_fib_table_dump ");

    s = format (s, "bd_id %d ", ntohl(mp->bd_id));

    FINISH;
}

static void *vl_api_control_ping_t_print
(vl_api_control_ping_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: control_ping ");

    FINISH;
}

static void *vl_api_want_interface_events_t_print
(vl_api_want_interface_events_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: want_interface_events pid %d enable %d ",
                ntohl(mp->pid), ntohl(mp->enable_disable));

    FINISH;
}

static void *vl_api_cli_request_t_print
(vl_api_cli_request_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: cli_request ");

    FINISH;
}

static void *vl_api_memclnt_create_t_print
(vl_api_memclnt_create_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: memclnt_create name %s ", mp->name);

    FINISH;
}

static void *vl_api_show_version_t_print
(vl_api_show_version_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: show_version ");

    FINISH;
}

static void *vl_api_vxlan_gpe_add_del_tunnel_t_print
(vl_api_vxlan_gpe_add_del_tunnel_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: vxlan_gpe_add_del_tunnel ");

    s = format (s, "local %U ", format_ip46_address, &mp->local, mp->is_ipv6);

    s = format (s, "remote %U ", format_ip46_address, &mp->remote, mp->is_ipv6);

    s = format (s, "protocol %d ", ntohl(mp->protocol));

    s = format (s, "vni %d ", ntohl(mp->vni));

    if (mp->is_add == 0)
        s = format (s, "del ");

    if (mp->encap_vrf_id)
        s = format (s, "encap-vrf-id %d ", ntohl(mp->encap_vrf_id));
    
    if (mp->decap_vrf_id)
        s = format (s, "decap-vrf-id %d ", ntohl(mp->decap_vrf_id));

    FINISH;
}

static void * vl_api_vxlan_gpe_tunnel_dump_t_print
(vl_api_vxlan_gpe_tunnel_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: vxlan_gpe_tunnel_dump ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

static void *vl_api_interface_name_renumber_t_print 
(vl_api_interface_name_renumber_t * mp, void * handle)
{
    u8 * s;

    s = format (0, "SCRIPT: interface_renumber ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    s = format (s, "new_show_dev_instance %d ", 
                ntohl(mp->new_show_dev_instance));
    
    FINISH;
}

static void *vl_api_want_ip4_arp_events_t_print
(vl_api_want_ip4_arp_events_t * mp, void * handle)
{
    u8 * s;
 
    s = format (0, "SCRIPT: want_ip4_arp_events ");
    s = format (s, "pid %d address %U ", mp->pid, 
                format_ip4_address, &mp->address);
    if (mp->enable_disable == 0)
        s = format (s, "del ");

    FINISH;
}

static void *vl_api_input_acl_set_interface_t_print
(vl_api_input_acl_set_interface_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: input_acl_set_interface ");

    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "ip4-table %d ", ntohl(mp->ip4_table_index));
    s = format (s, "ip6-table %d ", ntohl(mp->ip6_table_index));
    s = format (s, "l2-table %d ", ntohl(mp->l2_table_index));

    if (mp->is_add == 0)
        s = format (s, "del ");

    FINISH;
}

static void * vl_api_ip_address_dump_t_print
(vl_api_ip_address_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: ip6_address_dump ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "is_ipv6 %d ", mp->is_ipv6 != 0);

    FINISH;
}

static void * vl_api_ip_dump_t_print
(vl_api_ip_dump_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: ip_dump ");
    s = format (s, "is_ipv6 %d ", mp->is_ipv6 != 0);

    FINISH;
}

static void * vl_api_cop_interface_enable_disable_t_print
(vl_api_cop_interface_enable_disable_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: cop_interface_enable_disable ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    if (mp->enable_disable)
        s = format (s, "enable ");
    else
        s = format (s, "disable ");

    FINISH;
}

static void * vl_api_cop_whitelist_enable_disable_t_print
(vl_api_cop_whitelist_enable_disable_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: cop_whitelist_enable_disable ");
    s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));
    s = format (s, "fib-id %d ", ntohl(mp->fib_id));
    if (mp->ip4)
        s = format (s, "ip4 ");
    if (mp->ip6)
        s = format (s, "ip6 ");
    if (mp->default_cop)
        s = format (s, "default ");

    FINISH;
}

static void *vl_api_sw_interface_clear_stats_t_print
(vl_api_sw_interface_clear_stats_t * mp, void *handle)
{
    u8 * s;

    s = format (0, "SCRIPT: sw_interface_clear_stats ");
    if (mp->sw_if_index != ~0)
      s = format (s, "sw_if_index %d ", ntohl(mp->sw_if_index));

    FINISH;
}

#define foreach_custom_print_function                                   \
_(CREATE_LOOPBACK, create_loopback)                                     \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)                       \
_(SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address)           \
_(SW_INTERFACE_SET_TABLE, sw_interface_set_table)                       \
_(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath)                       \
_(TAP_CONNECT, tap_connect)                                             \
_(TAP_MODIFY, tap_modify)                                               \
_(TAP_DELETE, tap_delete)                                               \
_(SW_INTERFACE_TAP_DUMP, sw_interface_tap_dump)                         \
_(IP_ADD_DEL_ROUTE, ip_add_del_route)                                   \
_(PROXY_ARP_ADD_DEL, proxy_arp_add_del)                                 \
_(PROXY_ARP_INTFC_ENABLE_DISABLE, proxy_arp_intfc_enable_disable)       \
_(MPLS_ADD_DEL_DECAP, mpls_add_del_decap)                               \
_(MPLS_ADD_DEL_ENCAP, mpls_add_del_encap)                               \
_(MPLS_GRE_ADD_DEL_TUNNEL, mpls_gre_add_del_tunnel)                     \
_(MPLS_ETHERNET_ADD_DEL_TUNNEL, mpls_ethernet_add_del_tunnel)		\
_(MPLS_ETHERNET_ADD_DEL_TUNNEL_2, mpls_ethernet_add_del_tunnel_2)	\
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
_(SR_TUNNEL_ADD_DEL, sr_tunnel_add_del)					\
_(SR_POLICY_ADD_DEL, sr_policy_add_del)					\
_(SR_MULTICAST_MAP_ADD_DEL, sr_multicast_map_add_del)                   \
_(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect)           \
_(L2FIB_ADD_DEL, l2fib_add_del)                                         \
_(L2_FLAGS, l2_flags)                                                   \
_(BRIDGE_FLAGS, bridge_flags)                                           \
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)			\
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)			\
_(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge)		\
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)                         \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                               \
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)	\
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)	\
_(ADD_NODE_NEXT, add_node_next)						\
_(DHCP_PROXY_CONFIG_2, dhcp_proxy_config_2)	                        \
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
_(CLI_REQUEST, cli_request)						\
_(MEMCLNT_CREATE, memclnt_create)					\
_(SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump)           \
_(SHOW_VERSION, show_version)                                           \
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)                                 \
_(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel)			        \
_(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump)                         \
_(INTERFACE_NAME_RENUMBER, interface_name_renumber)			\
_(WANT_IP4_ARP_EVENTS, want_ip4_arp_events)                             \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_DUMP, ip_dump)                                                     \
_(DELETE_LOOPBACK, delete_loopback)                                     \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)					\
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable) 		\
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)           \
_(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)

void vl_msg_api_custom_dump_configure (api_main_t *am) 
{
#define _(n,f) am->msg_print_handlers[VL_API_##n]       \
    = (void *) vl_api_##f##_t_print;
    foreach_custom_print_function;
#undef _
}
