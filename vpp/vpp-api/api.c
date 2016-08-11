/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/api_errno.h>
#include <vnet/vnet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2tp/l2tp.h>
#include <vnet/ip/ip.h>
#include <vnet/unix/tuntap.h>
#include <vnet/unix/tapcli.h>
#include <vnet/mpls-gre/mpls.h>
#include <vnet/dhcp/proxy.h>
#include <vnet/dhcp/client.h>
#if IPV6SR > 0
#include <vnet/sr/sr.h>
#endif
#include <vnet/dhcpv6/proxy.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/input_acl.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/gre/gre.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-cp/control.h>
#include <vnet/map/map.h>
#include <vnet/cop/cop.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/devices/af_packet/af_packet.h>
#include <vnet/policer/policer.h>
#include <vnet/devices/netmap/netmap.h>
#include <vnet/flow/flow_report.h>

#undef BIHASH_TYPE
#undef __included_bihash_template_h__
#include <vnet/l2/l2_fib.h>

#if IPSEC > 0
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#endif /* IPSEC */
#if DPDK > 0
#include <vnet/devices/virtio/vhost-user.h>
#endif

#include <stats/stats.h>
#include <oam/oam.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/interface.h>

#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_bd.h>
#include <vpp-api/vpe_msg_enum.h>

#define f64_endian(a)
#define f64_print(a,b)

#define vl_typedefs		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#if (1 || CLIB_DEBUG > 0)	/* "trust, but verify" */

#define VALIDATE_SW_IF_INDEX(mp)				\
 do { u32 __sw_if_index = ntohl(mp->sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __sw_if_index)) {                    \
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_sw_if_index;                                   \
    }                                                           \
} while(0);

#define BAD_SW_IF_INDEX_LABEL                   \
do {                                            \
bad_sw_if_index:                                \
    ;                                           \
} while (0);

#define VALIDATE_RX_SW_IF_INDEX(mp)				\
 do { u32 __rx_sw_if_index = ntohl(mp->rx_sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __rx_sw_if_index)) {			\
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_rx_sw_if_index;				\
    }                                                           \
} while(0);

#define BAD_RX_SW_IF_INDEX_LABEL		\
do {                                            \
bad_rx_sw_if_index:				\
    ;                                           \
} while (0);

#define VALIDATE_TX_SW_IF_INDEX(mp)				\
 do { u32 __tx_sw_if_index = ntohl(mp->tx_sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __tx_sw_if_index)) {			\
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_tx_sw_if_index;				\
    }                                                           \
} while(0);

#define BAD_TX_SW_IF_INDEX_LABEL		\
do {                                            \
bad_tx_sw_if_index:				\
    ;                                           \
} while (0);

#else

#define VALIDATE_SW_IF_INDEX(mp)
#define BAD_SW_IF_INDEX_LABEL
#define VALIDATE_RX_SW_IF_INDEX(mp)
#define BAD_RX_SW_IF_INDEX_LABEL
#define VALIDATE_TX_SW_IF_INDEX(mp)
#define BAD_TX_SW_IF_INDEX_LABEL

#endif /* CLIB_DEBUG > 0 */

#define foreach_vpe_api_msg                                             \
_(WANT_INTERFACE_EVENTS, want_interface_events)                         \
_(WANT_OAM_EVENTS, want_oam_events)                                     \
_(OAM_ADD_DEL, oam_add_del)                                             \
_(SW_INTERFACE_DUMP, sw_interface_dump)                                 \
_(SW_INTERFACE_DETAILS, sw_interface_details)                           \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)                       \
_(IP_ADD_DEL_ROUTE, ip_add_del_route)                                   \
_(IS_ADDRESS_REACHABLE, is_address_reachable)                           \
_(SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address)           \
_(SW_INTERFACE_SET_TABLE, sw_interface_set_table)                       \
_(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath)                       \
_(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect)           \
_(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge)               \
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)                         \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                               \
_(BRIDGE_DOMAIN_DETAILS, bridge_domain_details)                         \
_(BRIDGE_DOMAIN_SW_IF_DETAILS, bridge_domain_sw_if_details)             \
_(L2FIB_ADD_DEL, l2fib_add_del)                                         \
_(L2_FLAGS, l2_flags)                                                   \
_(BRIDGE_FLAGS, bridge_flags)                                           \
_(TAP_CONNECT, tap_connect)                                             \
_(TAP_MODIFY, tap_modify)                                               \
_(TAP_DELETE, tap_delete)                                               \
_(SW_INTERFACE_TAP_DUMP, sw_interface_tap_dump)                         \
_(CREATE_VLAN_SUBIF, create_vlan_subif)                                 \
_(CREATE_SUBIF, create_subif)                                           \
_(MPLS_GRE_ADD_DEL_TUNNEL, mpls_gre_add_del_tunnel)                     \
_(MPLS_ETHERNET_ADD_DEL_TUNNEL, mpls_ethernet_add_del_tunnel)           \
_(MPLS_ETHERNET_ADD_DEL_TUNNEL_2, mpls_ethernet_add_del_tunnel_2)       \
_(MPLS_ADD_DEL_ENCAP, mpls_add_del_encap)                               \
_(MPLS_ADD_DEL_DECAP, mpls_add_del_decap)                               \
_(PROXY_ARP_ADD_DEL, proxy_arp_add_del)                                 \
_(PROXY_ARP_INTFC_ENABLE_DISABLE, proxy_arp_intfc_enable_disable)       \
_(IP_NEIGHBOR_ADD_DEL, ip_neighbor_add_del)                             \
_(VNET_GET_SUMMARY_STATS, vnet_get_summary_stats)			\
_(RESET_FIB, reset_fib)							\
_(DHCP_PROXY_CONFIG,dhcp_proxy_config)					\
_(DHCP_PROXY_CONFIG_2,dhcp_proxy_config_2)				\
_(DHCP_PROXY_SET_VSS,dhcp_proxy_set_vss)                                \
_(DHCP_CLIENT_CONFIG, dhcp_client_config)				\
_(SET_IP_FLOW_HASH,set_ip_flow_hash)                                    \
_(SW_INTERFACE_IP6ND_RA_CONFIG, sw_interface_ip6nd_ra_config)           \
_(SW_INTERFACE_IP6ND_RA_PREFIX, sw_interface_ip6nd_ra_prefix)           \
_(SW_INTERFACE_IP6_ENABLE_DISABLE, sw_interface_ip6_enable_disable )    \
_(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS, 				\
  sw_interface_ip6_set_link_local_address)                              \
_(SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered)		\
_(CREATE_LOOPBACK, create_loopback)					\
_(CONTROL_PING, control_ping)                                           \
_(NOPRINT_CONTROL_PING, noprint_control_ping)                           \
_(CLI_REQUEST, cli_request)                                             \
_(SET_ARP_NEIGHBOR_LIMIT, set_arp_neighbor_limit)			\
_(L2_PATCH_ADD_DEL, l2_patch_add_del)					\
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)			\
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)			\
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)     \
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)   \
_(GET_NODE_INDEX, get_node_index)                                       \
_(ADD_NODE_NEXT, add_node_next)						\
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
_(CREATE_VHOST_USER_IF, create_vhost_user_if)                           \
_(MODIFY_VHOST_USER_IF, modify_vhost_user_if)                           \
_(DELETE_VHOST_USER_IF, delete_vhost_user_if)                           \
_(SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump)           \
_(IP_ADDRESS_DUMP, ip_address_dump)                                     \
_(IP_DUMP, ip_dump)                                                     \
_(SW_INTERFACE_VHOST_USER_DETAILS, sw_interface_vhost_user_details)	\
_(SHOW_VERSION, show_version)						\
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)	                                \
_(L2_FIB_TABLE_ENTRY, l2_fib_table_entry)                               \
_(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel)                   \
_(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump)                         \
_(INTERFACE_NAME_RENUMBER, interface_name_renumber)			\
_(WANT_IP4_ARP_EVENTS, want_ip4_arp_events)                             \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(IPSEC_SPD_ADD_DEL, ipsec_spd_add_del)                                 \
_(IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd)             \
_(IPSEC_SPD_ADD_DEL_ENTRY, ipsec_spd_add_del_entry)                     \
_(IPSEC_SAD_ADD_DEL_ENTRY, ipsec_sad_add_del_entry)                     \
_(IPSEC_SA_SET_KEY, ipsec_sa_set_key)                                   \
_(IKEV2_PROFILE_ADD_DEL, ikev2_profile_add_del)                         \
_(IKEV2_PROFILE_SET_AUTH, ikev2_profile_set_auth)                       \
_(IKEV2_PROFILE_SET_ID, ikev2_profile_set_id)                           \
_(IKEV2_PROFILE_SET_TS, ikev2_profile_set_ts)                           \
_(IKEV2_SET_LOCAL_KEY, ikev2_set_local_key)                             \
_(DELETE_LOOPBACK, delete_loopback)                                     \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)                                 \
_(MAP_ADD_DOMAIN, map_add_domain)                                       \
_(MAP_DEL_DOMAIN, map_del_domain)                                       \
_(MAP_ADD_DEL_RULE, map_add_del_rule)                                   \
_(MAP_DOMAIN_DUMP, map_domain_dump)                                     \
_(MAP_RULE_DUMP, map_rule_dump)						\
_(MAP_SUMMARY_STATS, map_summary_stats)					\
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable)		\
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)		\
_(GET_NODE_GRAPH, get_node_graph)                                       \
_(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)                   \
_(TRACE_PROFILE_ADD, trace_profile_add)                                 \
_(TRACE_PROFILE_APPLY, trace_profile_apply)                             \
_(TRACE_PROFILE_DEL, trace_profile_del)                                 \
_(LISP_ADD_DEL_LOCATOR_SET, lisp_add_del_locator_set)                   \
_(LISP_ADD_DEL_LOCATOR, lisp_add_del_locator)                           \
_(LISP_ADD_DEL_LOCAL_EID, lisp_add_del_local_eid)                       \
_(LISP_GPE_ADD_DEL_FWD_ENTRY, lisp_gpe_add_del_fwd_entry)               \
_(LISP_ADD_DEL_MAP_RESOLVER, lisp_add_del_map_resolver)                 \
_(LISP_GPE_ENABLE_DISABLE, lisp_gpe_enable_disable)                     \
_(LISP_ENABLE_DISABLE, lisp_enable_disable)                             \
_(LISP_GPE_ADD_DEL_IFACE, lisp_gpe_add_del_iface)                       \
_(LISP_ADD_DEL_REMOTE_MAPPING, lisp_add_del_remote_mapping)             \
_(LISP_ADD_DEL_ADJACENCY, lisp_add_del_adjacency)                       \
_(LISP_PITR_SET_LOCATOR_SET, lisp_pitr_set_locator_set)                 \
_(LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map)               \
_(LISP_LOCATOR_SET_DUMP, lisp_locator_set_dump)                         \
_(LISP_LOCATOR_DUMP, lisp_locator_dump)                                 \
_(LISP_EID_TABLE_DUMP, lisp_eid_table_dump)                             \
_(LISP_GPE_TUNNEL_DUMP, lisp_gpe_tunnel_dump)                           \
_(LISP_MAP_RESOLVER_DUMP, lisp_map_resolver_dump)                       \
_(LISP_EID_TABLE_MAP_DUMP, lisp_eid_table_map_dump)                     \
_(SHOW_LISP_STATUS, show_lisp_status)                                   \
_(LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS,                                   \
  lisp_add_del_map_request_itr_rlocs)                                   \
_(LISP_GET_MAP_REQUEST_ITR_RLOCS, lisp_get_map_request_itr_rlocs)       \
_(SHOW_LISP_PITR, show_lisp_pitr)                                       \
_(SR_MULTICAST_MAP_ADD_DEL, sr_multicast_map_add_del)                   \
_(AF_PACKET_CREATE, af_packet_create)                                   \
_(AF_PACKET_DELETE, af_packet_delete)                                   \
_(POLICER_ADD_DEL, policer_add_del)                                     \
_(POLICER_DUMP, policer_dump)                                           \
_(POLICER_CLASSIFY_SET_INTERFACE, policer_classify_set_interface)       \
_(POLICER_CLASSIFY_DUMP, policer_classify_dump)                         \
_(NETMAP_CREATE, netmap_create)                                         \
_(NETMAP_DELETE, netmap_delete)                                         \
_(MPLS_GRE_TUNNEL_DUMP, mpls_gre_tunnel_dump)                           \
_(MPLS_GRE_TUNNEL_DETAILS, mpls_gre_tunnel_details)                     \
_(MPLS_ETH_TUNNEL_DUMP, mpls_eth_tunnel_dump)                           \
_(MPLS_ETH_TUNNEL_DETAILS, mpls_eth_tunnel_details)                     \
_(MPLS_FIB_ENCAP_DUMP, mpls_fib_encap_dump)                             \
_(MPLS_FIB_ENCAP_DETAILS, mpls_fib_encap_details)                       \
_(MPLS_FIB_DECAP_DUMP, mpls_fib_decap_dump)                             \
_(MPLS_FIB_DECAP_DETAILS, mpls_fib_decap_details)                       \
_(CLASSIFY_TABLE_IDS,classify_table_ids)                                \
_(CLASSIFY_TABLE_BY_INTERFACE, classify_table_by_interface)             \
_(CLASSIFY_TABLE_INFO,classify_table_info)                              \
_(CLASSIFY_SESSION_DUMP,classify_session_dump)                          \
_(CLASSIFY_SESSION_DETAILS,classify_session_details)                    \
_(IPFIX_ENABLE,ipfix_enable)                                            \
_(IPFIX_DUMP,ipfix_dump)                                                \
_(GET_NEXT_INDEX, get_next_index)                                       \
_(PG_CREATE_INTERFACE, pg_create_interface)                             \
_(PG_CAPTURE, pg_capture)                                               \
_(PG_ENABLE_DISABLE, pg_enable_disable)                                 \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL,                               \
  ip_source_and_port_range_check_add_del)                               \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL,                     \
  ip_source_and_port_range_check_interface_add_del)

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)

#define foreach_registration_hash               \
_(interface_events)                             \
_(to_netconf_server)                            \
_(from_netconf_server)                          \
_(to_netconf_client)                            \
_(from_netconf_client)                          \
_(oam_events)

typedef enum
{
  RESOLVE_IP4_ADD_DEL_ROUTE = 1,
  RESOLVE_IP6_ADD_DEL_ROUTE,
  RESOLVE_MPLS_ETHERNET_ADD_DEL,
} resolve_t;

typedef struct
{
  u8 resolve_type;
  union
  {
    vl_api_ip_add_del_route_t r;
    vl_api_mpls_ethernet_add_del_tunnel_2_t t;
  };
} pending_route_t;

typedef struct
{

#define _(a) uword *a##_registration_hash;              \
    vpe_client_registration_t * a##_registrations;
  foreach_registration_hash
#undef _
    /* notifications happen really early in the game */
  u8 link_state_process_up;

  /* ip4 pending route adds */
  pending_route_t *pending_routes;

  /* ip4 arp event registration pool */
  vl_api_ip4_arp_event_t *arp_events;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vpe_api_main_t;

static vlib_node_registration_t vpe_resolver_process_node;
static vpe_api_main_t vpe_api_main;

static void send_sw_interface_flags (vpe_api_main_t * am,
				     unix_shared_memory_queue_t * q,
				     vnet_sw_interface_t * swif);
static void send_sw_interface_flags_deleted (vpe_api_main_t * am,
					     unix_shared_memory_queue_t * q,
					     u32 sw_if_index);

static int arp_change_delete_callback (u32 pool_index, u8 * notused);


/* Clean up all registrations belonging to the indicated client */
int
vl_api_memclnt_delete_callback (u32 client_index)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vpe_client_registration_t *rp;
  uword *p;
  int stats_memclnt_delete_callback (u32 client_index);

  stats_memclnt_delete_callback (client_index);

#define _(a)                                                    \
    p = hash_get (vam->a##_registration_hash, client_index);    \
    if (p) {                                                    \
        rp = pool_elt_at_index (vam->a##_registrations, p[0]);  \
        pool_put (vam->a##_registrations, rp);                  \
        hash_unset (vam->a##_registration_hash, client_index);  \
    }
  foreach_registration_hash;
#undef _
  return 0;
}

#define API_LINK_STATE_EVENT 1
#define API_ADMIN_UP_DOWN_EVENT 2

static int
event_data_cmp (void *a1, void *a2)
{
  uword *e1 = a1;
  uword *e2 = a2;

  return (word) e1[0] - (word) e2[0];
}

static uword
link_state_process (vlib_main_t * vm,
		    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_main_t *vnm = vam->vnet_main;
  vnet_sw_interface_t *swif;
  uword *event_data = 0;
  vpe_client_registration_t *reg;
  int i;
  u32 prev_sw_if_index;
  unix_shared_memory_queue_t *q;

  vam->link_state_process_up = 1;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      /* Unified list of changed link or admin state sw_if_indices */
      vlib_process_get_events_with_type
	(vm, &event_data, API_LINK_STATE_EVENT);
      vlib_process_get_events_with_type
	(vm, &event_data, API_ADMIN_UP_DOWN_EVENT);

      /* Sort, so we can eliminate duplicates */
      vec_sort_with_function (event_data, event_data_cmp);

      prev_sw_if_index = ~0;

      for (i = 0; i < vec_len (event_data); i++)
	{
	  /* Only one message per swif */
	  if (prev_sw_if_index == event_data[i])
	    continue;
	  prev_sw_if_index = event_data[i];

          /* *INDENT-OFF* */
          pool_foreach(reg, vam->interface_events_registrations,
          ({
            q = vl_api_client_index_to_input_queue (reg->client_index);
            if (q)
              {
                /* sw_interface may be deleted already */
                if (!pool_is_free_index (vnm->interface_main.sw_interfaces,
                                         event_data[i]))
                  {
                    swif = vnet_get_sw_interface (vnm, event_data[i]);
                    send_sw_interface_flags (vam, q, swif);
                  }
              }
          }));
          /* *INDENT-ON* */
	}
      vec_reset_length (event_data);
    }

  return 0;
}

static clib_error_t *link_up_down_function (vnet_main_t * vm, u32 hw_if_index,
					    u32 flags);
static clib_error_t *admin_up_down_function (vnet_main_t * vm,
					     u32 hw_if_index, u32 flags);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (link_state_process_node,static) = {
  .function = link_state_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vpe-link-state-process",
};
/* *INDENT-ON* */

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (admin_up_down_function);
VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (link_up_down_function);

static clib_error_t *
link_up_down_function (vnet_main_t * vm, u32 hw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vm, hw_if_index);

  if (vam->link_state_process_up)
    vlib_process_signal_event (vam->vlib_main,
			       link_state_process_node.index,
			       API_LINK_STATE_EVENT, hi->sw_if_index);
  return 0;
}

static clib_error_t *
admin_up_down_function (vnet_main_t * vm, u32 sw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;

  /*
   * Note: it's perfectly fair to set a subif admin up / admin down.
   * Note the subtle distinction between this routine and the previous
   * routine.
   */
  if (vam->link_state_process_up)
    vlib_process_signal_event (vam->vlib_main,
			       link_state_process_node.index,
			       API_ADMIN_UP_DOWN_EVENT, sw_if_index);
  return 0;
}

#define pub_sub_handler(lca,UCA)                                        \
static void vl_api_want_##lca##_t_handler (                             \
    vl_api_want_##lca##_t *mp)                                          \
{                                                                       \
    vpe_api_main_t *vam = &vpe_api_main;                                \
    vpe_client_registration_t *rp;                                      \
    vl_api_want_##lca##_reply_t *rmp;                                   \
    uword *p;                                                           \
    i32 rv = 0;                                                         \
                                                                        \
    p = hash_get (vam->lca##_registration_hash, mp->client_index);      \
    if (p) {                                                            \
        if (mp->enable_disable) {                                       \
            clib_warning ("pid %d: already enabled...", mp->pid);       \
            rv = VNET_API_ERROR_INVALID_REGISTRATION;                   \
            goto reply;                                                 \
        } else {                                                        \
            rp = pool_elt_at_index (vam->lca##_registrations, p[0]);    \
            pool_put (vam->lca##_registrations, rp);                    \
            hash_unset (vam->lca##_registration_hash,                   \
                mp->client_index);                                      \
            goto reply;                                                 \
        }                                                               \
    }                                                                   \
    if (mp->enable_disable == 0) {                                      \
        clib_warning ("pid %d: already disabled...", mp->pid);          \
        rv = VNET_API_ERROR_INVALID_REGISTRATION;                       \
        goto reply;                                                     \
    }                                                                   \
    pool_get (vam->lca##_registrations, rp);                            \
    rp->client_index = mp->client_index;                                \
    rp->client_pid = mp->pid;                                           \
    hash_set (vam->lca##_registration_hash, rp->client_index,           \
              rp - vam->lca##_registrations);                           \
                                                                        \
reply:                                                                  \
    REPLY_MACRO (VL_API_WANT_##UCA##_REPLY);                            \
}

pub_sub_handler (interface_events, INTERFACE_EVENTS)
pub_sub_handler (oam_events, OAM_EVENTS)
#define RESOLUTION_EVENT 1
#define RESOLUTION_PENDING_EVENT 2
#define IP4_ARP_EVENT 3
     static int ip4_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);
     static int ip6_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);
     static int mpls_ethernet_add_del_tunnel_2_t_handler
       (vl_api_mpls_ethernet_add_del_tunnel_2_t * mp);

     void handle_ip4_arp_event (u32 pool_index)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_main_t *vnm = vam->vnet_main;
  vlib_main_t *vm = vam->vlib_main;
  vl_api_ip4_arp_event_t *event;
  vl_api_ip4_arp_event_t *mp;
  unix_shared_memory_queue_t *q;

  /* Client can cancel, die, etc. */
  if (pool_is_free_index (vam->arp_events, pool_index))
    return;

  event = pool_elt_at_index (vam->arp_events, pool_index);

  q = vl_api_client_index_to_input_queue (event->client_index);
  if (!q)
    {
      (void) vnet_add_del_ip4_arp_change_event
	(vnm, arp_change_delete_callback,
	 event->pid, &event->address,
	 vpe_resolver_process_node.index, IP4_ARP_EVENT,
	 ~0 /* pool index, notused */ , 0 /* is_add */ );
      return;
    }

  if (q->cursize < q->maxsize)
    {
      mp = vl_msg_api_alloc (sizeof (*mp));
      clib_memcpy (mp, event, sizeof (*mp));
      vl_msg_api_send_shmem (q, (u8 *) & mp);
    }
  else
    {
      static f64 last_time;
      /*
       * Throttle syslog msgs.
       * It's pretty tempting to just revoke the registration...
       */
      if (vlib_time_now (vm) > last_time + 10.0)
	{
	  clib_warning ("arp event for %U to pid %d: queue stuffed!",
			format_ip4_address, &event->address, event->pid);
	  last_time = vlib_time_now (vm);
	}
    }
}

static uword
resolver_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword event_type;
  uword *event_data = 0;
  f64 timeout = 100.0;
  vpe_api_main_t *vam = &vpe_api_main;
  pending_route_t *pr;
  vl_api_ip_add_del_route_t *adr;
  vl_api_mpls_ethernet_add_del_tunnel_2_t *pme;
  u32 *resolution_failures = 0;
  int i, rv;
  clib_error_t *e;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case RESOLUTION_PENDING_EVENT:
	  timeout = 1.0;
	  break;

	case RESOLUTION_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      /*
	       * Resolution events can occur long after the
	       * original request has timed out. $$$ add a cancel
	       * mechanism..
	       */
	      if (pool_is_free_index (vam->pending_routes, event_data[i]))
		continue;

	      pr = pool_elt_at_index (vam->pending_routes, event_data[i]);
	      adr = &pr->r;
	      pme = &pr->t;

	      switch (pr->resolve_type)
		{
		case RESOLVE_IP4_ADD_DEL_ROUTE:
		  rv = ip4_add_del_route_t_handler (adr);
		  clib_warning ("resolver: add %U/%d via %U %s",
				format_ip4_address,
				(ip4_address_t *) & (adr->dst_address),
				adr->dst_address_length,
				format_ip4_address,
				(ip4_address_t *) & (adr->next_hop_address),
				(rv >= 0) ? "succeeded" : "failed");
		  break;

		case RESOLVE_IP6_ADD_DEL_ROUTE:
		  rv = ip6_add_del_route_t_handler (adr);
		  clib_warning ("resolver: add %U/%d via %U %s",
				format_ip6_address,
				(ip6_address_t *) & (adr->dst_address),
				adr->dst_address_length,
				format_ip6_address,
				(ip6_address_t *) & (adr->next_hop_address),
				(rv >= 0) ? "succeeded" : "failed");
		  break;

		case RESOLVE_MPLS_ETHERNET_ADD_DEL:
		  rv = mpls_ethernet_add_del_tunnel_2_t_handler (pme);
		  clib_warning ("resolver: add mpls-o-e via %U %s",
				format_ip4_address,
				(ip4_address_t *) &
				(pme->next_hop_ip4_address_in_outer_vrf),
				(rv >= 0) ? "succeeded" : "failed");
		  break;

		default:
		  clib_warning ("resolver: BOGUS TYPE %d", pr->resolve_type);
		}
	      pool_put (vam->pending_routes, pr);
	    }
	  break;

	case IP4_ARP_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_ip4_arp_event (event_data[i]);
	  break;

	case ~0:		/* timeout, retry pending resolutions */
          /* *INDENT-OFF* */
          pool_foreach (pr, vam->pending_routes,
          ({
            int is_adr = 1;
            adr = &pr->r;
            pme = &pr->t;

            /* May fail, e.g. due to interface down */
            switch (pr->resolve_type)
              {
              case RESOLVE_IP4_ADD_DEL_ROUTE:
                e = ip4_probe_neighbor
                  (vm, (ip4_address_t *)&(adr->next_hop_address),
                   ntohl(adr->next_hop_sw_if_index));
                break;

              case RESOLVE_IP6_ADD_DEL_ROUTE:
                e = ip6_probe_neighbor
                  (vm, (ip6_address_t *)&(adr->next_hop_address),
                   ntohl(adr->next_hop_sw_if_index));
                break;

              case RESOLVE_MPLS_ETHERNET_ADD_DEL:
                is_adr = 0;
                e = ip4_probe_neighbor
                  (vm,
                   (ip4_address_t *)&(pme->next_hop_ip4_address_in_outer_vrf),
                   pme->resolve_opaque);
                break;

              default:
                e = clib_error_return (0, "resolver: BOGUS TYPE %d",
                                       pr->resolve_type);
              }
            if (e)
              {
                clib_error_report (e);
                if (is_adr)
                  adr->resolve_attempts = 1;
                else
                  pme->resolve_attempts = 1;
              }
            if (is_adr)
              {
                adr->resolve_attempts -= 1;
                if (adr->resolve_attempts == 0)
                  vec_add1 (resolution_failures,
                            pr - vam->pending_routes);
              }
            else
              {
                pme->resolve_attempts -= 1;
                if (pme->resolve_attempts == 0)
                  vec_add1 (resolution_failures,
                            pr - vam->pending_routes);
              }
          }));
          /* *INDENT-ON* */
	  for (i = 0; i < vec_len (resolution_failures); i++)
	    {
	      pr = pool_elt_at_index (vam->pending_routes,
				      resolution_failures[i]);
	      adr = &pr->r;
	      pme = &pr->t;

	      switch (pr->resolve_type)
		{
		case RESOLVE_IP4_ADD_DEL_ROUTE:
		  clib_warning ("resolver: add %U/%d via %U retry failure",
				format_ip4_address,
				(ip4_address_t *) & (adr->dst_address),
				adr->dst_address_length,
				format_ip4_address,
				(ip4_address_t *) & (adr->next_hop_address));
		  break;

		case RESOLVE_IP6_ADD_DEL_ROUTE:
		  clib_warning ("resolver: add %U/%d via %U retry failure",
				format_ip6_address,
				(ip6_address_t *) & (adr->dst_address),
				adr->dst_address_length,
				format_ip6_address,
				(ip6_address_t *) & (adr->next_hop_address));
		  break;

		case RESOLVE_MPLS_ETHERNET_ADD_DEL:
		  clib_warning ("resolver: add mpls-o-e via %U retry failure",
				format_ip4_address,
				(ip4_address_t *) &
				(pme->next_hop_ip4_address_in_outer_vrf));
		  break;

		default:
		  clib_warning ("BUG");
		}
	      pool_put (vam->pending_routes, pr);
	    }
	  vec_reset_length (resolution_failures);
	  break;
	}
      if (pool_elts (vam->pending_routes) == 0)
	timeout = 100.0;
      vec_reset_length (event_data);
    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vpe_resolver_process_node,static) = {
  .function = resolver_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vpe-route-resolver-process",
};
/* *INDENT-ON* */

static int
ip4_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  stats_main_t *sm = &stats_main;
  ip4_add_del_route_args_t a;
  ip4_address_t next_hop_address;
  u32 fib_index;
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_main_t *vnm = vam->vnet_main;
  vlib_main_t *vm = vlib_get_main ();
  pending_route_t *pr;
  vl_api_ip_add_del_route_t *adr;
  uword *p;
  clib_error_t *e;
  u32 ai;
  ip_adjacency_t *adj;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->vrf_id));
  if (!p)
    {
      if (mp->create_vrf_if_needed)
	{
	  ip4_fib_t *f;
	  f = find_ip4_fib_by_table_index_or_id (im, ntohl (mp->vrf_id),
						 0 /* flags */ );
	  fib_index = f->index;
	}
      else
	{
	  /* No such VRF, and we weren't asked to create one */
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}
    }
  else
    {
      fib_index = p[0];
    }

  if (~0 != mp->next_hop_sw_if_index &&
      pool_is_free_index (vnm->interface_main.sw_interfaces,
			  ntohl (mp->next_hop_sw_if_index)))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  clib_memcpy (next_hop_address.data, mp->next_hop_address,
	       sizeof (next_hop_address.data));

  /* Arp for the next_hop if necessary */
  if (mp->is_add && mp->resolve_if_needed && ~0 != mp->next_hop_sw_if_index)
    {
      u32 lookup_result;
      ip_adjacency_t *adj;

      lookup_result = ip4_fib_lookup_with_table
	(im, fib_index, &next_hop_address, 1 /* disable default route */ );

      adj = ip_get_adjacency (lm, lookup_result);

      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	{
	  pool_get (vam->pending_routes, pr);
	  pr->resolve_type = RESOLVE_IP4_ADD_DEL_ROUTE;
	  adr = &pr->r;
	  clib_memcpy (adr, mp, sizeof (*adr));
	  /* recursion block, "just in case" */
	  adr->resolve_if_needed = 0;
	  adr->resolve_attempts = ntohl (mp->resolve_attempts);
	  vnet_register_ip4_arp_resolution_event
	    (vnm, &next_hop_address, vpe_resolver_process_node.index,
	     RESOLUTION_EVENT, pr - vam->pending_routes);

	  vlib_process_signal_event
	    (vm, vpe_resolver_process_node.index,
	     RESOLUTION_PENDING_EVENT, 0 /* data */ );

	  /* The interface may be down, etc. */
	  e = ip4_probe_neighbor
	    (vm, (ip4_address_t *) & (mp->next_hop_address),
	     ntohl (mp->next_hop_sw_if_index));

	  if (e)
	    clib_error_report (e);

	  return VNET_API_ERROR_IN_PROGRESS;
	}
    }

  if (mp->is_multipath)
    {
      u32 flags;

      dslock (sm, 1 /* release hint */ , 10 /* tag */ );

      if (mp->is_add)
	flags = IP4_ROUTE_FLAG_ADD;
      else
	flags = IP4_ROUTE_FLAG_DEL;

      if (mp->not_last)
	flags |= IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP;

      ip4_add_del_route_next_hop (im, flags,
				  (ip4_address_t *) mp->dst_address,
				  (u32) mp->dst_address_length,
				  (ip4_address_t *) mp->next_hop_address,
				  ntohl (mp->next_hop_sw_if_index),
				  (u32) mp->next_hop_weight,
				  ~0 /* adj_index */ ,
				  fib_index);
      dsunlock (sm);
      return 0;
    }

  memset (&a, 0, sizeof (a));
  clib_memcpy (a.dst_address.data, mp->dst_address,
	       sizeof (a.dst_address.data));

  a.dst_address_length = mp->dst_address_length;

  a.flags = (mp->is_add ? IP4_ROUTE_FLAG_ADD : IP4_ROUTE_FLAG_DEL);
  a.flags |= IP4_ROUTE_FLAG_FIB_INDEX;
  a.table_index_or_table_id = fib_index;
  a.add_adj = 0;
  a.n_add_adj = 0;

  if (mp->not_last)
    a.flags |= IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP;

  dslock (sm, 1 /* release hint */ , 2 /* tag */ );

  if (mp->is_add)
    {
      if (mp->is_drop)
	ai = lm->drop_adj_index;
      else if (mp->is_local)
	ai = lm->local_adj_index;
      else if (mp->is_classify)
	{
	  if (pool_is_free_index
	      (cm->tables, ntohl (mp->classify_table_index)))
	    {
	      dsunlock (sm);
	      return VNET_API_ERROR_NO_SUCH_TABLE;
	    }
	  adj = ip_add_adjacency (lm,
				  /* template */ 0,
				  /* block size */ 1,
				  &ai);

	  adj->lookup_next_index = IP_LOOKUP_NEXT_CLASSIFY;
	  adj->classify.table_index = ntohl (mp->classify_table_index);
	}
      else if (mp->lookup_in_vrf)
	{
	  p = hash_get (im->fib_index_by_table_id, ntohl (mp->lookup_in_vrf));
	  if (p)
	    {
	      adj = ip_add_adjacency (lm,
				      /* template */ 0,
				      /* block size */ 1,
				      &ai);
	      adj->explicit_fib_index = p[0];
	    }
	  else
	    {
	      dsunlock (sm);
	      return VNET_API_ERROR_NO_SUCH_INNER_FIB;
	    }
	}
      else
	ai = ip4_route_get_next_hop_adj (im,
					 fib_index,
					 &next_hop_address,
					 ntohl (mp->next_hop_sw_if_index),
					 fib_index);

      if (ai == lm->miss_adj_index)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_NO_SUCH_INNER_FIB;
	}
    }
  else
    {
      ip_adjacency_t *adj;
      int disable_default_route = 1;

      /* Trying to delete the default route? */
      if (a.dst_address.as_u32 == 0 && a.dst_address_length == 0)
	disable_default_route = 0;

      ai = ip4_fib_lookup_with_table
	(im, fib_index, &a.dst_address, disable_default_route);
      if (ai == lm->miss_adj_index)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_UNKNOWN_DESTINATION;
	}

      adj = ip_get_adjacency (lm, ai);
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_ADDRESS_MATCHES_INTERFACE_ADDRESS;
	}
    }

  a.adj_index = ai;
  ip4_add_del_route (im, &a);

  dsunlock (sm);
  return 0;
}

static int
ip6_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vpe_api_main_t *vam = &vpe_api_main;
  stats_main_t *sm = &stats_main;
  ip6_add_del_route_args_t a;
  ip6_address_t next_hop_address;
  pending_route_t *pr;
  vl_api_ip_add_del_route_t *adr;

  u32 fib_index;
  uword *p;
  clib_error_t *e;
  ip_adjacency_t *adj = 0;
  u32 ai;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->vrf_id));

  if (!p)
    {
      if (mp->create_vrf_if_needed)
	{
	  ip6_fib_t *f;
	  f = find_ip6_fib_by_table_index_or_id (im, ntohl (mp->vrf_id),
						 0 /* flags */ );
	  fib_index = f->index;
	}
      else
	{
	  /* No such VRF, and we weren't asked to create one */
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}
    }
  else
    {
      fib_index = p[0];
    }

  if (~0 != mp->next_hop_sw_if_index &&
      pool_is_free_index (vnm->interface_main.sw_interfaces,
			  ntohl (mp->next_hop_sw_if_index)))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  clib_memcpy (next_hop_address.as_u8, mp->next_hop_address,
	       sizeof (next_hop_address.as_u8));

  /* Arp for the next_hop if necessary */
  if (mp->is_add && mp->resolve_if_needed && ~0 != mp->next_hop_sw_if_index)
    {
      u32 lookup_result;
      ip_adjacency_t *adj;

      lookup_result = ip6_fib_lookup_with_table
	(im, fib_index, &next_hop_address);

      adj = ip_get_adjacency (lm, lookup_result);

      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	{
	  pool_get (vam->pending_routes, pr);
	  adr = &pr->r;
	  pr->resolve_type = RESOLVE_IP6_ADD_DEL_ROUTE;
	  clib_memcpy (adr, mp, sizeof (*adr));
	  /* recursion block, "just in case" */
	  adr->resolve_if_needed = 0;
	  adr->resolve_attempts = ntohl (mp->resolve_attempts);
	  vnet_register_ip6_neighbor_resolution_event
	    (vnm, &next_hop_address, vpe_resolver_process_node.index,
	     RESOLUTION_EVENT, pr - vam->pending_routes);

	  vlib_process_signal_event
	    (vm, vpe_resolver_process_node.index,
	     RESOLUTION_PENDING_EVENT, 0 /* data */ );

	  /* The interface may be down, etc. */
	  e = ip6_probe_neighbor
	    (vm, (ip6_address_t *) & (mp->next_hop_address),
	     ntohl (mp->next_hop_sw_if_index));

	  if (e)
	    clib_error_report (e);

	  return VNET_API_ERROR_IN_PROGRESS;
	}
    }

  if (mp->is_multipath)
    {
      u32 flags;

      dslock (sm, 1 /* release hint */ , 11 /* tag */ );

      if (mp->is_add)
	flags = IP6_ROUTE_FLAG_ADD;
      else
	flags = IP6_ROUTE_FLAG_DEL;

      if (mp->not_last)
	flags |= IP6_ROUTE_FLAG_NOT_LAST_IN_GROUP;

      ip6_add_del_route_next_hop (im, flags,
				  (ip6_address_t *) mp->dst_address,
				  (u32) mp->dst_address_length,
				  (ip6_address_t *) mp->next_hop_address,
				  ntohl (mp->next_hop_sw_if_index),
				  (u32) mp->next_hop_weight,
				  ~0 /* adj_index */ ,
				  fib_index);
      dsunlock (sm);
      return 0;
    }

  memset (&a, 0, sizeof (a));
  clib_memcpy (a.dst_address.as_u8, mp->dst_address,
	       sizeof (a.dst_address.as_u8));

  a.dst_address_length = mp->dst_address_length;

  a.flags = (mp->is_add ? IP6_ROUTE_FLAG_ADD : IP6_ROUTE_FLAG_DEL);
  a.flags |= IP6_ROUTE_FLAG_FIB_INDEX;
  a.table_index_or_table_id = fib_index;
  a.add_adj = 0;
  a.n_add_adj = 0;

  if (mp->not_last)
    a.flags |= IP6_ROUTE_FLAG_NOT_LAST_IN_GROUP;

  dslock (sm, 1 /* release hint */ , 3 /* tag */ );

  if (mp->is_add)
    {
      if (mp->is_drop)
	ai = lm->drop_adj_index;
      else if (mp->is_local)
	ai = lm->local_adj_index;
      else if (mp->lookup_in_vrf)
	{
	  p = hash_get (im->fib_index_by_table_id, ntohl (mp->lookup_in_vrf));
	  if (p)
	    {
	      adj = ip_add_adjacency (lm,
				      /* template */ 0,
				      /* block size */ 1,
				      &ai);
	      adj->explicit_fib_index = p[0];
	    }
	  else
	    {
	      dsunlock (sm);
	      return VNET_API_ERROR_NO_SUCH_INNER_FIB;
	    }
	}
      else
	ai = ip6_route_get_next_hop_adj (im,
					 fib_index,
					 &next_hop_address,
					 ntohl (mp->next_hop_sw_if_index),
					 fib_index);
      if (ai == lm->miss_adj_index)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;
	}
    }
  else
    {
      ip_adjacency_t *adj;

      ai = ip6_fib_lookup_with_table (im, fib_index, &a.dst_address);
      if (ai == lm->miss_adj_index)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_UNKNOWN_DESTINATION;
	}
      adj = ip_get_adjacency (lm, ai);
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	{
	  dsunlock (sm);
	  return VNET_API_ERROR_ADDRESS_MATCHES_INTERFACE_ADDRESS;
	}
    }

  a.adj_index = ai;
  ip6_add_del_route (im, &a);

  dsunlock (sm);
  return 0;
}

void
vl_api_ip_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp)
{
  vl_api_ip_add_del_route_reply_t *rmp;
  int rv;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  if (mp->is_ipv6)
    rv = ip6_add_del_route_t_handler (mp);
  else
    rv = ip4_add_del_route_t_handler (mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_IP_ADD_DEL_ROUTE_REPLY);
}

void
api_config_default_ip_route (u8 is_ipv6, u8 is_add, u32 vrf_id,
			     u32 sw_if_index, u8 * next_hop_addr)
{
  vl_api_ip_add_del_route_t mp;
  int rv;

  memset (&mp, 0, sizeof (vl_api_ip_add_del_route_t));

  /*
   * Configure default IP route:
   *  - ip route add 0.0.0.0/1 via <GW IP>
   *  - ip route add 128.0.0.0/1 via <GW IP>
   */
  mp.next_hop_sw_if_index = ntohl (sw_if_index);
  mp.vrf_id = vrf_id;
  mp.resolve_attempts = ~0;
  mp.resolve_if_needed = 1;
  mp.is_add = is_add;
  mp.is_ipv6 = is_ipv6;
  mp.next_hop_weight = 1;

  clib_memcpy (&mp.next_hop_address[0], next_hop_addr, 16);

  if (is_ipv6)
    rv = ip6_add_del_route_t_handler (&mp);
  else
    {
      mp.dst_address_length = 1;

      mp.dst_address[0] = 0;
      rv = ip4_add_del_route_t_handler (&mp);

      mp.dst_address[0] = 128;
      rv |= ip4_add_del_route_t_handler (&mp);
    }

  if (rv)
    clib_error_return (0, "failed to config default IP route");

}

static void
  vl_api_sw_interface_add_del_address_t_handler
  (vl_api_sw_interface_add_del_address_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_add_del_address_reply_t *rmp;
  int rv = 0;
  u32 is_del;

  VALIDATE_SW_IF_INDEX (mp);

  is_del = mp->is_add == 0;

  if (mp->del_all)
    ip_del_all_interface_addresses (vm, ntohl (mp->sw_if_index));
  else if (mp->is_ipv6)
    ip6_add_del_interface_address (vm, ntohl (mp->sw_if_index),
				   (void *) mp->address,
				   mp->address_length, is_del);
  else
    ip4_add_del_interface_address (vm, ntohl (mp->sw_if_index),
				   (void *) mp->address,
				   mp->address_length, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY);
}

static void
vl_api_sw_interface_set_table_t_handler (vl_api_sw_interface_set_table_t * mp)
{
  int rv = 0;
  u32 table_id = ntohl (mp->vrf_id);
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_sw_interface_set_table_reply_t *rmp;
  stats_main_t *sm = &stats_main;

  VALIDATE_SW_IF_INDEX (mp);

  dslock (sm, 1 /* release hint */ , 4 /* tag */ );

  if (mp->is_ipv6)
    {
      ip6_main_t *im = &ip6_main;
      ip6_fib_t *fib = find_ip6_fib_by_table_index_or_id (im, table_id,
							  IP6_ROUTE_FLAG_TABLE_ID);
      if (fib)
	{
	  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
	  im->fib_index_by_sw_if_index[sw_if_index] = fib->index;
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	}
    }
  else
    {
      ip4_main_t *im = &ip4_main;
      ip4_fib_t *fib = find_ip4_fib_by_table_index_or_id
	(im, table_id, IP4_ROUTE_FLAG_TABLE_ID);

      /* Truthfully this can't fail */
      if (fib)
	{
	  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
	  im->fib_index_by_sw_if_index[sw_if_index] = fib->index;
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	}
    }
  dsunlock (sm);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

static void
vl_api_sw_interface_set_vpath_t_handler (vl_api_sw_interface_set_vpath_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  vl_api_sw_interface_set_vpath_reply_t *rmp;
  int rv = 0;
  u32 ci;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  ip4_main_t *ip4m = &ip4_main;
  ip6_main_t *ip6m = &ip6_main;
  ip_lookup_main_t *ip4lm = &ip4m->lookup_main;
  ip_lookup_main_t *ip6lm = &ip6m->lookup_main;
  ip_config_main_t *rx_cm4u = &ip4lm->rx_config_mains[VNET_UNICAST];
  ip_config_main_t *rx_cm4m = &ip4lm->rx_config_mains[VNET_MULTICAST];
  ip_config_main_t *rx_cm6u = &ip6lm->rx_config_mains[VNET_UNICAST];
  ip_config_main_t *rx_cm6m = &ip6lm->rx_config_mains[VNET_MULTICAST];

  VALIDATE_SW_IF_INDEX (mp);

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_VPATH, mp->enable);
  if (mp->enable)
    {
      ci = rx_cm4u->config_index_by_sw_if_index[sw_if_index];	//IP4 unicast
      ci = vnet_config_add_feature (vm, &rx_cm4u->config_main,
				    ci,
				    im4->ip4_unicast_rx_feature_vpath, 0, 0);
      rx_cm4u->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm4m->config_index_by_sw_if_index[sw_if_index];	//IP4 mcast
      ci = vnet_config_add_feature (vm, &rx_cm4m->config_main,
				    ci,
				    im4->ip4_multicast_rx_feature_vpath,
				    0, 0);
      rx_cm4m->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm6u->config_index_by_sw_if_index[sw_if_index];	//IP6 unicast
      ci = vnet_config_add_feature (vm, &rx_cm6u->config_main,
				    ci,
				    im6->ip6_unicast_rx_feature_vpath, 0, 0);
      rx_cm6u->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm6m->config_index_by_sw_if_index[sw_if_index];	//IP6 mcast
      ci = vnet_config_add_feature (vm, &rx_cm6m->config_main,
				    ci,
				    im6->ip6_multicast_rx_feature_vpath,
				    0, 0);
      rx_cm6m->config_index_by_sw_if_index[sw_if_index] = ci;
    }
  else
    {
      ci = rx_cm4u->config_index_by_sw_if_index[sw_if_index];	//IP4 unicast
      ci = vnet_config_del_feature (vm, &rx_cm4u->config_main,
				    ci,
				    im4->ip4_unicast_rx_feature_vpath, 0, 0);
      rx_cm4u->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm4m->config_index_by_sw_if_index[sw_if_index];	//IP4 mcast
      ci = vnet_config_del_feature (vm, &rx_cm4m->config_main,
				    ci,
				    im4->ip4_multicast_rx_feature_vpath,
				    0, 0);
      rx_cm4m->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm6u->config_index_by_sw_if_index[sw_if_index];	//IP6 unicast
      ci = vnet_config_del_feature (vm, &rx_cm6u->config_main,
				    ci,
				    im6->ip6_unicast_rx_feature_vpath, 0, 0);
      rx_cm6u->config_index_by_sw_if_index[sw_if_index] = ci;
      ci = rx_cm6m->config_index_by_sw_if_index[sw_if_index];	//IP6 mcast
      ci = vnet_config_del_feature (vm, &rx_cm6m->config_main,
				    ci,
				    im6->ip6_multicast_rx_feature_vpath,
				    0, 0);
      rx_cm6m->config_index_by_sw_if_index[sw_if_index] = ci;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VPATH_REPLY);
}

static void
  vl_api_sw_interface_set_l2_xconnect_t_handler
  (vl_api_sw_interface_set_l2_xconnect_t * mp)
{
  vl_api_sw_interface_set_l2_xconnect_reply_t *rmp;
  int rv = 0;
  u32 rx_sw_if_index = ntohl (mp->rx_sw_if_index);
  u32 tx_sw_if_index = ntohl (mp->tx_sw_if_index);
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  VALIDATE_RX_SW_IF_INDEX (mp);

  if (mp->enable)
    {
      VALIDATE_TX_SW_IF_INDEX (mp);
      rv = set_int_l2_mode (vm, vnm, MODE_L2_XC,
			    rx_sw_if_index, 0, 0, 0, tx_sw_if_index);
    }
  else
    {
      rv = set_int_l2_mode (vm, vnm, MODE_L3, rx_sw_if_index, 0, 0, 0, 0);
    }

  BAD_RX_SW_IF_INDEX_LABEL;
  BAD_TX_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY);
}

static void
  vl_api_sw_interface_set_l2_bridge_t_handler
  (vl_api_sw_interface_set_l2_bridge_t * mp)
{
  bd_main_t *bdm = &bd_main;
  vl_api_sw_interface_set_l2_bridge_reply_t *rmp;
  int rv = 0;
  u32 rx_sw_if_index = ntohl (mp->rx_sw_if_index);
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 bvi = mp->bvi;
  u8 shg = mp->shg;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  VALIDATE_RX_SW_IF_INDEX (mp);

  bd_index = bd_find_or_add_bd_index (bdm, bd_id);

  if (mp->enable)
    {
      //VALIDATE_TX_SW_IF_INDEX(mp);
      rv = set_int_l2_mode (vm, vnm, MODE_L2_BRIDGE,
			    rx_sw_if_index, bd_index, bvi, shg, 0);
    }
  else
    {
      rv = set_int_l2_mode (vm, vnm, MODE_L3, rx_sw_if_index, 0, 0, 0, 0);
    }

  BAD_RX_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY);
}

static void
vl_api_bridge_domain_add_del_t_handler (vl_api_bridge_domain_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_domain_add_del_reply_t *rmp;
  int rv = 0;
  u32 enable_flags = 0, disable_flags = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;

  if (mp->is_add)
    {
      bd_index = bd_find_or_add_bd_index (bdm, bd_id);

      if (mp->flood)
	enable_flags |= L2_FLOOD;
      else
	disable_flags |= L2_FLOOD;

      if (mp->uu_flood)
	enable_flags |= L2_UU_FLOOD;
      else
	disable_flags |= L2_UU_FLOOD;

      if (mp->forward)
	enable_flags |= L2_FWD;
      else
	disable_flags |= L2_FWD;

      if (mp->arp_term)
	enable_flags |= L2_ARP_TERM;
      else
	disable_flags |= L2_ARP_TERM;

      if (mp->learn)
	enable_flags |= L2_LEARN;
      else
	disable_flags |= L2_LEARN;

      if (enable_flags)
	bd_set_flags (vm, bd_index, enable_flags, 1 /* enable */ );

      if (disable_flags)
	bd_set_flags (vm, bd_index, disable_flags, 0 /* disable */ );

    }
  else
    rv = bd_delete_bd_index (bdm, bd_id);

  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY);
}

static void
vl_api_bridge_domain_details_t_handler (vl_api_bridge_domain_details_t * mp)
{
  clib_warning ("BUG");
}

static void
  vl_api_bridge_domain_sw_if_details_t_handler
  (vl_api_bridge_domain_sw_if_details_t * mp)
{
  clib_warning ("BUG");
}

static void
send_bridge_domain_details (unix_shared_memory_queue_t * q,
			    l2_bridge_domain_t * bd_config,
			    u32 n_sw_ifs, u32 context)
{
  vl_api_bridge_domain_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BRIDGE_DOMAIN_DETAILS);
  mp->bd_id = ntohl (bd_config->bd_id);
  mp->flood = bd_feature_flood (bd_config);
  mp->uu_flood = bd_feature_uu_flood (bd_config);
  mp->forward = bd_feature_forward (bd_config);
  mp->learn = bd_feature_learn (bd_config);
  mp->arp_term = bd_feature_arp_term (bd_config);
  mp->bvi_sw_if_index = ntohl (bd_config->bvi_sw_if_index);
  mp->n_sw_ifs = ntohl (n_sw_ifs);
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_bd_sw_if_details (l2input_main_t * l2im,
		       unix_shared_memory_queue_t * q,
		       l2_flood_member_t * member, u32 bd_id, u32 context)
{
  vl_api_bridge_domain_sw_if_details_t *mp;
  l2_input_config_t *input_cfg;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BRIDGE_DOMAIN_SW_IF_DETAILS);
  mp->bd_id = ntohl (bd_id);
  mp->sw_if_index = ntohl (member->sw_if_index);
  input_cfg = vec_elt_at_index (l2im->configs, member->sw_if_index);
  mp->shg = input_cfg->shg;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bridge_domain_dump_t_handler (vl_api_bridge_domain_dump_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  unix_shared_memory_queue_t *q;
  l2_bridge_domain_t *bd_config;
  u32 bd_id, bd_index;
  u32 end;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (q == 0)
    return;

  bd_id = ntohl (mp->bd_id);

  bd_index = (bd_id == ~0) ? 0 : bd_find_or_add_bd_index (bdm, bd_id);
  end = (bd_id == ~0) ? vec_len (l2im->bd_configs) : bd_index + 1;
  for (; bd_index < end; bd_index++)
    {
      bd_config = l2input_bd_config_from_index (l2im, bd_index);
      /* skip dummy bd_id 0 */
      if (bd_config && (bd_config->bd_id > 0))
	{
	  u32 n_sw_ifs;
	  l2_flood_member_t *m;

	  n_sw_ifs = vec_len (bd_config->members);
	  send_bridge_domain_details (q, bd_config, n_sw_ifs, mp->context);

	  vec_foreach (m, bd_config->members)
	  {
	    send_bd_sw_if_details (l2im, q, m, bd_config->bd_id, mp->context);
	  }
	}
    }
}

static void
vl_api_l2fib_add_del_t_handler (vl_api_l2fib_add_del_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  vl_api_l2fib_add_del_reply_t *rmp;
  int rv = 0;
  u64 mac = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 static_mac;
  u32 filter_mac;
  u32 bvi_mac;
  uword *p;

  mac = mp->mac;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto bad_sw_if_index;
    }
  bd_index = p[0];

  if (mp->is_add)
    {
      VALIDATE_SW_IF_INDEX (mp);
      if (vec_len (l2im->configs) <= sw_if_index)
	{
	  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	  goto bad_sw_if_index;
	}
      else
	{
	  l2_input_config_t *config;
	  config = vec_elt_at_index (l2im->configs, sw_if_index);
	  if (config->bridge == 0)
	    {
	      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	      goto bad_sw_if_index;
	    }
	}
      static_mac = mp->static_mac ? 1 : 0;
      filter_mac = mp->filter_mac ? 1 : 0;
      bvi_mac = mp->bvi_mac ? 1 : 0;
      l2fib_add_entry (mac, bd_index, sw_if_index, static_mac, filter_mac,
		       bvi_mac);
    }
  else
    {
      l2fib_del_entry (mac, bd_index);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2FIB_ADD_DEL_REPLY);
}

static void
vl_api_l2_flags_t_handler (vl_api_l2_flags_t * mp)
{
  vl_api_l2_flags_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 flags = ntohl (mp->feature_bitmap);
  u32 rbm = 0;

  VALIDATE_SW_IF_INDEX (mp);

#define _(a,b) \
    if (flags & L2INPUT_FEAT_ ## a) \
        rbm = l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_ ## a, mp->is_set);
  foreach_l2input_feat;
#undef _

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_L2_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(rbm);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bridge_flags_t_handler (vl_api_bridge_flags_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_flags_reply_t *rmp;
  int rv = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 flags = ntohl (mp->feature_bitmap);
  uword *p;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }

  bd_index = p[0];

  bd_set_flags (vm, bd_index, flags, mp->is_set);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BRIDGE_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(flags);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bd_ip_mac_add_del_t_handler (vl_api_bd_ip_mac_add_del_t * mp)
{
  bd_main_t *bdm = &bd_main;
  vl_api_bd_ip_mac_add_del_reply_t *rmp;
  int rv = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  uword *p;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }

  bd_index = p[0];
  if (bd_add_del_ip_mac (bd_index, mp->ip_address,
			 mp->mac_address, mp->is_ipv6, mp->is_add))
    rv = VNET_API_ERROR_UNSPECIFIED;

out:
  REPLY_MACRO (VL_API_BD_IP_MAC_ADD_DEL_REPLY);
}

static void
vl_api_tap_connect_t_handler (vl_api_tap_connect_t * mp, vlib_main_t * vm)
{
  int rv;
  vl_api_tap_connect_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  u32 sw_if_index = (u32) ~ 0;

  rv = vnet_tap_connect_renumber (vm, mp->tap_name,
				  mp->use_random_mac ? 0 : mp->mac_address,
				  &sw_if_index, mp->renumber,
				  ntohl (mp->custom_dev_instance));

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_CONNECT_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->sw_if_index = ntohl (sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_tap_modify_t_handler (vl_api_tap_modify_t * mp, vlib_main_t * vm)
{
  int rv;
  vl_api_tap_modify_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  u32 sw_if_index = (u32) ~ 0;

  rv = vnet_tap_modify (vm, ntohl (mp->sw_if_index), mp->tap_name,
			mp->use_random_mac ? 0 : mp->mac_address,
			&sw_if_index, mp->renumber,
			ntohl (mp->custom_dev_instance));

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_MODIFY_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->sw_if_index = ntohl (sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_tap_delete_t_handler (vl_api_tap_delete_t * mp, vlib_main_t * vm)
{
  int rv;
  vpe_api_main_t *vam = &vpe_api_main;
  vl_api_tap_delete_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = vnet_tap_delete (vm, sw_if_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_DELETE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);

  if (!rv)
    send_sw_interface_flags_deleted (vam, q, sw_if_index);
}

static void
vl_api_create_vlan_subif_t_handler (vl_api_create_vlan_subif_t * mp)
{
  vl_api_create_vlan_subif_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index, sw_if_index = (u32) ~ 0;
  vnet_hw_interface_t *hi;
  int rv = 0;
  u32 id;
  vnet_sw_interface_t template;
  uword *p;
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 sup_and_sub_key;
  u64 *kp;
  unix_shared_memory_queue_t *q;
  clib_error_t *error;

  VALIDATE_SW_IF_INDEX (mp);

  hw_if_index = ntohl (mp->sw_if_index);
  hi = vnet_get_hw_interface (vnm, hw_if_index);

  id = ntohl (mp->vlan_id);
  if (id == 0 || id > 4095)
    {
      rv = VNET_API_ERROR_INVALID_VLAN;
      goto out;
    }

  sup_and_sub_key = ((u64) (hi->sw_if_index) << 32) | (u64) id;

  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
  if (p)
    {
      rv = VNET_API_ERROR_VLAN_ALREADY_EXISTS;
      goto out;
    }

  kp = clib_mem_alloc (sizeof (*kp));
  *kp = sup_and_sub_key;

  memset (&template, 0, sizeof (template));
  template.type = VNET_SW_INTERFACE_TYPE_SUB;
  template.sup_sw_if_index = hi->sw_if_index;
  template.sub.id = id;
  template.sub.eth.raw_flags = 0;
  template.sub.eth.flags.one_tag = 1;
  template.sub.eth.outer_vlan_id = id;
  template.sub.eth.flags.exact_match = 1;

  error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto out;
    }
  hash_set (hi->sub_interface_sw_if_index_by_id, id, sw_if_index);
  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

out:
  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CREATE_VLAN_SUBIF_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->sw_if_index = ntohl (sw_if_index);
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_create_subif_t_handler (vl_api_create_subif_t * mp)
{
  vl_api_create_subif_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv = 0;
  u32 sub_id;
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t template;
  uword *p;
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 sup_and_sub_key;
  u64 *kp;
  clib_error_t *error;

  VALIDATE_SW_IF_INDEX (mp);

  si = vnet_get_sup_sw_interface (vnm, ntohl (mp->sw_if_index));
  hi = vnet_get_sup_hw_interface (vnm, ntohl (mp->sw_if_index));

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    {
      rv = VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED;
      goto out;
    }

  sw_if_index = si->sw_if_index;
  sub_id = ntohl (mp->sub_id);

  sup_and_sub_key = ((u64) (sw_if_index) << 32) | (u64) sub_id;

  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
  if (p)
    {
      if (CLIB_DEBUG > 0)
	clib_warning ("sup sw_if_index %d, sub id %d already exists\n",
		      sw_if_index, sub_id);
      rv = VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
      goto out;
    }

  kp = clib_mem_alloc (sizeof (*kp));
  *kp = sup_and_sub_key;

  memset (&template, 0, sizeof (template));
  template.type = VNET_SW_INTERFACE_TYPE_SUB;
  template.sup_sw_if_index = sw_if_index;
  template.sub.id = sub_id;
  template.sub.eth.flags.no_tags = mp->no_tags;
  template.sub.eth.flags.one_tag = mp->one_tag;
  template.sub.eth.flags.two_tags = mp->two_tags;
  template.sub.eth.flags.dot1ad = mp->dot1ad;
  template.sub.eth.flags.exact_match = mp->exact_match;
  template.sub.eth.flags.default_sub = mp->default_sub;
  template.sub.eth.flags.outer_vlan_id_any = mp->outer_vlan_id_any;
  template.sub.eth.flags.inner_vlan_id_any = mp->inner_vlan_id_any;
  template.sub.eth.outer_vlan_id = ntohs (mp->outer_vlan_id);
  template.sub.eth.inner_vlan_id = ntohs (mp->inner_vlan_id);

  error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_SUBIF_CREATE_FAILED;
      goto out;
    }

  hash_set (hi->sub_interface_sw_if_index_by_id, sub_id, sw_if_index);
  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

out:

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_SUBIF_REPLY,
  ({
    rmp->sw_if_index = ntohl(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_mpls_gre_add_del_tunnel_t_handler (vl_api_mpls_gre_add_del_tunnel_t *
					  mp)
{
  vl_api_mpls_gre_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  stats_main_t *sm = &stats_main;
  u32 tunnel_sw_if_index = ~0;

  dslock (sm, 1 /* release hint */ , 5 /* tag */ );

  rv = vnet_mpls_gre_add_del_tunnel ((ip4_address_t *) (mp->src_address),
				     (ip4_address_t *) (mp->dst_address),
				     (ip4_address_t *) (mp->intfc_address),
				     (u32) (mp->intfc_address_length),
				     ntohl (mp->inner_vrf_id),
				     ntohl (mp->outer_vrf_id),
				     &tunnel_sw_if_index,
				     mp->l2_only, mp->is_add);
  dsunlock (sm);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_GRE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->tunnel_sw_if_index = ntohl(tunnel_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_mpls_ethernet_add_del_tunnel_t_handler
  (vl_api_mpls_ethernet_add_del_tunnel_t * mp)
{
  vl_api_mpls_ethernet_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  stats_main_t *sm = &stats_main;
  u32 tunnel_sw_if_index;

  dslock (sm, 1 /* release hint */ , 5 /* tag */ );

  rv = vnet_mpls_ethernet_add_del_tunnel
    (mp->dst_mac_address, (ip4_address_t *) (mp->adj_address),
     (u32) (mp->adj_address_length), ntohl (mp->vrf_id),
     ntohl (mp->tx_sw_if_index),
     &tunnel_sw_if_index, mp->l2_only, mp->is_add);

  dsunlock (sm);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_ETHERNET_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->tunnel_sw_if_index = ntohl(tunnel_sw_if_index);
  }));
  /* *INDENT-ON* */
}

/*
 * This piece of misery brought to you because the control-plane
 * can't figure out the tx interface + dst-mac address all by itself
 */
static int mpls_ethernet_add_del_tunnel_2_t_handler
  (vl_api_mpls_ethernet_add_del_tunnel_2_t * mp)
{
  pending_route_t *pr;
  vl_api_mpls_ethernet_add_del_tunnel_2_t *pme;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  stats_main_t *sm = &stats_main;
  vpe_api_main_t *vam = &vpe_api_main;
  u32 inner_fib_index, outer_fib_index;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_adjacency_t *adj = 0;
  u32 lookup_result;
  u32 tx_sw_if_index;
  u8 *dst_mac_address;
  clib_error_t *e;
  uword *p;
  int rv;
  u32 tunnel_sw_if_index;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->outer_vrf_id));
  if (!p)
    return VNET_API_ERROR_NO_SUCH_FIB;
  else
    outer_fib_index = p[0];


  p = hash_get (im->fib_index_by_table_id, ntohl (mp->inner_vrf_id));
  if (!p)
    return VNET_API_ERROR_NO_SUCH_INNER_FIB;
  else
    inner_fib_index = p[0];

  if (inner_fib_index == outer_fib_index)
    return VNET_API_ERROR_INVALID_VALUE;

  lookup_result = ip4_fib_lookup_with_table
    (im, outer_fib_index,
     (ip4_address_t *) mp->next_hop_ip4_address_in_outer_vrf,
     1 /* disable default route */ );

  adj = ip_get_adjacency (lm, lookup_result);
  tx_sw_if_index = adj->rewrite_header.sw_if_index;

  if (mp->is_add && mp->resolve_if_needed)
    {
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	{
	  pool_get (vam->pending_routes, pr);
	  pr->resolve_type = RESOLVE_MPLS_ETHERNET_ADD_DEL;
	  pme = &pr->t;
	  clib_memcpy (pme, mp, sizeof (*pme));
	  /* recursion block, "just in case" */
	  pme->resolve_if_needed = 0;
	  pme->resolve_attempts = ntohl (mp->resolve_attempts);
	  pme->resolve_opaque = tx_sw_if_index;
	  vnet_register_ip4_arp_resolution_event
	    (vnm,
	     (ip4_address_t *) & (pme->next_hop_ip4_address_in_outer_vrf),
	     vpe_resolver_process_node.index,
	     RESOLUTION_EVENT, pr - vam->pending_routes);

	  vlib_process_signal_event
	    (vm, vpe_resolver_process_node.index,
	     RESOLUTION_PENDING_EVENT, 0 /* data */ );

	  /* The interface may be down, etc. */
	  e = ip4_probe_neighbor
	    (vm, (ip4_address_t *) & (mp->next_hop_ip4_address_in_outer_vrf),
	     tx_sw_if_index);

	  if (e)
	    clib_error_report (e);

	  return VNET_API_ERROR_IN_PROGRESS;
	}
    }

  if (adj->lookup_next_index != IP_LOOKUP_NEXT_REWRITE)
    return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;

  dst_mac_address =
    vnet_rewrite_get_data_internal
    (&adj->rewrite_header, sizeof (adj->rewrite_data));

  dslock (sm, 1 /* release hint */ , 10 /* tag */ );

  rv = vnet_mpls_ethernet_add_del_tunnel
    (dst_mac_address, (ip4_address_t *) (mp->adj_address),
     (u32) (mp->adj_address_length), ntohl (mp->inner_vrf_id),
     tx_sw_if_index, &tunnel_sw_if_index, mp->l2_only, mp->is_add);

  dsunlock (sm);

  return rv;
}

static void
  vl_api_mpls_ethernet_add_del_tunnel_2_t_handler
  (vl_api_mpls_ethernet_add_del_tunnel_2_t * mp)
{
  vl_api_mpls_ethernet_add_del_tunnel_reply_t *rmp;
  int rv = 0;

  rv = mpls_ethernet_add_del_tunnel_2_t_handler (mp);

  REPLY_MACRO (VL_API_MPLS_ETHERNET_ADD_DEL_TUNNEL_2_REPLY);
}


static void
vl_api_mpls_add_del_encap_t_handler (vl_api_mpls_add_del_encap_t * mp)
{
  vl_api_mpls_add_del_encap_reply_t *rmp;
  int rv;
  static u32 *labels;
  int i;

  vec_reset_length (labels);

  for (i = 0; i < mp->nlabels; i++)
    vec_add1 (labels, ntohl (mp->labels[i]));

  /* $$$$ fixme */
  rv = vnet_mpls_add_del_encap ((ip4_address_t *) mp->dst_address,
				ntohl (mp->vrf_id), labels,
				~0 /* policy_tunnel_index */ ,
				0 /* no_dst_hash */ ,
				0 /* indexp */ ,
				mp->is_add);

  REPLY_MACRO (VL_API_MPLS_ADD_DEL_ENCAP_REPLY);
}

static void
vl_api_mpls_add_del_decap_t_handler (vl_api_mpls_add_del_decap_t * mp)
{
  vl_api_mpls_add_del_decap_reply_t *rmp;
  int rv;

  rv = vnet_mpls_add_del_decap (ntohl (mp->rx_vrf_id), ntohl (mp->tx_vrf_id),
				ntohl (mp->label), ntohl (mp->next_index),
				mp->s_bit, mp->is_add);

  REPLY_MACRO (VL_API_MPLS_ADD_DEL_DECAP_REPLY);
}

static void
vl_api_proxy_arp_add_del_t_handler (vl_api_proxy_arp_add_del_t * mp)
{
  vl_api_proxy_arp_add_del_reply_t *rmp;
  u32 fib_index;
  int rv;
  ip4_main_t *im = &ip4_main;
  stats_main_t *sm = &stats_main;
  int vnet_proxy_arp_add_del (ip4_address_t * lo_addr,
			      ip4_address_t * hi_addr,
			      u32 fib_index, int is_del);
  uword *p;

  dslock (sm, 1 /* release hint */ , 6 /* tag */ );

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->vrf_id));

  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  fib_index = p[0];

  rv = vnet_proxy_arp_add_del ((ip4_address_t *) mp->low_address,
			       (ip4_address_t *) mp->hi_address,
			       fib_index, mp->is_add == 0);

out:
  dsunlock (sm);
  REPLY_MACRO (VL_API_PROXY_ARP_ADD_DEL_REPLY);
}

static void
  vl_api_proxy_arp_intfc_enable_disable_t_handler
  (vl_api_proxy_arp_intfc_enable_disable_t * mp)
{
  int rv = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_proxy_arp_intfc_enable_disable_reply_t *rmp;
  vnet_sw_interface_t *si;
  u32 sw_if_index;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  si = vnet_get_sw_interface (vnm, sw_if_index);

  ASSERT (si);

  if (mp->enable_disable)
    si->flags |= VNET_SW_INTERFACE_FLAG_PROXY_ARP;
  else
    si->flags &= ~VNET_SW_INTERFACE_FLAG_PROXY_ARP;

  BAD_SW_IF_INDEX_LABEL;

out:
  REPLY_MACRO (VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ip_neighbor_add_del_t_handler (vl_api_ip_neighbor_add_del_t * mp,
				      vlib_main_t * vm)
{
  vl_api_ip_neighbor_add_del_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 fib_index;
  int rv = 0;
  stats_main_t *sm = &stats_main;

  VALIDATE_SW_IF_INDEX (mp);

  dslock (sm, 1 /* release hint */ , 7 /* tag */ );

  if (mp->is_ipv6)
    {
      if (mp->is_add)
	rv = vnet_set_ip6_ethernet_neighbor
	  (vm, ntohl (mp->sw_if_index),
	   (ip6_address_t *) (mp->dst_address),
	   mp->mac_address, sizeof (mp->mac_address), mp->is_static);
      else
	rv = vnet_unset_ip6_ethernet_neighbor
	  (vm, ntohl (mp->sw_if_index),
	   (ip6_address_t *) (mp->dst_address),
	   mp->mac_address, sizeof (mp->mac_address));
    }
  else
    {
      ip4_main_t *im = &ip4_main;
      ip_lookup_main_t *lm = &im->lookup_main;
      ethernet_arp_ip4_over_ethernet_address_t a;
      u32 ai;
      ip_adjacency_t *nh_adj;

      uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->vrf_id));
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	  goto out;
	}
      fib_index = p[0];

      /*
       * Unfortunately, folks have a penchant for
       * adding interface addresses to the ARP cache, and
       * wondering why the forwarder eventually ASSERTs...
       */
      ai = ip4_fib_lookup_with_table
	(im, fib_index, (ip4_address_t *) (mp->dst_address),
	 1 /* disable default route */ );

      if (ai != 0)
	{
	  nh_adj = ip_get_adjacency (lm, ai);
	  /* Never allow manipulation of a local adj! */
	  if (nh_adj->lookup_next_index == IP_LOOKUP_NEXT_LOCAL)
	    {
	      clib_warning ("%U matches local adj",
			    format_ip4_address,
			    (ip4_address_t *) (mp->dst_address));
	      rv = VNET_API_ERROR_ADDRESS_MATCHES_INTERFACE_ADDRESS;
	      goto out;
	    }
	}

      clib_memcpy (&a.ethernet, mp->mac_address, 6);
      clib_memcpy (&a.ip4, mp->dst_address, 4);

      if (mp->is_add)
	rv = vnet_arp_set_ip4_over_ethernet (vnm, ntohl (mp->sw_if_index),
					     fib_index, &a, mp->is_static);
      else
	rv = vnet_arp_unset_ip4_over_ethernet (vnm, ntohl (mp->sw_if_index),
					       fib_index, &a);
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  dsunlock (sm);
  REPLY_MACRO (VL_API_IP_NEIGHBOR_ADD_DEL_REPLY);
}

static void
vl_api_is_address_reachable_t_handler (vl_api_is_address_reachable_t * mp)
{
#if 0
  vpe_main_t *rm = &vpe_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ip_lookup_main_t *lm;
  union
  {
    ip4_address_t ip4;
    ip6_address_t ip6;
  } addr;
  u32 adj_index, sw_if_index;
  vl_api_is_address_reachable_t *rmp;
  ip_adjacency_t *adj;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    {
      increment_missing_api_client_counter (rm->vlib_main);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memcpy (rmp, mp, sizeof (*rmp));

  sw_if_index = mp->next_hop_sw_if_index;
  clib_memcpy (&addr, mp->address, sizeof (addr));
  if (mp->is_ipv6)
    {
      lm = &im6->lookup_main;
      adj_index = ip6_fib_lookup (im6, sw_if_index, &addr.ip6);
    }
  else
    {
      lm = &im4->lookup_main;
      adj_index = ip4_fib_lookup (im4, sw_if_index, &addr.ip4);
    }
  if (adj_index == ~0)
    {
      rmp->is_error = 1;
      goto send;
    }
  adj = ip_get_adjacency (lm, adj_index);

  if (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE
      && adj->rewrite_header.sw_if_index == sw_if_index)
    {
      rmp->is_known = 1;
    }
  else
    {
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP
	  && adj->rewrite_header.sw_if_index == sw_if_index)
	{
	  if (mp->is_ipv6)
	    ip6_probe_neighbor (rm->vlib_main, &addr.ip6, sw_if_index);
	  else
	    ip4_probe_neighbor (rm->vlib_main, &addr.ip4, sw_if_index);
	}
      else if (adj->lookup_next_index == IP_LOOKUP_NEXT_DROP)
	{
	  rmp->is_known = 1;
	  goto send;
	}
      rmp->is_known = 0;
    }

send:
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
#endif
}

static void
vl_api_sw_interface_details_t_handler (vl_api_sw_interface_details_t * mp)
{
  clib_warning ("BUG");
}

static void
vl_api_sw_interface_set_flags_t_handler (vl_api_sw_interface_set_flags_t * mp)
{
  vl_api_sw_interface_set_flags_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;
  u16 flags;

  VALIDATE_SW_IF_INDEX (mp);

  flags = mp->admin_up_down ? VNET_SW_INTERFACE_FLAG_ADMIN_UP : 0;

  error = vnet_sw_interface_set_flags (vnm, ntohl (mp->sw_if_index), flags);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_FLAGS_REPLY);
}

static void
vl_api_sw_interface_clear_stats_t_handler (vl_api_sw_interface_clear_stats_t *
					   mp)
{
  vl_api_sw_interface_clear_stats_reply_t *rmp;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_simple_counter_main_t *sm;
  vlib_combined_counter_main_t *cm;
  static vnet_main_t **my_vnet_mains;
  int i, j, n_counters;
  int rv = 0;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX(mp);

  vec_reset_length (my_vnet_mains);

  for (i = 0; i < vec_len (vnet_mains); i++)
    {
      if (vnet_mains[i])
	vec_add1 (my_vnet_mains, vnet_mains[i]);
    }

  if (vec_len (vnet_mains) == 0)
    vec_add1 (my_vnet_mains, vnm);

  n_counters = vec_len (im->combined_sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  cm = im->combined_sw_if_counters + j;
	  if (mp->sw_if_index == (u32) ~ 0)
	    vlib_clear_combined_counters (cm);
	  else
	    vlib_zero_combined_counter (cm, ntohl (mp->sw_if_index));
	}
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  sm = im->sw_if_counters + j;
	  if (mp->sw_if_index == (u32) ~ 0)
	    vlib_clear_simple_counters (sm);
	  else
	    vlib_zero_simple_counter (sm, ntohl (mp->sw_if_index));
	}
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_CLEAR_STATS_REPLY);
}

static void
send_sw_interface_details (vpe_api_main_t * am,
			   unix_shared_memory_queue_t * q,
			   vnet_sw_interface_t * swif,
			   u8 * interface_name, u32 context)
{
  vl_api_sw_interface_details_t *mp;
  vnet_hw_interface_t *hi;

  hi = vnet_get_sup_hw_interface (am->vnet_main, swif->sw_if_index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_DETAILS);
  mp->sw_if_index = ntohl (swif->sw_if_index);
  mp->sup_sw_if_index = ntohl (swif->sup_sw_if_index);
  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;
  mp->link_up_down = (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;
  mp->link_duplex = ((hi->flags & VNET_HW_INTERFACE_FLAG_DUPLEX_MASK) >>
		     VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT);
  mp->link_speed = ((hi->flags & VNET_HW_INTERFACE_FLAG_SPEED_MASK) >>
		    VNET_HW_INTERFACE_FLAG_SPEED_SHIFT);
  mp->link_mtu = ntohs (hi->max_packet_bytes);
  mp->context = context;

  strncpy ((char *) mp->interface_name,
	   (char *) interface_name, ARRAY_LEN (mp->interface_name) - 1);

  /* Send the L2 address for ethernet physical intfcs */
  if (swif->sup_sw_if_index == swif->sw_if_index
      && hi->hw_class_index == ethernet_hw_interface_class.index)
    {
      ethernet_main_t *em = ethernet_get_main (am->vlib_main);
      ethernet_interface_t *ei;

      ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
      ASSERT (sizeof (mp->l2_address) >= sizeof (ei->address));
      clib_memcpy (mp->l2_address, ei->address, sizeof (ei->address));
      mp->l2_address_length = ntohl (sizeof (ei->address));
    }
  else if (swif->sup_sw_if_index != swif->sw_if_index)
    {
      vnet_sub_interface_t *sub = &swif->sub;
      mp->sub_id = ntohl (sub->id);
      mp->sub_dot1ad = sub->eth.flags.dot1ad;
      mp->sub_number_of_tags =
	sub->eth.flags.one_tag + sub->eth.flags.two_tags * 2;
      mp->sub_outer_vlan_id = ntohs (sub->eth.outer_vlan_id);
      mp->sub_inner_vlan_id = ntohs (sub->eth.inner_vlan_id);
      mp->sub_exact_match = sub->eth.flags.exact_match;
      mp->sub_default = sub->eth.flags.default_sub;
      mp->sub_outer_vlan_id_any = sub->eth.flags.outer_vlan_id_any;
      mp->sub_inner_vlan_id_any = sub->eth.flags.inner_vlan_id_any;

      /* vlan tag rewrite data */
      u32 vtr_op = L2_VTR_DISABLED;
      u32 vtr_push_dot1q = 0, vtr_tag1 = 0, vtr_tag2 = 0;

      if (l2vtr_get (am->vlib_main, am->vnet_main, swif->sw_if_index,
		     &vtr_op, &vtr_push_dot1q, &vtr_tag1, &vtr_tag2) != 0)
	{
	  // error - default to disabled
	  mp->vtr_op = ntohl (L2_VTR_DISABLED);
	  clib_warning ("cannot get vlan tag rewrite for sw_if_index %d",
			swif->sw_if_index);
	}
      else
	{
	  mp->vtr_op = ntohl (vtr_op);
	  mp->vtr_push_dot1q = ntohl (vtr_push_dot1q);
	  mp->vtr_tag1 = ntohl (vtr_tag1);
	  mp->vtr_tag2 = ntohl (vtr_tag2);
	}
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_sw_interface_flags (vpe_api_main_t * am,
			 unix_shared_memory_queue_t * q,
			 vnet_sw_interface_t * swif)
{
  vl_api_sw_interface_set_flags_t *mp;
  vnet_main_t *vnm = am->vnet_main;

  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm,
						       swif->sw_if_index);
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_FLAGS);
  mp->sw_if_index = ntohl (swif->sw_if_index);

  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;
  mp->link_up_down = (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void send_sw_interface_flags_deleted (vpe_api_main_t * am,
					     unix_shared_memory_queue_t * q,
					     u32 sw_if_index)
  __attribute__ ((unused));

static void
send_sw_interface_flags_deleted (vpe_api_main_t * am,
				 unix_shared_memory_queue_t * q,
				 u32 sw_if_index)
{
  vl_api_sw_interface_set_flags_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_FLAGS);
  mp->sw_if_index = ntohl (sw_if_index);

  mp->admin_up_down = 0;
  mp->link_up_down = 0;
  mp->deleted = 1;
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_interface_dump_t_handler (vl_api_sw_interface_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u8 *filter_string = 0, *name_string = 0;
  unix_shared_memory_queue_t *q;
  char *strcasestr (char *, char *);	/* lnx hdr file botch */

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (q == 0)
    return;

  if (mp->name_filter_valid)
    {
      mp->name_filter[ARRAY_LEN (mp->name_filter) - 1] = 0;
      filter_string = format (0, "%s%c", mp->name_filter, 0);
    }

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    name_string = format (name_string, "%U%c",
                          format_vnet_sw_interface_name,
                          am->vnet_main, swif, 0);

    if (mp->name_filter_valid == 0 ||
        strcasestr((char *) name_string, (char *) filter_string)) {

      send_sw_interface_details (am, q, swif, name_string, mp->context);
    }
    _vec_len (name_string) = 0;
  }));
  /* *INDENT-ON* */

  vec_free (name_string);
  vec_free (filter_string);
}

void
send_oam_event (oam_target_t * t)
{
  vpe_api_main_t *vam = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vpe_client_registration_t *reg;
  vl_api_oam_event_t *mp;

  /* *INDENT-OFF* */
  pool_foreach(reg, vam->oam_events_registrations,
  ({
    q = vl_api_client_index_to_input_queue (reg->client_index);
    if (q)
      {
        mp = vl_msg_api_alloc (sizeof (*mp));
        mp->_vl_msg_id = ntohs (VL_API_OAM_EVENT);
        clib_memcpy (mp->dst_address, &t->dst_address,
                     sizeof (mp->dst_address));
        mp->state = t->state;
        vl_msg_api_send_shmem (q, (u8 *)&mp);
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_oam_add_del_t_handler (vl_api_oam_add_del_t * mp)
{
  vl_api_oam_add_del_reply_t *rmp;
  int rv;

  rv = vpe_oam_add_del_target ((ip4_address_t *) mp->src_address,
			       (ip4_address_t *) mp->dst_address,
			       ntohl (mp->vrf_id), (int) (mp->is_add));

  REPLY_MACRO (VL_API_OAM_ADD_DEL_REPLY);
}

static void
vl_api_vnet_get_summary_stats_t_handler (vl_api_vnet_get_summary_stats_t * mp)
{
  stats_main_t *sm = &stats_main;
  vnet_interface_main_t *im = sm->interface_main;
  vl_api_vnet_summary_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  vlib_counter_t v;
  int i, which;
  u64 total_pkts[VLIB_N_RX_TX];
  u64 total_bytes[VLIB_N_RX_TX];

  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VNET_SUMMARY_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;

  memset (total_pkts, 0, sizeof (total_pkts));
  memset (total_bytes, 0, sizeof (total_bytes));

  vnet_interface_counter_lock (im);

  vec_foreach (cm, im->combined_sw_if_counters)
  {
    which = cm - im->combined_sw_if_counters;

    for (i = 0; i < vec_len (cm->maxi); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }
  vnet_interface_counter_unlock (im);

  /* Note: in HOST byte order! */
  rmp->total_pkts[VLIB_RX] = total_pkts[VLIB_RX];
  rmp->total_bytes[VLIB_RX] = total_bytes[VLIB_RX];
  rmp->total_pkts[VLIB_TX] = total_pkts[VLIB_TX];
  rmp->total_bytes[VLIB_TX] = total_bytes[VLIB_TX];
  rmp->vector_rate = vlib_last_vector_length_per_node (sm->vlib_main);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_address_t address;
  u32 address_length: 6;
  u32 index:26;
}) ip4_route_t;
/* *INDENT-ON* */

static int
ip4_reset_fib_t_handler (vl_api_reset_fib_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip4_main_t *im4 = &ip4_main;
  static ip4_route_t *routes;
  static u32 *sw_if_indices_to_shut;
  stats_main_t *sm = &stats_main;
  ip4_route_t *r;
  ip4_fib_t *fib;
  u32 sw_if_index;
  int i;
  int rv = VNET_API_ERROR_NO_SUCH_FIB;
  u32 target_fib_id = ntohl (mp->vrf_id);

  dslock (sm, 1 /* release hint */ , 8 /* tag */ );

  vec_foreach (fib, im4->fibs)
  {
    vnet_sw_interface_t *si;

    if (fib->table_id != target_fib_id)
      continue;

    /* remove any mpls/gre tunnels in this fib */
    vnet_mpls_gre_delete_fib_tunnels (fib->table_id);

    /* remove any mpls encap/decap labels */
    mpls_fib_reset_labels (fib->table_id);

    /* remove any proxy arps in this fib */
    vnet_proxy_arp_fib_reset (fib->table_id);

    /* Set the flow hash for this fib to the default */
    vnet_set_ip4_flow_hash (fib->table_id, IP_FLOW_HASH_DEFAULT);

    vec_reset_length (sw_if_indices_to_shut);

    /* Shut down interfaces in this FIB / clean out intfc routes */
    /* *INDENT-OFF* */
    pool_foreach (si, im->sw_interfaces,
    ({
      u32 sw_if_index = si->sw_if_index;

      if (sw_if_index < vec_len (im4->fib_index_by_sw_if_index)
          && (im4->fib_index_by_sw_if_index[si->sw_if_index] ==
              fib - im4->fibs))
        vec_add1 (sw_if_indices_to_shut, si->sw_if_index);
    }));
    /* *INDENT-ON* */

    for (i = 0; i < vec_len (sw_if_indices_to_shut); i++)
      {
	sw_if_index = sw_if_indices_to_shut[i];
	// vec_foreach (sw_if_index, sw_if_indices_to_shut) {

	u32 flags = vnet_sw_interface_get_flags (vnm, sw_if_index);
	flags &= ~(VNET_SW_INTERFACE_FLAG_ADMIN_UP);
	vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
      }

    vec_reset_length (routes);

    for (i = 0; i < ARRAY_LEN (fib->adj_index_by_dst_address); i++)
      {
	uword *hash = fib->adj_index_by_dst_address[i];
	hash_pair_t *p;
	ip4_route_t x;

	x.address_length = i;

        /* *INDENT-OFF* */
        hash_foreach_pair (p, hash,
        ({
          x.address.data_u32 = p->key;
          vec_add1 (routes, x);
        }));
        /* *INDENT-ON* */
      }

    vec_foreach (r, routes)
    {
      ip4_add_del_route_args_t a;

      memset (&a, 0, sizeof (a));
      a.flags = IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_DEL;
      a.table_index_or_table_id = fib - im4->fibs;
      a.dst_address = r->address;
      a.dst_address_length = r->address_length;
      a.adj_index = ~0;

      ip4_add_del_route (im4, &a);
      ip4_maybe_remap_adjacencies (im4, fib - im4->fibs,
				   IP4_ROUTE_FLAG_FIB_INDEX);
    }
    rv = 0;
    break;
  }				/* vec_foreach (fib) */

  dsunlock (sm);
  return rv;
}

typedef struct
{
  ip6_address_t address;
  u32 address_length;
  u32 index;
} ip6_route_t;

typedef struct
{
  u32 fib_index;
  ip6_route_t **routep;
} add_routes_in_fib_arg_t;

static void
add_routes_in_fib (clib_bihash_kv_24_8_t * kvp, void *arg)
{
  add_routes_in_fib_arg_t *ap = arg;

  if (kvp->key[2] >> 32 == ap->fib_index)
    {
      ip6_address_t *addr;
      ip6_route_t *r;
      addr = (ip6_address_t *) kvp;
      vec_add2 (*ap->routep, r, 1);
      r->address = addr[0];
      r->address_length = kvp->key[2] & 0xFF;
      r->index = kvp->value;
    }
}

static int
ip6_reset_fib_t_handler (vl_api_reset_fib_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip6_main_t *im6 = &ip6_main;
  stats_main_t *sm = &stats_main;
  static ip6_route_t *routes;
  static u32 *sw_if_indices_to_shut;
  ip6_route_t *r;
  ip6_fib_t *fib;
  u32 sw_if_index;
  int i;
  int rv = VNET_API_ERROR_NO_SUCH_FIB;
  u32 target_fib_id = ntohl (mp->vrf_id);
  add_routes_in_fib_arg_t _a, *a = &_a;
  clib_bihash_24_8_t *h = &im6->ip6_lookup_table;

  dslock (sm, 1 /* release hint */ , 9 /* tag */ );

  vec_foreach (fib, im6->fibs)
  {
    vnet_sw_interface_t *si;

    if (fib->table_id != target_fib_id)
      continue;

    vec_reset_length (sw_if_indices_to_shut);

    /* Shut down interfaces in this FIB / clean out intfc routes */
    /* *INDENT-OFF* */
    pool_foreach (si, im->sw_interfaces,
    ({
      if (im6->fib_index_by_sw_if_index[si->sw_if_index] ==
          fib - im6->fibs)
        vec_add1 (sw_if_indices_to_shut, si->sw_if_index);
    }));
    /* *INDENT-ON* */

    for (i = 0; i < vec_len (sw_if_indices_to_shut); i++)
      {
	sw_if_index = sw_if_indices_to_shut[i];
	// vec_foreach (sw_if_index, sw_if_indices_to_shut) {

	u32 flags = vnet_sw_interface_get_flags (vnm, sw_if_index);
	flags &= ~(VNET_SW_INTERFACE_FLAG_ADMIN_UP);
	vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
      }

    vec_reset_length (routes);

    a->fib_index = fib - im6->fibs;
    a->routep = &routes;

    clib_bihash_foreach_key_value_pair_24_8 (h, add_routes_in_fib, a);

    vec_foreach (r, routes)
    {
      ip6_add_del_route_args_t a;

      memset (&a, 0, sizeof (a));
      a.flags = IP6_ROUTE_FLAG_FIB_INDEX | IP6_ROUTE_FLAG_DEL;
      a.table_index_or_table_id = fib - im6->fibs;
      a.dst_address = r->address;
      a.dst_address_length = r->address_length;
      a.adj_index = ~0;

      ip6_add_del_route (im6, &a);
      ip6_maybe_remap_adjacencies (im6, fib - im6->fibs,
				   IP6_ROUTE_FLAG_FIB_INDEX);
    }
    rv = 0;
    /* Reinstall the neighbor / router discovery routes */
    vnet_ip6_fib_init (im6, fib - im6->fibs);
    break;
  }				/* vec_foreach (fib) */

  dsunlock (sm);
  return rv;
}

static void
vl_api_reset_fib_t_handler (vl_api_reset_fib_t * mp)
{
  int rv;
  vl_api_reset_fib_reply_t *rmp;

  if (mp->is_ipv6)
    rv = ip6_reset_fib_t_handler (mp);
  else
    rv = ip4_reset_fib_t_handler (mp);

  REPLY_MACRO (VL_API_RESET_FIB_REPLY);
}


static void
dhcpv4_proxy_config (vl_api_dhcp_proxy_config_t * mp)
{
  vl_api_dhcp_proxy_config_reply_t *rmp;
  int rv;

  rv = dhcp_proxy_set_server ((ip4_address_t *) (&mp->dhcp_server),
			      (ip4_address_t *) (&mp->dhcp_src_address),
			      (u32) ntohl (mp->vrf_id),
			      (int) mp->insert_circuit_id,
			      (int) (mp->is_add == 0));

  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_REPLY);
}


static void
dhcpv6_proxy_config (vl_api_dhcp_proxy_config_t * mp)
{
  vl_api_dhcp_proxy_config_reply_t *rmp;
  int rv = -1;

  rv = dhcpv6_proxy_set_server ((ip6_address_t *) (&mp->dhcp_server),
				(ip6_address_t *) (&mp->dhcp_src_address),
				(u32) ntohl (mp->vrf_id),
				(int) mp->insert_circuit_id,
				(int) (mp->is_add == 0));

  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_REPLY);
}

static void
dhcpv4_proxy_config_2 (vl_api_dhcp_proxy_config_2_t * mp)
{
  vl_api_dhcp_proxy_config_reply_t *rmp;
  int rv;

  rv = dhcp_proxy_set_server_2 ((ip4_address_t *) (&mp->dhcp_server),
				(ip4_address_t *) (&mp->dhcp_src_address),
				(u32) ntohl (mp->rx_vrf_id),
				(u32) ntohl (mp->server_vrf_id),
				(int) mp->insert_circuit_id,
				(int) (mp->is_add == 0));

  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_2_REPLY);
}


static void
dhcpv6_proxy_config_2 (vl_api_dhcp_proxy_config_2_t * mp)
{
  vl_api_dhcp_proxy_config_reply_t *rmp;
  int rv = -1;

#if 0				// $$$$ FIXME
  rv = dhcpv6_proxy_set_server_2 ((ip6_address_t *) (&mp->dhcp_server),
				  (ip6_address_t *) (&mp->dhcp_src_address),
				  (u32) ntohl (mp->rx_vrf_id),
				  (u32) ntohl (mp->server_vrf_id),
				  (int) mp->insert_circuit_id,
				  (int) (mp->is_add == 0));
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_2_REPLY);
}


static void
vl_api_dhcp_proxy_set_vss_t_handler (vl_api_dhcp_proxy_set_vss_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  int rv;
  if (!mp->is_ipv6)
    rv = dhcp_proxy_set_option82_vss (ntohl (mp->tbl_id),
				      ntohl (mp->oui),
				      ntohl (mp->fib_id),
				      (int) mp->is_add == 0);
  else
    rv = dhcpv6_proxy_set_vss (ntohl (mp->tbl_id),
			       ntohl (mp->oui),
			       ntohl (mp->fib_id), (int) mp->is_add == 0);

  REPLY_MACRO (VL_API_DHCP_PROXY_SET_VSS_REPLY);
}


static void vl_api_dhcp_proxy_config_t_handler
  (vl_api_dhcp_proxy_config_t * mp)
{
  if (mp->is_ipv6 == 0)
    dhcpv4_proxy_config (mp);
  else
    dhcpv6_proxy_config (mp);
}

static void vl_api_dhcp_proxy_config_2_t_handler
  (vl_api_dhcp_proxy_config_2_t * mp)
{
  if (mp->is_ipv6 == 0)
    dhcpv4_proxy_config_2 (mp);
  else
    dhcpv6_proxy_config_2 (mp);
}

void
dhcp_compl_event_callback (u32 client_index, u32 pid, u8 * hostname,
			   u8 is_ipv6, u8 * host_address, u8 * router_address,
			   u8 * host_mac)
{
  unix_shared_memory_queue_t *q;
  vl_api_dhcp_compl_event_t *mp;

  q = vl_api_client_index_to_input_queue (client_index);
  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->client_index = client_index;
  mp->pid = pid;
  mp->is_ipv6 = is_ipv6;
  clib_memcpy (&mp->hostname, hostname, vec_len (hostname));
  mp->hostname[vec_len (hostname) + 1] = '\n';
  clib_memcpy (&mp->host_address[0], host_address, 16);
  clib_memcpy (&mp->router_address[0], router_address, 16);
  clib_memcpy (&mp->host_mac[0], host_mac, 6);

  mp->_vl_msg_id = ntohs (VL_API_DHCP_COMPL_EVENT);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void vl_api_dhcp_client_config_t_handler
  (vl_api_dhcp_client_config_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dhcp_client_config_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = dhcp_client_config (vm, ntohl (mp->sw_if_index),
			   mp->hostname, mp->is_add, mp->client_index,
			   mp->want_dhcp_event ? dhcp_compl_event_callback :
			   NULL, mp->pid);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_DHCP_CLIENT_CONFIG_REPLY);
}

static void
  vl_api_sw_interface_ip6nd_ra_config_t_handler
  (vl_api_sw_interface_ip6nd_ra_config_t * mp, vlib_main_t * vm)
{
  vl_api_sw_interface_ip6nd_ra_config_reply_t *rmp;
  int rv = 0;
  u8 is_no, suppress, managed, other, ll_option, send_unicast, cease,
    default_router;

  is_no = mp->is_no == 1;
  suppress = mp->suppress == 1;
  managed = mp->managed == 1;
  other = mp->other == 1;
  ll_option = mp->ll_option == 1;
  send_unicast = mp->send_unicast == 1;
  cease = mp->cease == 1;
  default_router = mp->default_router == 1;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ip6_neighbor_ra_config (vm, ntohl (mp->sw_if_index),
			       suppress, managed, other,
			       ll_option, send_unicast, cease,
			       default_router, ntohl (mp->lifetime),
			       ntohl (mp->initial_count),
			       ntohl (mp->initial_interval),
			       ntohl (mp->max_interval),
			       ntohl (mp->min_interval), is_no);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY);
}

static void
  vl_api_sw_interface_ip6nd_ra_prefix_t_handler
  (vl_api_sw_interface_ip6nd_ra_prefix_t * mp, vlib_main_t * vm)
{
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t *rmp;
  int rv = 0;
  u8 is_no, use_default, no_advertise, off_link, no_autoconfig, no_onlink;

  VALIDATE_SW_IF_INDEX (mp);

  is_no = mp->is_no == 1;
  use_default = mp->use_default == 1;
  no_advertise = mp->no_advertise == 1;
  off_link = mp->off_link == 1;
  no_autoconfig = mp->no_autoconfig == 1;
  no_onlink = mp->no_onlink == 1;

  rv = ip6_neighbor_ra_prefix (vm, ntohl (mp->sw_if_index),
			       (ip6_address_t *) mp->address,
			       mp->address_length, use_default,
			       ntohl (mp->val_lifetime),
			       ntohl (mp->pref_lifetime), no_advertise,
			       off_link, no_autoconfig, no_onlink, is_no);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY);
}

static void
  vl_api_sw_interface_ip6_enable_disable_t_handler
  (vl_api_sw_interface_ip6_enable_disable_t * mp, vlib_main_t * vm)
{
  vl_api_sw_interface_ip6_enable_disable_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;

  vnm->api_errno = 0;

  VALIDATE_SW_IF_INDEX (mp);

  error =
    (mp->enable == 1) ? enable_ip6_interface (vm,
					      ntohl (mp->sw_if_index)) :
    disable_ip6_interface (vm, ntohl (mp->sw_if_index));

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = vnm->api_errno;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_sw_interface_ip6_set_link_local_address_t_handler
  (vl_api_sw_interface_ip6_set_link_local_address_t * mp, vlib_main_t * vm)
{
  vl_api_sw_interface_ip6_set_link_local_address_reply_t *rmp;
  int rv = 0;
  clib_error_t *error;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  VALIDATE_SW_IF_INDEX (mp);

  error = set_ip6_link_local_address (vm,
				      ntohl (mp->sw_if_index),
				      (ip6_address_t *) mp->address,
				      mp->address_length);
  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = vnm->api_errno;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY);
}

static void
set_ip6_flow_hash (vl_api_set_ip_flow_hash_t * mp)
{
  vl_api_set_ip_flow_hash_reply_t *rmp;
  int rv = VNET_API_ERROR_UNIMPLEMENTED;

  clib_warning ("unimplemented...");

  REPLY_MACRO (VL_API_SET_IP_FLOW_HASH_REPLY);
}

static void
set_ip4_flow_hash (vl_api_set_ip_flow_hash_t * mp)
{
  vl_api_set_ip_flow_hash_reply_t *rmp;
  int rv;
  u32 table_id;
  u32 flow_hash_config = 0;

  table_id = ntohl (mp->vrf_id);

#define _(a,b) if (mp->a) flow_hash_config |= b;
  foreach_flow_hash_bit;
#undef _

  rv = vnet_set_ip4_flow_hash (table_id, flow_hash_config);

  REPLY_MACRO (VL_API_SET_IP_FLOW_HASH_REPLY);
}


static void
vl_api_set_ip_flow_hash_t_handler (vl_api_set_ip_flow_hash_t * mp)
{
  if (mp->is_ipv6 == 0)
    set_ip4_flow_hash (mp);
  else
    set_ip6_flow_hash (mp);
}

static void vl_api_sw_interface_set_unnumbered_t_handler
  (vl_api_sw_interface_set_unnumbered_t * mp)
{
  vl_api_sw_interface_set_unnumbered_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *si;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, unnumbered_sw_if_index;

  sw_if_index = ntohl (mp->sw_if_index);
  unnumbered_sw_if_index = ntohl (mp->unnumbered_sw_if_index);

  /*
   * The API message field names are backwards from
   * the underlying data structure names.
   * It's not worth changing them now.
   */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
			  unnumbered_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  /* Only check the "use loop0" field when setting the binding */
  if (mp->is_add &&
      pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto done;
    }

  si = vnet_get_sw_interface (vnm, unnumbered_sw_if_index);

  if (mp->is_add)
    {
      si->flags |= VNET_SW_INTERFACE_FLAG_UNNUMBERED;
      si->unnumbered_sw_if_index = sw_if_index;
    }
  else
    {
      si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
      si->unnumbered_sw_if_index = (u32) ~ 0;
    }

done:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY);
}

static void
vl_api_create_loopback_t_handler (vl_api_create_loopback_t * mp)
{
  vl_api_create_loopback_reply_t *rmp;
  u32 sw_if_index;
  int rv;

  rv = vnet_create_loopback_interface (&sw_if_index, mp->mac_address);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_LOOPBACK_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_delete_loopback_t_handler (vl_api_delete_loopback_t * mp)
{
  vl_api_delete_loopback_reply_t *rmp;
  u32 sw_if_index;
  int rv;

  sw_if_index = ntohl (mp->sw_if_index);
  rv = vnet_delete_loopback_interface (sw_if_index);

  REPLY_MACRO (VL_API_DELETE_LOOPBACK_REPLY);
}

static void
vl_api_control_ping_t_handler (vl_api_control_ping_t * mp)
{
  vl_api_control_ping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid());
  }));
  /* *INDENT-ON* */
}

static void vl_api_noprint_control_ping_t_handler
  (vl_api_noprint_control_ping_t * mp)
{
  vl_api_noprint_control_ping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_NOPRINT_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid());
  }));
  /* *INDENT-ON* */
}

static void
shmem_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **shmem_vecp = (u8 **) arg;
  u8 *shmem_vec;
  void *oldheap;
  api_main_t *am = &api_main;
  u32 offset;

  shmem_vec = *shmem_vecp;

  offset = vec_len (shmem_vec);

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_validate (shmem_vec, offset + buffer_bytes - 1);

  clib_memcpy (shmem_vec + offset, buffer, buffer_bytes);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  *shmem_vecp = shmem_vec;
}


static void
vl_api_cli_request_t_handler (vl_api_cli_request_t * mp)
{
  vl_api_cli_reply_t *rp;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = vlib_get_main ();
  api_main_t *am = &api_main;
  unformat_input_t input;
  u8 *shmem_vec = 0;
  void *oldheap;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_CLI_REPLY);
  rp->context = mp->context;

  unformat_init_vector (&input, (u8 *) (uword) mp->cmd_in_shmem);

  vlib_cli_input (vm, &input, shmem_cli_output, (uword) & shmem_vec);

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_add1 (shmem_vec, 0);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  rp->reply_in_shmem = (uword) shmem_vec;

  vl_msg_api_send_shmem (q, (u8 *) & rp);
}

static void
vl_api_set_arp_neighbor_limit_t_handler (vl_api_set_arp_neighbor_limit_t * mp)
{
  int rv;
  vl_api_set_arp_neighbor_limit_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error;

  vnm->api_errno = 0;

  if (mp->is_ipv6)
    error = ip6_set_neighbor_limit (ntohl (mp->arp_neighbor_limit));
  else
    error = ip4_set_arp_limit (ntohl (mp->arp_neighbor_limit));

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = vnm->api_errno;
    }

  REPLY_MACRO (VL_API_SET_ARP_NEIGHBOR_LIMIT_REPLY);
}

static void vl_api_sr_tunnel_add_del_t_handler
  (vl_api_sr_tunnel_add_del_t * mp)
{
#if IPV6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_tunnel_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_tunnel_add_del_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t *tags = 0, *tag;
  ip6_address_t *this_address;
  int i;

  if (mp->n_segments == 0)
    {
      rv = -11;
      goto out;
    }

  memset (a, 0, sizeof (*a));
  a->src_address = (ip6_address_t *) & mp->src_address;
  a->dst_address = (ip6_address_t *) & mp->dst_address;
  a->dst_mask_width = mp->dst_mask_width;
  a->flags_net_byte_order = mp->flags_net_byte_order;
  a->is_del = (mp->is_add == 0);
  a->rx_table_id = ntohl (mp->outer_vrf_id);
  a->tx_table_id = ntohl (mp->inner_vrf_id);

  a->name = format (0, "%s", mp->name);
  if (!(vec_len (a->name)))
    a->name = 0;

  a->policy_name = format (0, "%s", mp->policy_name);
  if (!(vec_len (a->policy_name)))
    a->policy_name = 0;

  /* Yank segments and tags out of the API message */
  this_address = (ip6_address_t *) mp->segs_and_tags;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }
  for (i = 0; i < mp->n_tags; i++)
    {
      vec_add2 (tags, tag, 1);
      clib_memcpy (tag->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  a->segments = segments;
  a->tags = tags;

  rv = ip6_sr_add_del_tunnel (a);

out:

  REPLY_MACRO (VL_API_SR_TUNNEL_ADD_DEL_REPLY);
#endif
}

static void vl_api_sr_policy_add_del_t_handler
  (vl_api_sr_policy_add_del_t * mp)
{
#if IPV6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_policy_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_policy_add_del_reply_t *rmp;
  int i;

  memset (a, 0, sizeof (*a));
  a->is_del = (mp->is_add == 0);

  a->name = format (0, "%s", mp->name);
  if (!(vec_len (a->name)))
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }

  if (!(mp->tunnel_names[0]))
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }

  // start deserializing tunnel_names
  int num_tunnels = mp->tunnel_names[0];	//number of tunnels
  u8 *deser_tun_names = mp->tunnel_names;
  deser_tun_names += 1;		//moving along

  u8 *tun_name = 0;
  int tun_name_len = 0;

  for (i = 0; i < num_tunnels; i++)
    {
      tun_name_len = *deser_tun_names;
      deser_tun_names += 1;
      vec_resize (tun_name, tun_name_len);
      memcpy (tun_name, deser_tun_names, tun_name_len);
      vec_add1 (a->tunnel_names, tun_name);
      deser_tun_names += tun_name_len;
      tun_name = 0;
    }

  rv = ip6_sr_add_del_policy (a);

out:

  REPLY_MACRO (VL_API_SR_POLICY_ADD_DEL_REPLY);
#endif
}

static void vl_api_sr_multicast_map_add_del_t_handler
  (vl_api_sr_multicast_map_add_del_t * mp)
{
#if IPV6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_multicastmap_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_multicast_map_add_del_reply_t *rmp;

  memset (a, 0, sizeof (*a));
  a->is_del = (mp->is_add == 0);

  a->multicast_address = (ip6_address_t *) & mp->multicast_address;
  a->policy_name = format (0, "%s", mp->policy_name);

  if (a->multicast_address == 0)
    {
      rv = -1;
      goto out;
    }

  if (!(a->policy_name))
    {
      rv = -2;
      goto out;
    }

#if DPDK > 0			/* Cannot call replicate without DPDK */
  rv = ip6_sr_add_del_multicastmap (a);
#else
  clib_warning ("multicast replication without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

out:

  REPLY_MACRO (VL_API_SR_MULTICAST_MAP_ADD_DEL_REPLY);
#endif
}

#define foreach_classify_add_del_table_field    \
_(table_index)                                  \
_(nbuckets)                                     \
_(memory_size)                                  \
_(skip_n_vectors)                               \
_(match_n_vectors)                              \
_(next_table_index)                             \
_(miss_next_index)

static void vl_api_classify_add_del_table_t_handler
  (vl_api_classify_add_del_table_t * mp)
{
  vl_api_classify_add_del_table_reply_t *rmp;
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  int rv;

#define _(a) u32 a;
  foreach_classify_add_del_table_field;
#undef _

#define _(a) a = ntohl(mp->a);
  foreach_classify_add_del_table_field;
#undef _

  /* The underlying API fails silently, on purpose, so check here */
  if (mp->is_add == 0)
    if (pool_is_free_index (cm->tables, table_index))
      {
	rv = VNET_API_ERROR_NO_SUCH_TABLE;
	goto out;
      }

  rv = vnet_classify_add_del_table
    (cm, mp->mask, nbuckets, memory_size,
     skip_n_vectors, match_n_vectors,
     next_table_index, miss_next_index, &table_index, mp->is_add);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY,
  ({
    if (rv == 0 && mp->is_add)
      {
        t = pool_elt_at_index (cm->tables, table_index);
        rmp->skip_n_vectors = ntohl(t->skip_n_vectors);
        rmp->match_n_vectors = ntohl(t->match_n_vectors);
        rmp->new_table_index = ntohl(table_index);
      }
    else
      {
        rmp->skip_n_vectors = ~0;
        rmp->match_n_vectors = ~0;
        rmp->new_table_index = ~0;
      }
  }));
  /* *INDENT-ON* */
}

static void vl_api_classify_add_del_session_t_handler
  (vl_api_classify_add_del_session_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_classify_add_del_session_reply_t *rmp;
  int rv;
  u32 table_index, hit_next_index, opaque_index;
  i32 advance;

  table_index = ntohl (mp->table_index);
  hit_next_index = ntohl (mp->hit_next_index);
  opaque_index = ntohl (mp->opaque_index);
  advance = ntohl (mp->advance);

  rv = vnet_classify_add_del_session
    (cm, table_index, mp->match, hit_next_index, opaque_index,
     advance, mp->is_add);

  REPLY_MACRO (VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY);
}

static void vl_api_classify_set_interface_ip_table_t_handler
  (vl_api_classify_set_interface_ip_table_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_classify_set_interface_ip_table_reply_t *rmp;
  int rv;
  u32 table_index, sw_if_index;

  table_index = ntohl (mp->table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_ipv6)
    rv = vnet_set_ip6_classify_intfc (vm, sw_if_index, table_index);
  else
    rv = vnet_set_ip4_classify_intfc (vm, sw_if_index, table_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY);
}

static void vl_api_classify_set_interface_l2_tables_t_handler
  (vl_api_classify_set_interface_l2_tables_t * mp)
{
  vl_api_classify_set_interface_l2_tables_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index, other_table_index;
  int enable;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  other_table_index = ntohl (mp->other_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_l2_classify_set_tables (sw_if_index, ip4_table_index,
				    ip6_table_index, other_table_index);

  if (rv == 0)
    {
      if (ip4_table_index != ~0 || ip6_table_index != ~0
	  || other_table_index != ~0)
	enable = 1;
      else
	enable = 0;

      vnet_l2_classify_enable_disable (sw_if_index, enable);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY);
}

static void
vl_api_l2_fib_clear_table_t_handler (vl_api_l2_fib_clear_table_t * mp)
{
  int rv = 0;
  vl_api_l2_fib_clear_table_reply_t *rmp;

  /* DAW-FIXME: This API should only clear non-static l2fib entries, but
   *            that is not currently implemented.  When that TODO is fixed
   *            this call should be changed to pass 1 instead of 0.
   */
  l2fib_clear_table (0);

  REPLY_MACRO (VL_API_L2_FIB_CLEAR_TABLE_REPLY);
}

extern void l2_efp_filter_configure (vnet_main_t * vnet_main,
				     u32 sw_if_index, u32 enable);

static void
vl_api_l2_interface_efp_filter_t_handler (vl_api_l2_interface_efp_filter_t *
					  mp)
{
  int rv;
  vl_api_l2_interface_efp_filter_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();

  // enable/disable the feature
  l2_efp_filter_configure (vnm, mp->sw_if_index, mp->enable_disable);
  rv = vnm->api_errno;

  REPLY_MACRO (VL_API_L2_INTERFACE_EFP_FILTER_REPLY);
}

static void
  vl_api_l2_interface_vlan_tag_rewrite_t_handler
  (vl_api_l2_interface_vlan_tag_rewrite_t * mp)
{
  int rv = 0;
  vl_api_l2_interface_vlan_tag_rewrite_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 vtr_op;

  VALIDATE_SW_IF_INDEX (mp);

  vtr_op = ntohl (mp->vtr_op);

  /* The L2 code is unsuspicious */
  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
    case L2_VTR_PUSH_1:
    case L2_VTR_PUSH_2:
    case L2_VTR_POP_1:
    case L2_VTR_POP_2:
    case L2_VTR_TRANSLATE_1_1:
    case L2_VTR_TRANSLATE_1_2:
    case L2_VTR_TRANSLATE_2_1:
    case L2_VTR_TRANSLATE_2_2:
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  rv = l2vtr_configure (vm, vnm, ntohl (mp->sw_if_index), vtr_op,
			ntohl (mp->push_dot1q), ntohl (mp->tag1),
			ntohl (mp->tag2));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY);
}

static void
vl_api_create_vhost_user_if_t_handler (vl_api_create_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_create_vhost_user_if_reply_t *rmp;
#if DPDK > 0
  u32 sw_if_index = (u32) ~ 0;

  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  rv = vhost_user_create_if (vnm, vm, (char *) mp->sock_filename,
			     mp->is_server, &sw_if_index, (u64) ~ 0,
			     mp->renumber, ntohl (mp->custom_dev_instance),
			     (mp->use_custom_mac) ? mp->mac_address : NULL);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_VHOST_USER_IF_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  REPLY_MACRO (VL_API_CREATE_VHOST_USER_IF_REPLY);
#endif
}

static void
vl_api_modify_vhost_user_if_t_handler (vl_api_modify_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_modify_vhost_user_if_reply_t *rmp;
#if DPDK > 0 && DPDK_VHOST_USER
  u32 sw_if_index = ntohl (mp->sw_if_index);

  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  rv = dpdk_vhost_user_modify_if (vnm, vm, (char *) mp->sock_filename,
				  mp->is_server, sw_if_index, (u64) ~ 0,
				  mp->renumber,
				  ntohl (mp->custom_dev_instance));
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif
  REPLY_MACRO (VL_API_MODIFY_VHOST_USER_IF_REPLY);
}

static void
vl_api_delete_vhost_user_if_t_handler (vl_api_delete_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_delete_vhost_user_if_reply_t *rmp;
#if DPDK > 0 && DPDK_VHOST_USER
  vpe_api_main_t *vam = &vpe_api_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  rv = dpdk_vhost_user_delete_if (vnm, vm, sw_if_index);

  REPLY_MACRO (VL_API_DELETE_VHOST_USER_IF_REPLY);
  if (!rv)
    {
      unix_shared_memory_queue_t *q =
	vl_api_client_index_to_input_queue (mp->client_index);
      if (!q)
	return;

      send_sw_interface_flags_deleted (vam, q, sw_if_index);
    }
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  REPLY_MACRO (VL_API_DELETE_VHOST_USER_IF_REPLY);
#endif
}

static void
  vl_api_sw_interface_vhost_user_details_t_handler
  (vl_api_sw_interface_vhost_user_details_t * mp)
{
  clib_warning ("BUG");
}

#if DPDK > 0 && DPDK_VHOST_USER
static void
send_sw_interface_vhost_user_details (vpe_api_main_t * am,
				      unix_shared_memory_queue_t * q,
				      vhost_user_intf_details_t * vui,
				      u32 context)
{
  vl_api_sw_interface_vhost_user_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_VHOST_USER_DETAILS);
  mp->sw_if_index = ntohl (vui->sw_if_index);
  mp->virtio_net_hdr_sz = ntohl (vui->virtio_net_hdr_sz);
  mp->features = clib_net_to_host_u64 (vui->features);
  mp->is_server = vui->is_server;
  mp->num_regions = ntohl (vui->num_regions);
  mp->sock_errno = ntohl (vui->sock_errno);
  mp->context = context;

  strncpy ((char *) mp->sock_filename,
	   (char *) vui->sock_filename, ARRAY_LEN (mp->sock_filename) - 1);
  strncpy ((char *) mp->interface_name,
	   (char *) vui->if_name, ARRAY_LEN (mp->interface_name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}
#endif

static void
  vl_api_sw_interface_vhost_user_dump_t_handler
  (vl_api_sw_interface_vhost_user_dump_t * mp)
{
#if DPDK > 0 && DPDK_VHOST_USER
  int rv = 0;
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vhost_user_intf_details_t *ifaces = NULL;
  vhost_user_intf_details_t *vuid = NULL;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  rv = dpdk_vhost_user_dump_ifs (vnm, vm, &ifaces);
  if (rv)
    return;

  vec_foreach (vuid, ifaces)
  {
    send_sw_interface_vhost_user_details (am, q, vuid, mp->context);
  }
  vec_free (ifaces);
#endif
}

static void
send_sw_if_l2tpv3_tunnel_details (vpe_api_main_t * am,
				  unix_shared_memory_queue_t * q,
				  l2t_session_t * s,
				  l2t_main_t * lm, u32 context)
{
  vl_api_sw_if_l2tpv3_tunnel_details_t *mp;
  u8 *if_name = NULL;
  vnet_sw_interface_t *si = NULL;

  si = vnet_get_hw_sw_interface (lm->vnet_main, s->hw_if_index);

  if_name = format (if_name, "%U",
		    format_vnet_sw_interface_name, lm->vnet_main, si);

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS);
  strncpy ((char *) mp->interface_name,
	   (char *) if_name, ARRAY_LEN (mp->interface_name) - 1);
  mp->sw_if_index = ntohl (si->sw_if_index);
  mp->local_session_id = s->local_session_id;
  mp->remote_session_id = s->remote_session_id;
  mp->local_cookie[0] = s->local_cookie[0];
  mp->local_cookie[1] = s->local_cookie[1];
  mp->remote_cookie = s->remote_cookie;
  clib_memcpy (mp->client_address, &s->client_address,
	       sizeof (s->client_address));
  clib_memcpy (mp->our_address, &s->our_address, sizeof (s->our_address));
  mp->l2_sublayer_present = s->l2_sublayer_present;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_ip_address_details (vpe_api_main_t * am,
			 unix_shared_memory_queue_t * q,
			 u8 * ip, u16 prefix_length, u8 is_ipv6, u32 context)
{
  vl_api_ip_address_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_ADDRESS_DETAILS);

  if (is_ipv6)
    {
      clib_memcpy (&mp->ip, ip, sizeof (mp->ip));
    }
  else
    {
      u32 *tp = (u32 *) mp->ip;
      *tp = ntohl (*(u32 *) ip);
    }
  mp->prefix_length = prefix_length;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_ip_address_dump_t_handler (vl_api_ip_address_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  ip6_address_t *r6;
  ip4_address_t *r4;
  ip6_main_t *im6 = &ip6_main;
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_interface_address_t *ia = 0;
  u32 sw_if_index = ~0;
  int rv __attribute__ ((unused)) = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->is_ipv6)
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index,
                                    1 /* honor unnumbered */,
      ({
        r6 = ip_interface_address_get_address (lm6, ia);
        u16 prefix_length = ia->address_length;
        send_ip_address_details(am, q, (u8*)r6, prefix_length, 1, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index,
                                    1 /* honor unnumbered */,
      ({
        r4 = ip_interface_address_get_address (lm4, ia);
        u16 prefix_length = ia->address_length;
        send_ip_address_details(am, q, (u8*)r4, prefix_length, 0, mp->context);
      }));
      /* *INDENT-ON* */
    }
  BAD_SW_IF_INDEX_LABEL;
}

static void
send_ip_details (vpe_api_main_t * am,
		 unix_shared_memory_queue_t * q, u32 sw_if_index, u32 context)
{
  vl_api_ip_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_DETAILS);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_if_l2tpv3_tunnel_dump_t_handler (vl_api_sw_if_l2tpv3_tunnel_dump_t *
					   mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  l2t_main_t *lm = &l2t_main;
  unix_shared_memory_queue_t *q;
  l2t_session_t *session;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    send_sw_if_l2tpv3_tunnel_details (am, q, session, lm, mp->context);
  }));
  /* *INDENT-ON* */
}


static void
send_sw_interface_tap_details (vpe_api_main_t * am,
			       unix_shared_memory_queue_t * q,
			       tapcli_interface_details_t * tap_if,
			       u32 context)
{
  vl_api_sw_interface_tap_details_t *mp;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_TAP_DETAILS);
  mp->sw_if_index = ntohl (tap_if->sw_if_index);
  strncpy ((char *) mp->dev_name,
	   (char *) tap_if->dev_name, ARRAY_LEN (mp->dev_name) - 1);
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_interface_tap_dump_t_handler (vl_api_sw_interface_tap_dump_t * mp)
{
  int rv = 0;
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  tapcli_interface_details_t *tapifs = NULL;
  tapcli_interface_details_t *tap_if = NULL;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  rv = vnet_tap_dump_ifs (&tapifs);
  if (rv)
    return;

  vec_foreach (tap_if, tapifs)
  {
    send_sw_interface_tap_details (am, q, tap_if, mp->context);
  }

  vec_free (tapifs);
}

static void
vl_api_ip_dump_t_handler (vl_api_ip_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  unix_shared_memory_queue_t *q;
  vnet_sw_interface_t *si, *sorted_sis;
  u32 sw_if_index = ~0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* Gather interfaces. */
  sorted_sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
  _vec_len (sorted_sis) = 0;
  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces,
  ({
    vec_add1 (sorted_sis, si[0]);
  }));
  /* *INDENT-ON* */

  vec_foreach (si, sorted_sis)
  {
    if (!(si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED))
      {
	if (mp->is_ipv6 && !ip6_interface_enabled (vm, si->sw_if_index))
	  {
	    continue;
	  }
	sw_if_index = si->sw_if_index;
	send_ip_details (am, q, sw_if_index, mp->context);
      }
  }
}

static void
vl_api_l2_fib_table_entry_t_handler (vl_api_l2_fib_table_entry_t * mp)
{
  clib_warning ("BUG");
}

static void
send_l2fib_table_entry (vpe_api_main_t * am,
			unix_shared_memory_queue_t * q,
			l2fib_entry_key_t * l2fe_key,
			l2fib_entry_result_t * l2fe_res, u32 context)
{
  vl_api_l2_fib_table_entry_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_FIB_TABLE_ENTRY);

  mp->bd_id =
    ntohl (l2input_main.bd_configs[l2fe_key->fields.bd_index].bd_id);

  mp->mac = l2fib_make_key (l2fe_key->fields.mac, 0);
  mp->sw_if_index = ntohl (l2fe_res->fields.sw_if_index);
  mp->static_mac = l2fe_res->fields.static_mac;
  mp->filter_mac = l2fe_res->fields.filter;
  mp->bvi_mac = l2fe_res->fields.bvi;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_fib_table_dump_t_handler (vl_api_l2_fib_table_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  bd_main_t *bdm = &bd_main;
  l2fib_entry_key_t *l2fe_key = NULL;
  l2fib_entry_result_t *l2fe_res = NULL;
  u32 ni, bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  unix_shared_memory_queue_t *q;
  uword *p;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* see l2fib_table_dump: ~0 means "any" */
  if (bd_id == ~0)
    bd_index = ~0;
  else
    {
      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p == 0)
	return;

      bd_index = p[0];
    }

  l2fib_table_dump (bd_index, &l2fe_key, &l2fe_res);

  vec_foreach_index (ni, l2fe_key)
  {
    send_l2fib_table_entry (am, q, vec_elt_at_index (l2fe_key, ni),
			    vec_elt_at_index (l2fe_res, ni), mp->context);
  }
  vec_free (l2fe_key);
  vec_free (l2fe_res);
}

static void
vl_api_show_version_t_handler (vl_api_show_version_t * mp)
{
  vl_api_show_version_reply_t *rmp;
  int rv = 0;
  char *vpe_api_get_build_directory (void);
  char *vpe_api_get_version (void);
  char *vpe_api_get_build_date (void);

  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_VERSION_REPLY,
  ({
    strncpy ((char *) rmp->program, "vpe", ARRAY_LEN(rmp->program)-1);
    strncpy ((char *) rmp->build_directory, vpe_api_get_build_directory(),
             ARRAY_LEN(rmp->build_directory)-1);
    strncpy ((char *) rmp->version, vpe_api_get_version(),
             ARRAY_LEN(rmp->version)-1);
    strncpy ((char *) rmp->build_date, vpe_api_get_build_date(),
             ARRAY_LEN(rmp->build_date)-1);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_node_index_t_handler (vl_api_get_node_index_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_node_index_reply_t *rmp;
  vlib_node_t *n;
  int rv = 0;
  u32 node_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE;
  else
    node_index = n->index;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_INDEX_REPLY,
  ({
    rmp->node_index = ntohl(node_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_next_index_t_handler (vl_api_get_next_index_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_next_index_reply_t *rmp;
  vlib_node_t *node, *next_node;
  int rv = 0;
  u32 next_node_index = ~0, next_index = ~0;
  uword *p;

  node = vlib_get_node_by_name (vm, mp->node_name);

  if (node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next_node = vlib_get_node_by_name (vm, mp->next_name);

  if (next_node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }
  else
    next_node_index = next_node->index;

  p = hash_get (node->next_slot_by_node, next_node_index);

  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  else
    next_index = p[0];

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NEXT_INDEX_REPLY,
  ({
    rmp->next_index = ntohl(next_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_add_node_next_t_handler (vl_api_add_node_next_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_add_node_next_reply_t *rmp;
  vlib_node_t *n, *next;
  int rv = 0;
  u32 next_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next = vlib_get_node_by_name (vm, mp->next_name);

  if (next == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE2;
  else
    next_index = vlib_node_add_next (vm, n->index, next->index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_INDEX_REPLY,
  ({
    rmp->next_index = ntohl(next_index);
  }));
  /* *INDENT-ON* */
}

static void vl_api_l2tpv3_create_tunnel_t_handler
  (vl_api_l2tpv3_create_tunnel_t * mp)
{
  vl_api_l2tpv3_create_tunnel_reply_t *rmp;
  l2t_main_t *lm = &l2t_main;
  u32 sw_if_index = (u32) ~ 0;
  int rv;

  if (mp->is_ipv6 != 1)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  u32 encap_fib_index;

  if (mp->encap_vrf_id != ~0)
    {
      uword *p;
      ip6_main_t *im = &ip6_main;
      if (!
	  (p =
	   hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id))))
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	  goto out;
	}
      encap_fib_index = p[0];
    }
  else
    {
      encap_fib_index = ~0;
    }

  rv = create_l2tpv3_ipv6_tunnel (lm,
				  (ip6_address_t *) mp->client_address,
				  (ip6_address_t *) mp->our_address,
				  ntohl (mp->local_session_id),
				  ntohl (mp->remote_session_id),
				  clib_net_to_host_u64 (mp->local_cookie),
				  clib_net_to_host_u64 (mp->remote_cookie),
				  mp->l2_sublayer_present,
				  encap_fib_index, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_L2TPV3_CREATE_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void vl_api_l2tpv3_set_tunnel_cookies_t_handler
  (vl_api_l2tpv3_set_tunnel_cookies_t * mp)
{
  vl_api_l2tpv3_set_tunnel_cookies_reply_t *rmp;
  l2t_main_t *lm = &l2t_main;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = l2tpv3_set_tunnel_cookies (lm, ntohl (mp->sw_if_index),
				  clib_net_to_host_u64 (mp->new_local_cookie),
				  clib_net_to_host_u64
				  (mp->new_remote_cookie));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY);
}

static void vl_api_l2tpv3_interface_enable_disable_t_handler
  (vl_api_l2tpv3_interface_enable_disable_t * mp)
{
  int rv;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_l2tpv3_interface_enable_disable_reply_t *rmp;

  VALIDATE_SW_IF_INDEX (mp);

  rv = l2tpv3_interface_enable_disable
    (vnm, ntohl (mp->sw_if_index), mp->enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void vl_api_l2tpv3_set_lookup_key_t_handler
  (vl_api_l2tpv3_set_lookup_key_t * mp)
{
  int rv = 0;
  l2t_main_t *lm = &l2t_main;
  vl_api_l2tpv3_set_lookup_key_reply_t *rmp;

  if (mp->key > L2T_LOOKUP_SESSION_ID)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  lm->lookup_type = mp->key;

out:
  REPLY_MACRO (VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY);
}

static void vl_api_vxlan_add_del_tunnel_t_handler
  (vl_api_vxlan_add_del_tunnel_t * mp)
{
  vl_api_vxlan_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];

  /* Check src & dst are different */
  if ((mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 16) == 0) ||
      (!mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 4) == 0))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  a->is_ip6 = mp->is_ipv6;

  /* ip addresses sent in network byte order */
  if (a->is_ip6)
    {
      memcpy (&(a->src.ip6), mp->src_address, 16);
      memcpy (&(a->dst.ip6), mp->dst_address, 16);
    }
  else
    {
      memcpy (&(a->src.ip4), mp->src_address, 4);
      memcpy (&(a->dst.ip4), mp->dst_address, 4);
    }

  a->encap_fib_index = encap_fib_index;
  a->decap_next_index = ntohl (mp->decap_next_index);
  a->vni = ntohl (mp->vni);
  rv = vnet_vxlan_add_del_tunnel (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_VXLAN_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_vxlan_tunnel_details
  (vxlan_tunnel_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_vxlan_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !(t->flags & VXLAN_TUNNEL_IS_IPV4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->src_address, &(t->src.ip6), 16);
      memcpy (rmp->dst_address, &(t->dst.ip6), 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].table_id);
    }
  else
    {
      memcpy (rmp->src_address, &(t->src.ip4), 4);
      memcpy (rmp->dst_address, &(t->dst.ip4), 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].table_id);
    }
  rmp->vni = htonl (t->vni);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->is_ipv6 = is_ipv6;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void vl_api_vxlan_tunnel_dump_t_handler
  (vl_api_vxlan_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, vxm->tunnels,
      ({
        send_vxlan_tunnel_details(t, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_tunnel_details (t, q, mp->context);
    }
}

static void vl_api_gre_add_del_tunnel_t_handler
  (vl_api_gre_add_del_tunnel_t * mp)
{
  vl_api_gre_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_gre_add_del_tunnel_args_t _a, *a = &_a;
  u32 outer_fib_id;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->outer_fib_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  outer_fib_id = p[0];

  /* Check src & dst are different */
  if ((mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 16) == 0) ||
      (!mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 4) == 0))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;

  /* ip addresses sent in network byte order */
  clib_memcpy (&(a->src), mp->src_address, 4);
  clib_memcpy (&(a->dst), mp->dst_address, 4);

  a->outer_fib_id = outer_fib_id;
  rv = vnet_gre_add_del_tunnel (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GRE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_gre_tunnel_details
  (gre_tunnel_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_gre_tunnel_details_t *rmp;
  ip4_main_t *im = &ip4_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GRE_TUNNEL_DETAILS);
  clib_memcpy (rmp->src_address, &(t->tunnel_src), 4);
  clib_memcpy (rmp->dst_address, &(t->tunnel_dst), 4);
  rmp->outer_fib_id = htonl (im->fibs[t->outer_fib_index].table_id);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_gre_tunnel_dump_t_handler (vl_api_gre_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gm->tunnels,
      ({
        send_gre_tunnel_details(t, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (gm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gm->tunnels[gm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_gre_tunnel_details (t, q, mp->context);
    }
}

static void
vl_api_l2_patch_add_del_t_handler (vl_api_l2_patch_add_del_t * mp)
{
  extern int vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index,
				    int is_add);
  vl_api_l2_patch_add_del_reply_t *rmp;
  int vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index,
			     int is_add);
  int rv = 0;

  VALIDATE_RX_SW_IF_INDEX (mp);
  VALIDATE_TX_SW_IF_INDEX (mp);

  rv = vnet_l2_patch_add_del (ntohl (mp->rx_sw_if_index),
			      ntohl (mp->tx_sw_if_index),
			      (int) (mp->is_add != 0));

  BAD_RX_SW_IF_INDEX_LABEL;
  BAD_TX_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_PATCH_ADD_DEL_REPLY);
}

static void
  vl_api_vxlan_gpe_add_del_tunnel_t_handler
  (vl_api_vxlan_gpe_add_del_tunnel_t * mp)
{
  vl_api_vxlan_gpe_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index, decap_fib_index;
  u8 protocol;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;


  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];

  protocol = mp->protocol;

  /* Interpret decap_vrf_id as an opaque if sending to other-than-ip4-input */
  if (protocol == VXLAN_GPE_INPUT_NEXT_IP4_INPUT)
    {
      p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
	  goto out;
	}
      decap_fib_index = p[0];
    }
  else
    {
      decap_fib_index = ntohl (mp->decap_vrf_id);
    }

  /* Check src & dst are different */
  if ((mp->is_ipv6 && memcmp (mp->local, mp->remote, 16) == 0) ||
      (!mp->is_ipv6 && memcmp (mp->local, mp->remote, 4) == 0))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  a->is_ip6 = mp->is_ipv6;
  /* ip addresses sent in network byte order */
  if (a->is_ip6)
    {
      clib_memcpy (&(a->local.ip6), mp->local, 16);
      clib_memcpy (&(a->remote.ip6), mp->remote, 16);
    }
  else
    {
      clib_memcpy (&(a->local.ip4), mp->local, 4);
      clib_memcpy (&(a->remote.ip4), mp->remote, 4);
    }
  a->encap_fib_index = encap_fib_index;
  a->decap_fib_index = decap_fib_index;
  a->protocol = protocol;
  a->vni = ntohl (mp->vni);
  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_vxlan_gpe_tunnel_details
  (vxlan_gpe_tunnel_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_vxlan_gpe_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !(t->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_GPE_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->local, &(t->local.ip6), 16);
      memcpy (rmp->remote, &(t->remote.ip6), 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].table_id);
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].table_id);
    }
  else
    {
      memcpy (rmp->local, &(t->local.ip4), 4);
      memcpy (rmp->remote, &(t->remote.ip4), 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].table_id);
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].table_id);
    }
  rmp->vni = htonl (t->vni);
  rmp->protocol = t->protocol;
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->is_ipv6 = is_ipv6;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void vl_api_vxlan_gpe_tunnel_dump_t_handler
  (vl_api_vxlan_gpe_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vxlan_gpe_main_t *vgm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, vgm->tunnels,
      ({
        send_vxlan_gpe_tunnel_details(t, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (vgm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vgm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vgm->tunnels[vgm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_gpe_tunnel_details (t, q, mp->context);
    }
}

/** Used for transferring locators via VPP API */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u32 sw_if_index; /**< locator sw_if_index */
  u8 priority; /**< locator priority */
  u8 weight; /**< locator weight */
}) ls_locator_t;
/* *INDENT-ON* */

static void
vl_api_lisp_add_del_locator_set_t_handler (vl_api_lisp_add_del_locator_set_t *
					   mp)
{
  vl_api_lisp_add_del_locator_set_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  locator_t locator;
  ls_locator_t *ls_loc;
  u32 ls_index = ~0;
  u8 *locator_name = NULL;
  int i;

  memset (a, 0, sizeof (a[0]));

  locator_name = format (0, "%s", mp->locator_set_name);

  a->name = locator_name;
  a->is_add = mp->is_add;
  a->local = 1;

  memset (&locator, 0, sizeof (locator));
  for (i = 0; i < mp->locator_num; i++)
    {
      ls_loc = &((ls_locator_t *) mp->locators)[i];
      VALIDATE_SW_IF_INDEX (ls_loc);

      locator.sw_if_index = htonl (ls_loc->sw_if_index);
      locator.priority = ls_loc->priority;
      locator.weight = ls_loc->weight;
      locator.local = 1;
      vec_add1 (a->locators, locator);
    }

  rv = vnet_lisp_add_del_locator_set (a, &ls_index);

  BAD_SW_IF_INDEX_LABEL;

  vec_free (locator_name);
  vec_free (a->locators);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY);
}

static void
vl_api_lisp_add_del_locator_t_handler (vl_api_lisp_add_del_locator_t * mp)
{
  vl_api_lisp_add_del_locator_reply_t *rmp;
  int rv = 0;
  locator_t locator, *locators = NULL;
  vnet_lisp_add_del_locator_set_args_t _a, *a = &_a;
  u32 ls_index = ~0;
  u8 *locator_name = NULL;

  memset (&locator, 0, sizeof (locator));
  memset (a, 0, sizeof (a[0]));

  locator.sw_if_index = ntohl (mp->sw_if_index);
  locator.priority = mp->priority;
  locator.weight = mp->weight;
  locator.local = 1;
  vec_add1 (locators, locator);

  locator_name = format (0, "%s", mp->locator_set_name);

  a->name = locator_name;
  a->locators = locators;
  a->is_add = mp->is_add;
  a->local = 1;

  rv = vnet_lisp_add_del_locator (a, NULL, &ls_index);

  vec_free (locators);
  vec_free (locator_name);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_LOCATOR_REPLY);
}

static int
unformat_lisp_eid_api (gid_address_t * dst, u32 vni, u8 type, void *src,
		       u8 len)
{
  switch (type)
    {
    case 0:			/* ipv4 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP4);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 1:			/* ipv6 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP6);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 2:			/* l2 mac */
      gid_address_type (dst) = GID_ADDR_MAC;
      clib_memcpy (&gid_address_mac (dst), src, 6);
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = vni;

  return 0;
}

static void
vl_api_lisp_add_del_local_eid_t_handler (vl_api_lisp_add_del_local_eid_t * mp)
{
  vl_api_lisp_add_del_local_eid_reply_t *rmp;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;
  uword *p = NULL;
  u32 locator_set_index = ~0, map_index = ~0;
  vnet_lisp_add_del_mapping_args_t _a, *a = &_a;
  u8 *name = NULL;
  memset (a, 0, sizeof (a[0]));
  memset (eid, 0, sizeof (eid[0]));

  rv = unformat_lisp_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->eid, mp->prefix_len);
  if (rv)
    goto out;

  name = format (0, "%s", mp->locator_set_name);
  p = hash_get_mem (lcm->locator_set_index_by_name, name);
  if (!p)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }
  locator_set_index = p[0];

  /* XXX treat batch configuration */
  a->is_add = mp->is_add;
  gid_address_copy (&a->eid, eid);
  a->locator_set_index = locator_set_index;
  a->local = 1;
  rv = vnet_lisp_add_del_local_mapping (a, &map_index);

out:
  vec_free (name);
  gid_address_free (&a->eid);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY);
}

static void
  vl_api_lisp_eid_table_add_del_map_t_handler
  (vl_api_lisp_eid_table_add_del_map_t * mp)
{
  vl_api_lisp_eid_table_add_del_map_reply_t *rmp;
  int rv = 0;
  rv = vnet_lisp_eid_table_map (clib_net_to_host_u32 (mp->vni),
				clib_net_to_host_u32 (mp->dp_table),
				mp->is_l2, mp->is_add);
REPLY_MACRO (VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY)}

/** Used for transferring locators via VPP API */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 is_ip4; /**< is locator an IPv4 address */
  u8 priority; /**< locator priority */
  u8 weight; /**< locator weight */
  u8 addr[16]; /**< IPv4/IPv6 address */
}) rloc_t;
/* *INDENT-ON* */

static locator_pair_t *
unformat_lisp_loc_pairs (void *lcl_locs, void *rmt_locs, u32 rloc_num)
{
  u32 i;
  locator_pair_t *pairs = 0, pair;
  rloc_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* local locator */
      r = &((rloc_t *) lcl_locs)[i];
      memset (&pair.lcl_loc, 0, sizeof (pair.lcl_loc));
      ip_address_set (&pair.lcl_loc, &r->addr, r->is_ip4 ? IP4 : IP6);

      /* remote locators */
      r = &((rloc_t *) rmt_locs)[i];
      memset (&pair.rmt_loc, 0, sizeof (pair.rmt_loc));
      ip_address_set (&pair.rmt_loc, &r->addr, r->is_ip4 ? IP4 : IP6);

      pair.priority = r->priority;
      pair.weight = r->weight;

      vec_add1 (pairs, pair);
    }
  return pairs;
}

static locator_t *
unformat_lisp_locs (void *rmt_locs, u32 rloc_num)
{
  u32 i;
  locator_t *locs = 0, loc;
  rloc_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* remote locators */
      r = &((rloc_t *) rmt_locs)[i];
      memset (&loc, 0, sizeof (loc));
      gid_address_ip_set (&loc.address, &r->addr, r->is_ip4 ? IP4 : IP6);

      loc.priority = r->priority;
      loc.weight = r->weight;

      vec_add1 (locs, loc);
    }
  return locs;
}

static void
  vl_api_lisp_gpe_add_del_fwd_entry_t_handler
  (vl_api_lisp_gpe_add_del_fwd_entry_t * mp)
{
  vl_api_lisp_gpe_add_del_fwd_entry_reply_t *rmp;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  locator_pair_t *pairs = 0;
  int rv = 0;

  memset (a, 0, sizeof (a[0]));

  rv = unformat_lisp_eid_api (&a->rmt_eid, mp->vni, mp->eid_type,
			      mp->rmt_eid, mp->rmt_len);
  rv |= unformat_lisp_eid_api (&a->lcl_eid, mp->vni, mp->eid_type,
			       mp->lcl_eid, mp->lcl_len);

  pairs = unformat_lisp_loc_pairs (mp->lcl_locs, mp->rmt_locs, mp->loc_num);

  if (rv || 0 == pairs)
    goto send_reply;

  a->is_add = mp->is_add;
  a->locator_pairs = pairs;
  a->dp_table = mp->dp_table;
  a->vni = mp->vni;
  a->action = mp->action;

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, 0);
  vec_free (pairs);
send_reply:
  REPLY_MACRO (VL_API_LISP_GPE_ADD_DEL_FWD_ENTRY_REPLY);
}

static void
vl_api_lisp_add_del_map_resolver_t_handler (vl_api_lisp_add_del_map_resolver_t
					    * mp)
{
  vl_api_lisp_add_del_map_resolver_reply_t *rmp;
  int rv = 0;
  vnet_lisp_add_del_map_resolver_args_t _a, *a = &_a;

  memset (a, 0, sizeof (a[0]));

  a->is_add = mp->is_add;
  ip_address_set (&a->address, mp->ip_address, mp->is_ipv6 ? IP6 : IP4);

  rv = vnet_lisp_add_del_map_resolver (a);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY);
}

static void
vl_api_lisp_gpe_enable_disable_t_handler (vl_api_lisp_gpe_enable_disable_t *
					  mp)
{
  vl_api_lisp_gpe_enable_disable_reply_t *rmp;
  int rv = 0;
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;

  a->is_en = mp->is_en;
  vnet_lisp_gpe_enable_disable (a);

  REPLY_MACRO (VL_API_LISP_GPE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_lisp_enable_disable_t_handler (vl_api_lisp_enable_disable_t * mp)
{
  vl_api_lisp_enable_disable_reply_t *rmp;
  int rv = 0;

  vnet_lisp_enable_disable (mp->is_en);
  REPLY_MACRO (VL_API_LISP_ENABLE_DISABLE_REPLY);
}

static void
vl_api_lisp_gpe_add_del_iface_t_handler (vl_api_lisp_gpe_add_del_iface_t * mp)
{
  vl_api_lisp_gpe_add_del_iface_reply_t *rmp;
  int rv = 0;
  vnet_lisp_gpe_add_del_iface_args_t _a, *a = &_a;

  a->is_add = mp->is_add;
  a->dp_table = mp->dp_table;
  a->vni = mp->vni;
  a->is_l2 = mp->is_l2;
  rv = vnet_lisp_gpe_add_del_iface (a, 0);

  REPLY_MACRO (VL_API_LISP_GPE_ADD_DEL_IFACE_REPLY);
}

static void
vl_api_lisp_pitr_set_locator_set_t_handler (vl_api_lisp_pitr_set_locator_set_t
					    * mp)
{
  vl_api_lisp_pitr_set_locator_set_reply_t *rmp;
  int rv = 0;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);
  rv = vnet_lisp_pitr_set_locator_set (ls_name, mp->is_add);
  vec_free (ls_name);

  REPLY_MACRO (VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY);
}

static void
  vl_api_lisp_add_del_map_request_itr_rlocs_t_handler
  (vl_api_lisp_add_del_map_request_itr_rlocs_t * mp)
{
  vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *rmp;
  int rv = 0;
  u8 *locator_set_name = NULL;
  vnet_lisp_add_del_mreq_itr_rloc_args_t _a, *a = &_a;

  locator_set_name = format (0, "%s", mp->locator_set_name);

  a->is_add = mp->is_add;
  a->locator_set_name = locator_set_name;

  rv = vnet_lisp_add_del_mreq_itr_rlocs (a);

  vec_free (locator_set_name);

  REPLY_MACRO (VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY);
}

static void
  vl_api_lisp_add_del_remote_mapping_t_handler
  (vl_api_lisp_add_del_remote_mapping_t * mp)
{
  locator_t *rlocs = 0;
  vl_api_lisp_add_del_remote_mapping_reply_t *rmp;
  int rv = 0;
  gid_address_t _eid, *eid = &_eid;

  memset (eid, 0, sizeof (eid[0]));

  rv = unformat_lisp_eid_api (eid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->eid, mp->eid_len);
  if (rv)
    goto send_reply;

  rlocs = unformat_lisp_locs (mp->rlocs, mp->rloc_num);
  if (0 == rlocs)
    goto send_reply;

  if (!mp->is_add)
    {
      vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;
      gid_address_copy (&a->deid, eid);
      a->is_add = 0;
      rv = vnet_lisp_add_del_adjacency (a);
      if (rv)
	{
	  goto out;
	}
    }

  /* NOTE: for now this works as a static remote mapping, i.e.,
   * not authoritative and ttl infinite. */
  rv = vnet_lisp_add_del_mapping (eid, rlocs, mp->action, 0, ~0,
				  mp->is_add, 0);

  if (mp->del_all)
    vnet_lisp_clear_all_remote_adjacencies ();

out:
  vec_free (rlocs);
send_reply:
  REPLY_MACRO (VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY);
}

static void
vl_api_lisp_add_del_adjacency_t_handler (vl_api_lisp_add_del_adjacency_t * mp)
{
  vl_api_lisp_add_del_adjacency_reply_t *rmp;
  vnet_lisp_add_del_adjacency_args_t _a, *a = &_a;

  int rv = 0;
  memset (a, 0, sizeof (a[0]));

  rv = unformat_lisp_eid_api (&a->seid, clib_net_to_host_u32 (mp->vni),
			      mp->eid_type, mp->seid, mp->seid_len);
  rv |= unformat_lisp_eid_api (&a->deid, clib_net_to_host_u32 (mp->vni),
			       mp->eid_type, mp->deid, mp->deid_len);

  if (rv)
    goto send_reply;

  a->is_add = mp->is_add;
  rv = vnet_lisp_add_del_adjacency (a);

send_reply:
  REPLY_MACRO (VL_API_LISP_ADD_DEL_ADJACENCY_REPLY);
}

static void
send_lisp_locator_details (lisp_cp_main_t * lcm,
			   locator_t * loc,
			   unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_lisp_locator_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_LOCATOR_DETAILS);
  rmp->context = context;

  rmp->local = loc->local;
  if (loc->local)
    {
      rmp->sw_if_index = ntohl (loc->sw_if_index);
    }
  else
    {
      rmp->is_ipv6 = gid_address_ip_version (&loc->address);
      ip_address_copy_addr (rmp->ip_address, &gid_address_ip (&loc->address));
    }
  rmp->priority = loc->priority;
  rmp->weight = loc->weight;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_locator_dump_t_handler (vl_api_lisp_locator_dump_t * mp)
{
  unix_shared_memory_queue_t *q = 0;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = 0;
  locator_t *loc = 0;
  u32 ls_index = ~0, *locit = 0;
  u8 filter;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  ls_index = htonl (mp->locator_set_index);

  lsit = pool_elt_at_index (lcm->locator_set_pool, ls_index);

  filter = mp->filter;
  if (filter && !((1 == filter && lsit->local) ||
		  (2 == filter && !lsit->local)))
    {
      return;
    }

  vec_foreach (locit, lsit->locator_indices)
  {
    loc = pool_elt_at_index (lcm->locator_pool, locit[0]);
    send_lisp_locator_details (lcm, loc, q, mp->context);
  };
}

static void
send_lisp_locator_set_details (lisp_cp_main_t * lcm,
			       locator_set_t * lsit,
			       unix_shared_memory_queue_t * q,
			       u32 context, u32 ls_index)
{
  vl_api_lisp_locator_set_details_t *rmp;
  u8 *str = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_LOCATOR_SET_DETAILS);
  rmp->context = context;

  rmp->local = lsit->local;
  rmp->locator_set_index = htonl (ls_index);
  if (lsit->local)
    {
      ASSERT (lsit->name != NULL);
      strncpy ((char *) rmp->locator_set_name,
	       (char *) lsit->name, ARRAY_LEN (rmp->locator_set_name) - 1);
    }
  else
    {
      str = format (0, "remote-%d", ls_index);
      strncpy ((char *) rmp->locator_set_name, (char *) str,
	       ARRAY_LEN (rmp->locator_set_name) - 1);
      vec_free (str);
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_locator_set_dump_t_handler (vl_api_lisp_locator_set_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *lsit = NULL;
  u32 index;
  u8 filter;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  filter = mp->filter;
  index = 0;
  /* *INDENT-OFF* */
  pool_foreach (lsit, lcm->locator_set_pool,
  ({
    if (filter && !((1 == filter && lsit->local) ||
                    (2 == filter && !lsit->local))) {
      index++;
      continue;
    }
    send_lisp_locator_set_details(lcm, lsit, q, mp->context, index++);
  }));
  /* *INDENT-ON* */
}

static void
send_lisp_eid_table_details (mapping_t * mapit,
			     unix_shared_memory_queue_t * q,
			     u32 context, u8 filter)
{
  vl_api_lisp_eid_table_details_t *rmp = NULL;
  gid_address_t *gid = NULL;
  u8 *mac = 0;
  ip_prefix_t *ip_prefix = NULL;

  switch (filter)
    {
    case 0: /* all mappings */
      break;

    case 1: /* local only */
      if (!mapit->local)
        return;

    case 2: /* remote only */
      if (mapit->local)
        return;

    default:
      clib_warning ("Filter error, unknown filter: %d", filter);
      return;
    }

  gid = &mapit->eid;
  ip_prefix = &gid_address_ippref (gid);
  mac = gid_address_mac (gid);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_DETAILS);
  rmp->locator_set_index = mapit->locator_set_index;
  rmp->is_local = mapit->local;
  rmp->ttl = mapit->ttl;
  rmp->authoritative = mapit->authoritative;

  switch (gid_address_type (gid))
    {
    case GID_ADDR_IP_PREFIX:
      rmp->eid_prefix_len = ip_prefix_len (ip_prefix);
      if (ip_prefix_version (ip_prefix) == IP4)
	{
	  rmp->eid_type = 0;	/* ipv4 type */
	  clib_memcpy (rmp->eid, &ip_prefix_v4 (ip_prefix),
		       sizeof (ip_prefix_v4 (ip_prefix)));
	}
      else
	{
	  rmp->eid_type = 1;	/* ipv6 type */
	  clib_memcpy (rmp->eid, &ip_prefix_v6 (ip_prefix),
		       sizeof (ip_prefix_v6 (ip_prefix)));
	}
      break;
    case GID_ADDR_MAC:
      rmp->eid_type = 2;	/* l2 mac type */
      clib_memcpy (rmp->eid, mac, 6);
      break;
    default:
      ASSERT (0);
    }
  rmp->context = context;
  rmp->vni = clib_host_to_net_u32 (gid_address_vni (gid));
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_eid_table_dump_t_handler (vl_api_lisp_eid_table_dump_t * mp)
{
  u32 mi;
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *mapit = NULL;
  gid_address_t _eid, *eid = &_eid;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->eid_set)
    {
      memset (eid, 0, sizeof (*eid));

      unformat_lisp_eid_api (eid, mp->eid_type,
			     clib_net_to_host_u32 (mp->vni), mp->eid,
			     mp->prefix_length);

      mi = gid_dictionary_lookup (&lcm->mapping_index_by_gid, eid);
      if ((u32) ~ 0 == mi)
	return;

      mapit = pool_elt_at_index (lcm->mapping_pool, mi);
      send_lisp_eid_table_details (mapit, q, mp->context,
                                   0 /* ignore filter */);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (mapit, lcm->mapping_pool,
      ({
        send_lisp_eid_table_details(mapit, q, mp->context,
                                    mp->filter);
      }));
      /* *INDENT-ON* */
    }
}

static void
send_lisp_gpe_tunnel_details (lisp_gpe_tunnel_t * tunnel,
			      unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_lisp_gpe_tunnel_details_t *rmp;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_GPE_TUNNEL_DETAILS);

  rmp->tunnels = tunnel - lgm->tunnels;

  rmp->is_ipv6 = ip_addr_version (&tunnel->src) == IP6 ? 1 : 0;
  ip_address_copy_addr (rmp->source_ip, &tunnel->src);
  ip_address_copy_addr (rmp->destination_ip, &tunnel->dst);

  rmp->encap_fib_id = htonl (tunnel->encap_fib_index);
  rmp->decap_fib_id = htonl (tunnel->decap_fib_index);
  rmp->dcap_next = htonl (tunnel->decap_next_index);
  rmp->lisp_ver = tunnel->ver_res;
  rmp->next_protocol = tunnel->next_protocol;
  rmp->flags = tunnel->flags;
  rmp->ver_res = tunnel->ver_res;
  rmp->res = tunnel->res;
  rmp->iid = htonl (tunnel->vni);
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_gpe_tunnel_dump_t_handler (vl_api_lisp_gpe_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *tunnel = NULL;

  if (pool_elts (lgm->tunnels) == 0)
    {
      return;
    }

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach(tunnel, lgm->tunnels,
  ({
    send_lisp_gpe_tunnel_details(tunnel, q, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
send_lisp_map_resolver_details (ip_address_t * ip,
				unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_lisp_map_resolver_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_MAP_RESOLVER_DETAILS);

  switch (ip_addr_version (ip))
    {
    case IP4:
      rmp->is_ipv6 = 0;
      clib_memcpy (rmp->ip_address, &ip_addr_v4 (ip),
		   sizeof (ip_addr_v4 (ip)));
      break;

    case IP6:
      rmp->is_ipv6 = 1;
      clib_memcpy (rmp->ip_address, &ip_addr_v6 (ip),
		   sizeof (ip_addr_v6 (ip)));
      break;

    default:
      ASSERT (0);
    }
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_map_resolver_dump_t_handler (vl_api_lisp_map_resolver_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  ip_address_t *ip = NULL;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  vec_foreach (ip, lcm->map_resolvers)
  {
    send_lisp_map_resolver_details (ip, q, mp->context);
  }

}

static void
send_eid_table_map_pair (hash_pair_t * p,
			 unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_lisp_eid_table_map_details_t *rmp = NULL;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_LISP_EID_TABLE_MAP_DETAILS);

  rmp->vni = clib_host_to_net_u32 (p->key);
  rmp->vrf = clib_host_to_net_u32 (p->value[0]);
  rmp->context = context;
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_lisp_eid_table_map_dump_t_handler (vl_api_lisp_eid_table_map_dump_t *
					  mp)
{
  unix_shared_memory_queue_t *q = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  hash_pair_t *p;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }
  /* *INDENT-OFF* */
  hash_foreach_pair (p, lcm->table_id_by_vni,
  ({
    send_eid_table_map_pair (p, q, mp->context);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_show_lisp_status_t_handler (vl_api_show_lisp_status_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_lisp_status_reply_t *rmp = NULL;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_LISP_STATUS_REPLY,
  ({
    rmp->gpe_status = vnet_lisp_gpe_enable_disable_status ();
    rmp->feature_status = vnet_lisp_enable_disable_status ();
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_lisp_get_map_request_itr_rlocs_t_handler
  (vl_api_lisp_get_map_request_itr_rlocs_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_lisp_get_map_request_itr_rlocs_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  locator_set_t *loc_set = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (~0 == lcm->mreq_itr_rlocs)
    {
      tmp_str = format (0, " ");
    }
  else
    {
      loc_set =
	pool_elt_at_index (lcm->locator_set_pool, lcm->mreq_itr_rlocs);
      tmp_str = format (0, "%s", loc_set->name);
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY,
  ({
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */

  vec_free (tmp_str);
}

static void
vl_api_show_lisp_pitr_t_handler (vl_api_show_lisp_pitr_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  vl_api_show_lisp_pitr_reply_t *rmp = NULL;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  mapping_t *m;
  locator_set_t *ls = 0;
  u8 *tmp_str = 0;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (!lcm->lisp_pitr)
    {
      tmp_str = format (0, "N/A");
    }
  else
    {
      m = pool_elt_at_index (lcm->mapping_pool, lcm->pitr_map_index);
      if (~0 != m->locator_set_index)
	{
	  ls =
	    pool_elt_at_index (lcm->locator_set_pool, m->locator_set_index);
	  tmp_str = format (0, "%s", ls->name);
	}
      else
	{
	  tmp_str = format (0, "N/A");
	}
    }
  vec_add1 (tmp_str, 0);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_LISP_PITR_REPLY,
  ({
    rmp->status = lcm->lisp_pitr;
    strncpy((char *) rmp->locator_set_name, (char *) tmp_str,
            ARRAY_LEN(rmp->locator_set_name) - 1);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_interface_name_renumber_t_handler (vl_api_interface_name_renumber_t *
					  mp)
{
  vl_api_interface_name_renumber_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_interface_name_renumber
    (ntohl (mp->sw_if_index), ntohl (mp->new_show_dev_instance));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_INTERFACE_NAME_RENUMBER_REPLY);
}

static int
arp_change_data_callback (u32 pool_index, u8 * new_mac,
			  u32 sw_if_index, u32 address)
{
  vpe_api_main_t *am = &vpe_api_main;
  vlib_main_t *vm = am->vlib_main;
  vl_api_ip4_arp_event_t *event;
  static f64 arp_event_last_time;
  f64 now = vlib_time_now (vm);

  if (pool_is_free_index (am->arp_events, pool_index))
    return 1;

  event = pool_elt_at_index (am->arp_events, pool_index);
  if (memcmp (&event->new_mac, new_mac, sizeof (event->new_mac)))
    {
      clib_memcpy (event->new_mac, new_mac, sizeof (event->new_mac));
    }
  else
    {				/* same mac */
      if ((sw_if_index == event->sw_if_index) && ((address == 0) ||
						  /* for BD case, also check IP address with 10 sec timeout */
						  ((address == event->address)
						   &&
						   ((now -
						     arp_event_last_time) <
						    10.0))))
	return 1;
    }

  arp_event_last_time = now;
  event->sw_if_index = sw_if_index;
  if (address)
    event->address = address;
  return 0;
}

static int
arp_change_delete_callback (u32 pool_index, u8 * notused)
{
  vpe_api_main_t *am = &vpe_api_main;

  if (pool_is_free_index (am->arp_events, pool_index))
    return 1;

  pool_put_index (am->arp_events, pool_index);
  return 0;
}

static void
vl_api_want_ip4_arp_events_t_handler (vl_api_want_ip4_arp_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_want_ip4_arp_events_reply_t *rmp;
  vl_api_ip4_arp_event_t *event;
  int rv;

  if (mp->enable_disable)
    {
      pool_get (am->arp_events, event);
      memset (event, 0, sizeof (*event));

      event->_vl_msg_id = ntohs (VL_API_IP4_ARP_EVENT);
      event->client_index = mp->client_index;
      event->context = mp->context;
      event->address = mp->address;
      event->pid = mp->pid;

      rv = vnet_add_del_ip4_arp_change_event
	(vnm, arp_change_data_callback,
	 mp->pid, &mp->address /* addr, in net byte order */ ,
	 vpe_resolver_process_node.index,
	 IP4_ARP_EVENT, event - am->arp_events, 1 /* is_add */ );
    }
  else
    {
      rv = vnet_add_del_ip4_arp_change_event
	(vnm, arp_change_delete_callback,
	 mp->pid, &mp->address /* addr, in net byte order */ ,
	 vpe_resolver_process_node.index,
	 IP4_ARP_EVENT, ~0 /* pool index */ , 0 /* is_add */ );
    }
  REPLY_MACRO (VL_API_WANT_IP4_ARP_EVENTS_REPLY);
}

static void vl_api_input_acl_set_interface_t_handler
  (vl_api_input_acl_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_input_acl_set_interface_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index, l2_table_index;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  l2_table_index = ntohl (mp->l2_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_set_input_acl_intfc (vm, sw_if_index, ip4_table_index,
				 ip6_table_index, l2_table_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_INPUT_ACL_SET_INTERFACE_REPLY);
}

static void vl_api_ipsec_spd_add_del_t_handler
  (vl_api_ipsec_spd_add_del_t * mp)
{
#if IPSEC == 0
  clib_warning ("unimplemented");
#else

  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_add_del_reply_t *rmp;
  int rv;

#if DPDK > 0
  rv = ipsec_add_del_spd (vm, ntohl (mp->spd_id), mp->is_add);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IPSEC_SPD_ADD_DEL_REPLY);
#endif
}

static void vl_api_ipsec_interface_add_del_spd_t_handler
  (vl_api_ipsec_interface_add_del_spd_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
  int rv;
  u32 sw_if_index __attribute__ ((unused));
  u32 spd_id __attribute__ ((unused));

  sw_if_index = ntohl (mp->sw_if_index);
  spd_id = ntohl (mp->spd_id);

  VALIDATE_SW_IF_INDEX (mp);

#if IPSEC > 0
  rv = ipsec_set_interface_spd (vm, sw_if_index, spd_id, mp->is_add);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY);
}

static void vl_api_ipsec_spd_add_del_entry_t_handler
  (vl_api_ipsec_spd_add_del_entry_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_spd_add_del_entry_reply_t *rmp;
  int rv;

#if IPSEC > 0
  ipsec_policy_t p;

  memset (&p, 0, sizeof (p));

  p.id = ntohl (mp->spd_id);
  p.priority = ntohl (mp->priority);
  p.is_outbound = mp->is_outbound;
  p.is_ipv6 = mp->is_ipv6;

  if (mp->is_ipv6 || mp->is_ip_any)
    {
      clib_memcpy (&p.raddr.start, mp->remote_address_start, 16);
      clib_memcpy (&p.raddr.stop, mp->remote_address_stop, 16);
      clib_memcpy (&p.laddr.start, mp->local_address_start, 16);
      clib_memcpy (&p.laddr.stop, mp->local_address_stop, 16);
    }
  else
    {
      clib_memcpy (&p.raddr.start.ip4.data, mp->remote_address_start, 4);
      clib_memcpy (&p.raddr.stop.ip4.data, mp->remote_address_stop, 4);
      clib_memcpy (&p.laddr.start.ip4.data, mp->local_address_start, 4);
      clib_memcpy (&p.laddr.stop.ip4.data, mp->local_address_stop, 4);
    }
  p.protocol = mp->protocol;
  p.rport.start = ntohs (mp->remote_port_start);
  p.rport.stop = ntohs (mp->remote_port_stop);
  p.lport.start = ntohs (mp->local_port_start);
  p.lport.stop = ntohs (mp->local_port_stop);
  /* policy action resolve unsupported */
  if (mp->policy == IPSEC_POLICY_ACTION_RESOLVE)
    {
      clib_warning ("unsupported action: 'resolve'");
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  p.policy = mp->policy;
  p.sa_id = ntohl (mp->sa_id);

  rv = ipsec_add_del_policy (vm, &p, mp->is_add);
  if (rv)
    goto out;

  if (mp->is_ip_any)
    {
      p.is_ipv6 = 1;
      rv = ipsec_add_del_policy (vm, &p, mp->is_add);
    }
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  goto out;
#endif

out:
  REPLY_MACRO (VL_API_IPSEC_SPD_ADD_DEL_ENTRY_REPLY);
}

static void vl_api_ipsec_sad_add_del_entry_t_handler
  (vl_api_ipsec_sad_add_del_entry_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sad_add_del_entry_reply_t *rmp;
  int rv;
#if IPSEC > 0
  ipsec_sa_t sa;

  memset (&sa, 0, sizeof (sa));

  sa.id = ntohl (mp->sad_id);
  sa.spi = ntohl (mp->spi);
  /* security protocol AH unsupported */
  if (mp->protocol == IPSEC_PROTOCOL_AH)
    {
      clib_warning ("unsupported security protocol 'AH'");
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  sa.protocol = mp->protocol;
  /* check for unsupported crypto-alg */
  if (mp->crypto_algorithm < IPSEC_CRYPTO_ALG_AES_CBC_128 ||
      mp->crypto_algorithm > IPSEC_CRYPTO_ALG_AES_CBC_256)
    {
      clib_warning ("unsupported crypto-alg: '%U'", format_ipsec_crypto_alg,
		    mp->crypto_algorithm);
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  sa.crypto_alg = mp->crypto_algorithm;
  sa.crypto_key_len = mp->crypto_key_length;
  clib_memcpy (&sa.crypto_key, mp->crypto_key, sizeof (sa.crypto_key));
  /* check for unsupported integ-alg */
  if (mp->integrity_algorithm < IPSEC_INTEG_ALG_SHA1_96 ||
      mp->integrity_algorithm > IPSEC_INTEG_ALG_SHA_512_256)
    {
      clib_warning ("unsupported integ-alg: '%U'", format_ipsec_integ_alg,
		    mp->integrity_algorithm);
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }
  sa.integ_alg = mp->integrity_algorithm;
  sa.integ_key_len = mp->integrity_key_length;
  clib_memcpy (&sa.integ_key, mp->integrity_key, sizeof (sa.integ_key));
  sa.use_esn = mp->use_extended_sequence_number;
  sa.is_tunnel = mp->is_tunnel;
  sa.is_tunnel_ip6 = mp->is_tunnel_ipv6;
  if (sa.is_tunnel_ip6)
    {
      clib_memcpy (&sa.tunnel_src_addr, mp->tunnel_src_address, 16);
      clib_memcpy (&sa.tunnel_dst_addr, mp->tunnel_dst_address, 16);
    }
  else
    {
      clib_memcpy (&sa.tunnel_src_addr.ip4.data, mp->tunnel_src_address, 4);
      clib_memcpy (&sa.tunnel_dst_addr.ip4.data, mp->tunnel_dst_address, 4);
    }

  rv = ipsec_add_del_sa (vm, &sa, mp->is_add);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
  goto out;
#endif

out:
  REPLY_MACRO (VL_API_IPSEC_SAD_ADD_DEL_ENTRY_REPLY);
}

static void
vl_api_ikev2_profile_add_del_t_handler (vl_api_ikev2_profile_add_del_t * mp)
{
  vl_api_ikev2_profile_add_del_reply_t *rmp;
  int rv = 0;

#if IPSEC > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_add_del_profile (vm, tmp, mp->is_add);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_ADD_DEL_REPLY);
}

static void
  vl_api_ikev2_profile_set_auth_t_handler
  (vl_api_ikev2_profile_set_auth_t * mp)
{
  vl_api_ikev2_profile_set_auth_reply_t *rmp;
  int rv = 0;

#if IPSEC > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  u8 *data = vec_new (u8, mp->data_len);
  clib_memcpy (data, mp->data, mp->data_len);
  error = ikev2_set_profile_auth (vm, tmp, mp->auth_method, data, mp->is_hex);
  vec_free (tmp);
  vec_free (data);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_AUTH_REPLY);
}

static void
vl_api_ikev2_profile_set_id_t_handler (vl_api_ikev2_profile_set_id_t * mp)
{
  vl_api_ikev2_profile_add_del_reply_t *rmp;
  int rv = 0;

#if IPSEC > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  u8 *data = vec_new (u8, mp->data_len);
  clib_memcpy (data, mp->data, mp->data_len);
  error = ikev2_set_profile_id (vm, tmp, mp->id_type, data, mp->is_local);
  vec_free (tmp);
  vec_free (data);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_ID_REPLY);
}

static void
vl_api_ikev2_profile_set_ts_t_handler (vl_api_ikev2_profile_set_ts_t * mp)
{
  vl_api_ikev2_profile_set_ts_reply_t *rmp;
  int rv = 0;

#if IPSEC > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  u8 *tmp = format (0, "%s", mp->name);
  error = ikev2_set_profile_ts (vm, tmp, mp->proto, mp->start_port,
				mp->end_port, (ip4_address_t) mp->start_addr,
				(ip4_address_t) mp->end_addr, mp->is_local);
  vec_free (tmp);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_PROFILE_SET_TS_REPLY);
}

static void
vl_api_ikev2_set_local_key_t_handler (vl_api_ikev2_set_local_key_t * mp)
{
  vl_api_ikev2_profile_set_ts_reply_t *rmp;
  int rv = 0;

#if IPSEC > 0
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;

  error = ikev2_set_local_key (vm, mp->key_file);
  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IKEV2_SET_LOCAL_KEY_REPLY);
}

static void
vl_api_map_add_domain_t_handler (vl_api_map_add_domain_t * mp)
{
  vl_api_map_add_domain_reply_t *rmp;
  int rv = 0;
  u32 index;
  u8 flags = mp->is_translation ? MAP_DOMAIN_TRANSLATION : 0;
  rv =
    map_create_domain ((ip4_address_t *) & mp->ip4_prefix, mp->ip4_prefix_len,
		       (ip6_address_t *) & mp->ip6_prefix, mp->ip6_prefix_len,
		       (ip6_address_t *) & mp->ip6_src,
		       mp->ip6_src_prefix_len, mp->ea_bits_len,
		       mp->psid_offset, mp->psid_length, &index,
		       ntohs (mp->mtu), flags);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MAP_ADD_DOMAIN_REPLY,
  ({
    rmp->index = ntohl(index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_del_domain_t_handler (vl_api_map_del_domain_t * mp)
{
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv = map_delete_domain (ntohl (mp->index));

  REPLY_MACRO (VL_API_MAP_DEL_DOMAIN_REPLY);
}

static void
vl_api_map_add_del_rule_t_handler (vl_api_map_add_del_rule_t * mp)
{
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv =
    map_add_del_psid (ntohl (mp->index), ntohs (mp->psid),
		      (ip6_address_t *) mp->ip6_dst, mp->is_add);

  REPLY_MACRO (VL_API_MAP_ADD_DEL_RULE_REPLY);
}

static void
vl_api_map_domain_dump_t_handler (vl_api_map_domain_dump_t * mp)
{
  vl_api_map_domain_details_t *rmp;
  map_main_t *mm = &map_main;
  map_domain_t *d;
  unix_shared_memory_queue_t *q;

  if (pool_elts (mm->domains) == 0)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach(d, mm->domains,
  ({
    /* Make sure every field is initiated (or don't skip the memset()) */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs(VL_API_MAP_DOMAIN_DETAILS);
    rmp->domain_index = htonl(d - mm->domains);
    rmp->ea_bits_len = d->ea_bits_len;
    rmp->psid_offset = d->psid_offset;
    rmp->psid_length = d->psid_length;
    clib_memcpy(rmp->ip4_prefix, &d->ip4_prefix, sizeof(rmp->ip4_prefix));
    rmp->ip4_prefix_len = d->ip4_prefix_len;
    clib_memcpy(rmp->ip6_prefix, &d->ip6_prefix, sizeof(rmp->ip6_prefix));
    rmp->ip6_prefix_len = d->ip6_prefix_len;
    clib_memcpy(rmp->ip6_src, &d->ip6_src, sizeof(rmp->ip6_src));
    rmp->ip6_src_len = d->ip6_src_len;
    rmp->mtu = htons(d->mtu);
    rmp->is_translation = (d->flags & MAP_DOMAIN_TRANSLATION);
    rmp->context = mp->context;

    vl_msg_api_send_shmem (q, (u8 *)&rmp);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_rule_dump_t_handler (vl_api_map_rule_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  u16 i;
  ip6_address_t dst;
  vl_api_map_rule_details_t *rmp;
  map_main_t *mm = &map_main;
  u32 domain_index = ntohl (mp->domain_index);
  map_domain_t *d;

  if (pool_elts (mm->domains) == 0)
    return;

  d = pool_elt_at_index (mm->domains, domain_index);
  if (!d || !d->rules)
    {
      return;
    }

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  for (i = 0; i < (0x1 << d->psid_length); i++)
    {
      dst = d->rules[i];
      if (dst.as_u64[0] == 0 && dst.as_u64[1] == 0)
	{
	  continue;
	}
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_MAP_RULE_DETAILS);
      rmp->psid = htons (i);
      clib_memcpy (rmp->ip6_dst, &dst, sizeof (rmp->ip6_dst));
      rmp->context = mp->context;
      vl_msg_api_send_shmem (q, (u8 *) & rmp);
    }
}

static void
vl_api_map_summary_stats_t_handler (vl_api_map_summary_stats_t * mp)
{
  vl_api_map_summary_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  vlib_counter_t v;
  int i, which;
  u64 total_pkts[VLIB_N_RX_TX];
  u64 total_bytes[VLIB_N_RX_TX];
  map_main_t *mm = &map_main;
  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_MAP_SUMMARY_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;

  memset (total_pkts, 0, sizeof (total_pkts));
  memset (total_bytes, 0, sizeof (total_bytes));

  map_domain_counter_lock (mm);
  vec_foreach (cm, mm->domain_counters)
  {
    which = cm - mm->domain_counters;

    for (i = 0; i < vec_len (cm->maxi); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }

  map_domain_counter_unlock (mm);

  /* Note: in network byte order! */
  rmp->total_pkts[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_pkts[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bindings = clib_host_to_net_u64 (pool_elts (mm->domains));
  rmp->total_ip4_fragments = 0;	// Not yet implemented. Should be a simple counter.
  rmp->total_security_check[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_ENCAP_SEC_CHECK));
  rmp->total_security_check[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_DECAP_SEC_CHECK));

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_ipsec_sa_set_key_t_handler (vl_api_ipsec_sa_set_key_t * mp)
{
  vlib_main_t *vm __attribute__ ((unused)) = vlib_get_main ();
  vl_api_ipsec_sa_set_key_reply_t *rmp;
  int rv;
#if IPSEC > 0
  ipsec_sa_t sa;
  sa.id = ntohl (mp->sa_id);
  sa.crypto_key_len = mp->crypto_key_length;
  clib_memcpy (&sa.crypto_key, mp->crypto_key, sizeof (sa.crypto_key));
  sa.integ_key_len = mp->integrity_key_length;
  clib_memcpy (&sa.integ_key, mp->integrity_key, sizeof (sa.integ_key));

  rv = ipsec_set_sa_key (vm, &sa);
#else
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif

  REPLY_MACRO (VL_API_IPSEC_SA_SET_KEY_REPLY);
}

static void vl_api_cop_interface_enable_disable_t_handler
  (vl_api_cop_interface_enable_disable_t * mp)
{
  vl_api_cop_interface_enable_disable_reply_t *rmp;
  int rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int enable_disable;

  VALIDATE_SW_IF_INDEX (mp);

  enable_disable = (int) mp->enable_disable;

  rv = cop_interface_enable_disable (sw_if_index, enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_COP_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void vl_api_cop_whitelist_enable_disable_t_handler
  (vl_api_cop_whitelist_enable_disable_t * mp)
{
  vl_api_cop_whitelist_enable_disable_reply_t *rmp;
  cop_whitelist_enable_disable_args_t _a, *a = &_a;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  a->sw_if_index = sw_if_index;
  a->ip4 = mp->ip4;
  a->ip6 = mp->ip6;
  a->default_cop = mp->default_cop;
  a->fib_id = ntohl (mp->fib_id);

  rv = cop_whitelist_enable_disable (a);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_COP_WHITELIST_ENABLE_DISABLE_REPLY);
}

static void
vl_api_get_node_graph_t_handler (vl_api_get_node_graph_t * mp)
{
  int rv = 0;
  u8 *vector = 0;
  api_main_t *am = &api_main;
  vlib_main_t *vm = vlib_get_main ();
  void *oldheap;
  vl_api_get_node_graph_reply_t *rmp;

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  /*
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   */
  vec_validate (vector, 16384);
  vec_reset_length (vector);

  /* $$$$ FIXME */
  vector = vlib_node_serialize (&vm->node_main, vector,
				(u32) ~ 0 /* all threads */ ,
				1 /* include nexts */ ,
				1 /* include stats */ );

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_GRAPH_REPLY,
  ({
    rmp->reply_in_shmem = (uword) vector;
  }));
  /* *INDENT-ON* */
}

static void vl_api_trace_profile_add_t_handler
  (vl_api_trace_profile_add_t * mp)
{
  int rv = 0;
  vl_api_trace_profile_add_reply_t *rmp;
  clib_error_t *error;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = ip6_ioam_trace_profile_set (mp->trace_num_elt, mp->trace_type,
				      ntohl (mp->node_id),
				      ntohl (mp->trace_app_data),
				      mp->pow_enable, mp->trace_tsp,
				      mp->trace_ppc);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_TRACE_PROFILE_ADD_REPLY);
}

static void vl_api_trace_profile_apply_t_handler
  (vl_api_trace_profile_apply_t * mp)
{
  int rv = 0;
  vl_api_trace_profile_apply_reply_t *rmp;

  if (mp->enable != 0)
    {
      rv = ip6_ioam_set_destination ((ip6_address_t *) (&mp->dest_ipv6),
				     ntohl (mp->prefix_length),
				     ntohl (mp->vrf_id),
				     mp->trace_op == IOAM_HBYH_ADD,
				     mp->trace_op == IOAM_HBYH_POP,
				     mp->trace_op == IOAM_HBYH_MOD);
    }
  else
    {
      //ip6_ioam_clear_destination(&ip6, mp->prefix_length, mp->vrf_id);
    }
  REPLY_MACRO (VL_API_TRACE_PROFILE_APPLY_REPLY);
}

static void vl_api_trace_profile_del_t_handler
  (vl_api_trace_profile_del_t * mp)
{
  int rv = 0;
  vl_api_trace_profile_del_reply_t *rmp;
  clib_error_t *error;

  error = clear_ioam_rewrite_fn ();
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_TRACE_PROFILE_DEL_REPLY);
}

static void
vl_api_af_packet_create_t_handler (vl_api_af_packet_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_af_packet_create_reply_t *rmp;
  int rv = 0;
  u8 *host_if_name = NULL;
  u32 sw_if_index;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = af_packet_create_if (vm, host_if_name,
			    mp->use_random_hw_addr ? 0 : mp->hw_addr,
			    &sw_if_index);

  vec_free (host_if_name);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_AF_PACKET_CREATE_REPLY,
  ({
    rmp->sw_if_index = clib_host_to_net_u32(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_af_packet_delete_t_handler (vl_api_af_packet_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_af_packet_delete_reply_t *rmp;
  int rv = 0;
  u8 *host_if_name = NULL;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = af_packet_delete_if (vm, host_if_name);

  vec_free (host_if_name);

  REPLY_MACRO (VL_API_AF_PACKET_DELETE_REPLY);
}

static void
vl_api_policer_add_del_t_handler (vl_api_policer_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_add_del_reply_t *rmp;
  int rv = 0;
  u8 *name = NULL;
  sse2_qos_pol_cfg_params_st cfg;
  clib_error_t *error;
  u32 policer_index;

  name = format (0, "%s", mp->name);

  memset (&cfg, 0, sizeof (cfg));
  cfg.rfc = mp->type;
  cfg.rnd_type = mp->round_type;
  cfg.rate_type = mp->rate_type;
  cfg.rb.kbps.cir_kbps = mp->cir;
  cfg.rb.kbps.eir_kbps = mp->eir;
  cfg.rb.kbps.cb_bytes = mp->cb;
  cfg.rb.kbps.eb_bytes = mp->eb;
  cfg.conform_action.action_type = mp->conform_action_type;
  cfg.conform_action.dscp = mp->conform_dscp;
  cfg.exceed_action.action_type = mp->exceed_action_type;
  cfg.exceed_action.dscp = mp->exceed_dscp;
  cfg.violate_action.action_type = mp->violate_action_type;
  cfg.violate_action.dscp = mp->violate_dscp;
  cfg.color_aware = mp->color_aware;

  error = policer_add_del (vm, name, &cfg, &policer_index, mp->is_add);

  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_POLICER_ADD_DEL_REPLY,
  ({
    if (rv == 0 &&  mp->is_add)
      rmp->policer_index = ntohl(policer_index);
    else
      rmp->policer_index = ~0;
  }));
  /* *INDENT-ON* */
}

static void
send_policer_details (u8 * name,
		      sse2_qos_pol_cfg_params_st * config,
		      policer_read_response_type_st * templ,
		      unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_policer_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_POLICER_DETAILS);
  mp->context = context;
  mp->cir = htonl (config->rb.kbps.cir_kbps);
  mp->eir = htonl (config->rb.kbps.eir_kbps);
  mp->cb = htonl (config->rb.kbps.cb_bytes);
  mp->eb = htonl (config->rb.kbps.eb_bytes);
  mp->rate_type = config->rate_type;
  mp->round_type = config->rnd_type;
  mp->type = config->rfc;
  mp->conform_action_type = config->conform_action.action_type;
  mp->conform_dscp = config->conform_action.dscp;
  mp->exceed_action_type = config->exceed_action.action_type;
  mp->exceed_dscp = config->exceed_action.dscp;
  mp->violate_action_type = config->violate_action.action_type;
  mp->violate_dscp = config->violate_action.dscp;
  mp->single_rate = templ->single_rate ? 1 : 0;
  mp->color_aware = templ->color_aware ? 1 : 0;
  mp->scale = htonl (templ->scale);
  mp->cir_tokens_per_period = htonl (templ->cir_tokens_per_period);
  mp->pir_tokens_per_period = htonl (templ->pir_tokens_per_period);
  mp->current_limit = htonl (templ->current_limit);
  mp->current_bucket = htonl (templ->current_bucket);
  mp->extended_limit = htonl (templ->extended_limit);
  mp->extended_bucket = htonl (templ->extended_bucket);
  mp->last_update_time = clib_host_to_net_u64 (templ->last_update_time);

  strncpy ((char *) mp->name, (char *) name, ARRAY_LEN (mp->name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_policer_dump_t_handler (vl_api_policer_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vnet_policer_main_t *pm = &vnet_policer_main;
  hash_pair_t *hp;
  uword *p;
  u32 pool_index;
  u8 *match_name = 0;
  u8 *name;
  sse2_qos_pol_cfg_params_st *config;
  policer_read_response_type_st *templ;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  if (mp->match_name_valid)
    {
      match_name = format (0, "%s%c", mp->match_name, 0);
    }

  if (mp->match_name_valid)
    {
      p = hash_get_mem (pm->policer_config_by_name, match_name);
      if (p)
	{
	  pool_index = p[0];
	  config = pool_elt_at_index (pm->configs, pool_index);
	  templ = pool_elt_at_index (pm->policer_templates, pool_index);
	  send_policer_details (match_name, config, templ, q, mp->context);
	}
    }
  else
    {
      /* *INDENT-OFF* */
      hash_foreach_pair (hp, pm->policer_config_by_name,
      ({
        name = (u8 *) hp->key;
        pool_index = hp->value[0];
        config = pool_elt_at_index (pm->configs, pool_index);
        templ = pool_elt_at_index (pm->policer_templates, pool_index);
        send_policer_details(name, config, templ, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
}

static void
  vl_api_policer_classify_set_interface_t_handler
  (vl_api_policer_classify_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_classify_set_interface_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index, l2_table_index;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  l2_table_index = ntohl (mp->l2_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_set_policer_classify_intfc (vm, sw_if_index, ip4_table_index,
					ip6_table_index, l2_table_index,
					mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY);
}

static void
send_policer_classify_details (u32 sw_if_index,
			       u32 table_index,
			       unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_policer_classify_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_POLICER_CLASSIFY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->table_index = htonl (table_index);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_policer_classify_dump_t_handler (vl_api_policer_classify_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  policer_classify_main_t *pcm = &policer_classify_main;
  u32 *vec_tbl;
  int i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  vec_tbl = pcm->classify_table_index_by_sw_if_index[mp->type];

  if (vec_len (vec_tbl))
    {
      for (i = 0; i < vec_len (vec_tbl); i++)
	{
	  if (vec_elt (vec_tbl, i) == ~0)
	    continue;

	  send_policer_classify_details (i, vec_elt (vec_tbl, i), q,
					 mp->context);
	}
    }
}

static void
vl_api_netmap_create_t_handler (vl_api_netmap_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_netmap_create_reply_t *rmp;
  int rv = 0;
  u8 *if_name = NULL;

  if_name = format (0, "%s", mp->netmap_if_name);
  vec_add1 (if_name, 0);

  rv =
    netmap_create_if (vm, if_name, mp->use_random_hw_addr ? 0 : mp->hw_addr,
		      mp->is_pipe, mp->is_master, 0);

  vec_free (if_name);

  REPLY_MACRO (VL_API_NETMAP_CREATE_REPLY);
}

static void
vl_api_netmap_delete_t_handler (vl_api_netmap_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_netmap_delete_reply_t *rmp;
  int rv = 0;
  u8 *if_name = NULL;

  if_name = format (0, "%s", mp->netmap_if_name);
  vec_add1 (if_name, 0);

  rv = netmap_delete_if (vm, if_name);

  vec_free (if_name);

  REPLY_MACRO (VL_API_NETMAP_DELETE_REPLY);
}

static void
vl_api_mpls_gre_tunnel_details_t_handler (vl_api_mpls_gre_tunnel_details_t *
					  mp)
{
  clib_warning ("BUG");
}

static void
send_mpls_gre_tunnel_entry (vpe_api_main_t * am,
			    unix_shared_memory_queue_t * q,
			    mpls_gre_tunnel_t * gt, u32 index, u32 context)
{
  vl_api_mpls_gre_tunnel_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_GRE_TUNNEL_DETAILS);
  mp->context = context;

  if (gt != NULL)
    {
      mp->tunnel_index = htonl (index);
      mp->tunnel_src = gt->tunnel_src.as_u32;
      mp->tunnel_dst = gt->tunnel_dst.as_u32;
      mp->intfc_address = gt->intfc_address.as_u32;
      mp->mask_width = htonl (gt->mask_width);
      mp->inner_fib_index = htonl (gt->inner_fib_index);
      mp->outer_fib_index = htonl (gt->outer_fib_index);
      mp->encap_index = htonl (gt->encap_index);
      mp->hw_if_index = htonl (gt->hw_if_index);
      mp->l2_only = htonl (gt->l2_only);
    }

  mpls_main_t *mm = &mpls_main;
  mpls_encap_t *e;
  int i;
  u32 len = 0;

  e = pool_elt_at_index (mm->encaps, gt->encap_index);
  len = vec_len (e->labels);
  mp->nlabels = htonl (len);

  for (i = 0; i < len; i++)
    {
      mp->labels[i] =
	htonl (vnet_mpls_uc_get_label
	       (clib_host_to_net_u32 (e->labels[i].label_exp_s_ttl)));
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_gre_tunnel_dump_t_handler (vl_api_mpls_gre_tunnel_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = &vlib_global_main;
  mpls_main_t *mm = &mpls_main;
  mpls_gre_tunnel_t *gt;
  u32 index = ntohl (mp->tunnel_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  if (pool_elts (mm->gre_tunnels))
    {
      if (mp->tunnel_index >= 0)
	{
	  vlib_cli_output (vm, "MPLS-GRE tunnel %u", index);
	  gt = pool_elt_at_index (mm->gre_tunnels, index);
	  send_mpls_gre_tunnel_entry (am, q, gt, gt - mm->gre_tunnels,
				      mp->context);
	}
      else
	{
	  vlib_cli_output (vm, "MPLS-GRE tunnels");
          /* *INDENT-OFF* */
          pool_foreach (gt, mm->gre_tunnels,
          ({
            send_mpls_gre_tunnel_entry (am, q, gt, gt - mm->gre_tunnels,
                                        mp->context);
          }));
          /* *INDENT-ON* */
	}
    }
  else
    {
      vlib_cli_output (vm, "No MPLS-GRE tunnels");
    }
}

static void
vl_api_mpls_eth_tunnel_details_t_handler (vl_api_mpls_eth_tunnel_details_t *
					  mp)
{
  clib_warning ("BUG");
}

static void
send_mpls_eth_tunnel_entry (vpe_api_main_t * am,
			    unix_shared_memory_queue_t * q,
			    mpls_eth_tunnel_t * et, u32 index, u32 context)
{
  vl_api_mpls_eth_tunnel_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_ETH_TUNNEL_DETAILS);
  mp->context = context;

  if (et != NULL)
    {
      mp->tunnel_index = htonl (index);
      memcpy (mp->tunnel_dst_mac, et->tunnel_dst, 6);
      mp->intfc_address = et->intfc_address.as_u32;
      mp->tx_sw_if_index = htonl (et->tx_sw_if_index);
      mp->inner_fib_index = htonl (et->inner_fib_index);
      mp->mask_width = htonl (et->mask_width);
      mp->encap_index = htonl (et->encap_index);
      mp->hw_if_index = htonl (et->hw_if_index);
      mp->l2_only = htonl (et->l2_only);
    }

  mpls_main_t *mm = &mpls_main;
  mpls_encap_t *e;
  int i;
  u32 len = 0;

  e = pool_elt_at_index (mm->encaps, et->encap_index);
  len = vec_len (e->labels);
  mp->nlabels = htonl (len);

  for (i = 0; i < len; i++)
    {
      mp->labels[i] =
	htonl (vnet_mpls_uc_get_label
	       (clib_host_to_net_u32 (e->labels[i].label_exp_s_ttl)));
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_eth_tunnel_dump_t_handler (vl_api_mpls_eth_tunnel_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = &vlib_global_main;
  mpls_main_t *mm = &mpls_main;
  mpls_eth_tunnel_t *et;
  u32 index = ntohl (mp->tunnel_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  clib_warning ("Received mpls_eth_tunnel_dump");
  clib_warning ("Received tunnel index: %u from client %u", index,
		mp->client_index);

  if (pool_elts (mm->eth_tunnels))
    {
      if (mp->tunnel_index >= 0)
	{
	  vlib_cli_output (vm, "MPLS-Ethernet tunnel %u", index);
	  et = pool_elt_at_index (mm->eth_tunnels, index);
	  send_mpls_eth_tunnel_entry (am, q, et, et - mm->eth_tunnels,
				      mp->context);
	}
      else
	{
	  clib_warning ("MPLS-Ethernet tunnels");
          /* *INDENT-OFF* */
          pool_foreach (et, mm->eth_tunnels,
          ({
            send_mpls_eth_tunnel_entry (am, q, et, et - mm->eth_tunnels,
                                        mp->context);
          }));
          /* *INDENT-ON* */
	}
    }
  else
    {
      clib_warning ("No MPLS-Ethernet tunnels");
    }
}

static void
vl_api_mpls_fib_encap_details_t_handler (vl_api_mpls_fib_encap_details_t * mp)
{
  clib_warning ("BUG");
}

static void
send_mpls_fib_encap_details (vpe_api_main_t * am,
			     unix_shared_memory_queue_t * q,
			     show_mpls_fib_t * s, u32 context)
{
  vl_api_mpls_fib_encap_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_FIB_ENCAP_DETAILS);
  mp->context = context;

  mp->fib_index = htonl (s->fib_index);
  mp->entry_index = htonl (s->entry_index);
  mp->dest = s->dest;
  mp->s_bit = htonl (s->s_bit);

  mpls_main_t *mm = &mpls_main;
  mpls_encap_t *e;
  int i;
  u32 len = 0;

  e = pool_elt_at_index (mm->encaps, s->entry_index);
  len = vec_len (e->labels);
  mp->nlabels = htonl (len);

  for (i = 0; i < len; i++)
    {
      mp->labels[i] =
	htonl (vnet_mpls_uc_get_label
	       (clib_host_to_net_u32 (e->labels[i].label_exp_s_ttl)));
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_fib_encap_dump_t_handler (vl_api_mpls_fib_encap_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = &vlib_global_main;
  u64 key;
  u32 value;
  show_mpls_fib_t *records = 0;
  show_mpls_fib_t *s;
  mpls_main_t *mm = &mpls_main;
  ip4_main_t *im = &ip4_main;
  ip4_fib_t *rx_fib;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  hash_foreach (key, value, mm->mpls_encap_by_fib_and_dest,
  ({
    vec_add2 (records, s, 1);
    s->fib_index = (u32)(key>>32);
    s->dest = (u32)(key & 0xFFFFFFFF);
    s->entry_index = (u32) value;
  }));
  /* *INDENT-ON* */

  if (0 == vec_len (records))
    {
      vlib_cli_output (vm, "MPLS encap table empty");
      goto out;
    }

  /* sort output by dst address within fib */
  vec_sort_with_function (records, mpls_dest_cmp);
  vec_sort_with_function (records, mpls_fib_index_cmp);
  vlib_cli_output (vm, "MPLS encap table");
  vlib_cli_output (vm, "%=6s%=16s%=16s", "Table", "Dest address", "Labels");
  vec_foreach (s, records)
  {
    rx_fib = vec_elt_at_index (im->fibs, s->fib_index);
    vlib_cli_output (vm, "%=6d%=16U%=16U", rx_fib->table_id,
		     format_ip4_address, &s->dest, format_mpls_encap_index,
		     mm, s->entry_index);
    send_mpls_fib_encap_details (am, q, s, mp->context);
  }

out:
  vec_free (records);
}

static void
vl_api_mpls_fib_decap_details_t_handler (vl_api_mpls_fib_decap_details_t * mp)
{
  clib_warning ("BUG");
}

static void
send_mpls_fib_decap_details (vpe_api_main_t * am,
			     unix_shared_memory_queue_t * q,
			     show_mpls_fib_t * s,
			     u32 rx_table_id,
			     u32 tx_table_id, char *swif_tag, u32 context)
{
  vl_api_mpls_fib_decap_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_FIB_DECAP_DETAILS);
  mp->context = context;

  mp->fib_index = htonl (s->fib_index);
  mp->entry_index = htonl (s->entry_index);
  mp->dest = s->dest;
  mp->s_bit = htonl (s->s_bit);
  mp->label = htonl (s->label);
  mp->rx_table_id = htonl (rx_table_id);
  mp->tx_table_id = htonl (tx_table_id);
  strncpy ((char *) mp->swif_tag,
	   (char *) swif_tag, ARRAY_LEN (mp->swif_tag) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_fib_decap_dump_t_handler (vl_api_mpls_fib_decap_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = &vlib_global_main;
  u64 key;
  u32 value;
  show_mpls_fib_t *records = 0;
  show_mpls_fib_t *s;
  mpls_main_t *mm = &mpls_main;
  ip4_main_t *im = &ip4_main;
  ip4_fib_t *rx_fib;
  ip4_fib_t *tx_fib;
  u32 tx_table_id;
  char *swif_tag;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  hash_foreach (key, value, mm->mpls_decap_by_rx_fib_and_label,
  ({
    vec_add2 (records, s, 1);
    s->fib_index = (u32)(key>>32);
    s->entry_index = (u32) value;
    s->label = ((u32) key)>>12;
    s->s_bit = (key & (1<<8)) != 0;
  }));
  /* *INDENT-ON* */

  if (!vec_len (records))
    {
      vlib_cli_output (vm, "MPLS decap table empty");
      goto out;
    }

  vec_sort_with_function (records, mpls_label_cmp);
  vlib_cli_output (vm, "MPLS decap table");
  vlib_cli_output (vm, "%=10s%=15s%=6s%=6s", "RX Table", "TX Table/Intfc",
		   "Label", "S-bit");
  vec_foreach (s, records)
  {
    mpls_decap_t *d;
    d = pool_elt_at_index (mm->decaps, s->entry_index);
    if (d->next_index == MPLS_INPUT_NEXT_IP4_INPUT)
      {
	tx_fib = vec_elt_at_index (im->fibs, d->tx_fib_index);
	tx_table_id = tx_fib->table_id;
	swif_tag = "     ";
      }
    else
      {
	tx_table_id = d->tx_fib_index;
	swif_tag = "(i)  ";
      }
    rx_fib = vec_elt_at_index (im->fibs, s->fib_index);

    vlib_cli_output (vm, "%=10d%=10d%=5s%=6d%=6d", rx_fib->table_id,
		     tx_table_id, swif_tag, s->label, s->s_bit);

    send_mpls_fib_decap_details (am, q, s, rx_fib->table_id,
				 tx_table_id, swif_tag, mp->context);
  }

out:
  vec_free (records);
}

static void
vl_api_classify_table_ids_t_handler (vl_api_classify_table_ids_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *t;
  u32 *table_ids = 0;
  u32 count;

  /* *INDENT-OFF* */
  pool_foreach (t, cm->tables,
  ({
    vec_add1 (table_ids, ntohl(t - cm->tables));
  }));
  /* *INDENT-ON* */
  count = vec_len (table_ids);

  vl_api_classify_table_ids_reply_t *rmp;
  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp) + count * sizeof (u32));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TABLE_IDS_REPLY);
  rmp->context = mp->context;
  rmp->count = ntohl (count);
  clib_memcpy (rmp->ids, table_ids, count * sizeof (u32));
  rmp->retval = 0;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);

  vec_free (table_ids);
}

static void
  vl_api_classify_table_by_interface_t_handler
  (vl_api_classify_table_by_interface_t * mp)
{
  vl_api_classify_table_by_interface_reply_t *rmp;
  int rv = 0;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 *acl = 0;

  vec_validate (acl, INPUT_ACL_N_TABLES - 1);
  vec_set (acl, ~0);

  VALIDATE_SW_IF_INDEX (mp);

  input_acl_main_t *am = &input_acl_main;

  int if_idx;
  u32 type;

  for (type = 0; type < INPUT_ACL_N_TABLES; type++)
    {
      u32 *vec_tbl = am->classify_table_index_by_sw_if_index[type];
      if (vec_len (vec_tbl))
	{
	  for (if_idx = 0; if_idx < vec_len (vec_tbl); if_idx++)
	    {
	      if (vec_elt (vec_tbl, if_idx) == ~0 || sw_if_index != if_idx)
		{
		  continue;
		}
	      acl[type] = vec_elt (vec_tbl, if_idx);
	    }
	}
    }

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY,
  ({
    rmp->sw_if_index = ntohl(sw_if_index);
    rmp->l2_table_id = ntohl(acl[INPUT_ACL_TABLE_L2]);
    rmp->ip4_table_id = ntohl(acl[INPUT_ACL_TABLE_IP4]);
    rmp->ip6_table_id = ntohl(acl[INPUT_ACL_TABLE_IP6]);
  }));
  /* *INDENT-ON* */
  vec_free (acl);
}

static void
vl_api_classify_table_info_t_handler (vl_api_classify_table_info_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  vl_api_classify_table_info_reply_t *rmp = 0;

  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 table_id = ntohl (mp->table_id);
  vnet_classify_table_t *t;

  /* *INDENT-OFF* */
  pool_foreach (t, cm->tables,
  ({
    if (table_id == t - cm->tables)
      {
        rmp = vl_msg_api_alloc_as_if_client
          (sizeof (*rmp) + t->match_n_vectors * sizeof (u32x4));
        rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_TABLE_INFO_REPLY);
        rmp->context = mp->context;
        rmp->table_id = ntohl(table_id);
        rmp->nbuckets = ntohl(t->nbuckets);
        rmp->match_n_vectors = ntohl(t->match_n_vectors);
        rmp->skip_n_vectors = ntohl(t->skip_n_vectors);
        rmp->active_sessions = ntohl(t->active_elements);
        rmp->next_table_index = ntohl(t->next_table_index);
        rmp->miss_next_index = ntohl(t->miss_next_index);
        rmp->mask_length = ntohl(t->match_n_vectors * sizeof (u32x4));
        clib_memcpy(rmp->mask, t->mask, t->match_n_vectors * sizeof(u32x4));
        rmp->retval = 0;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (rmp == 0)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      rmp->_vl_msg_id = ntohs ((VL_API_CLASSIFY_TABLE_INFO_REPLY));
      rmp->context = mp->context;
      rmp->retval = ntohl (VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND);
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_classify_session_details_t_handler (vl_api_classify_session_details_t *
					   mp)
{
  clib_warning ("BUG");
}

static void
send_classify_session_details (unix_shared_memory_queue_t * q,
			       u32 table_id,
			       u32 match_length,
			       vnet_classify_entry_t * e, u32 context)
{
  vl_api_classify_session_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CLASSIFY_SESSION_DETAILS);
  rmp->context = context;
  rmp->table_id = ntohl (table_id);
  rmp->hit_next_index = ntohl (e->next_index);
  rmp->advance = ntohl (e->advance);
  rmp->opaque_index = ntohl (e->opaque_index);
  rmp->match_length = ntohl (match_length);
  clib_memcpy (rmp->match, e->key, match_length);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_classify_session_dump_t_handler (vl_api_classify_session_dump_t * mp)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  unix_shared_memory_queue_t *q;

  u32 table_id = ntohl (mp->table_id);
  vnet_classify_table_t *t;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  /* *INDENT-OFF* */
  pool_foreach (t, cm->tables,
  ({
    if (table_id == t - cm->tables)
      {
        vnet_classify_bucket_t * b;
        vnet_classify_entry_t * v, * save_v;
        int i, j, k;

        for (i = 0; i < t->nbuckets; i++)
          {
            b = &t->buckets [i];
            if (b->offset == 0)
              continue;

            save_v = vnet_classify_get_entry (t, b->offset);
            for (j = 0; j < (1<<b->log2_pages); j++)
              {
                for (k = 0; k < t->entries_per_page; k++)
                  {
                    v = vnet_classify_entry_at_index
                      (t, save_v, j*t->entries_per_page + k);
                    if (vnet_classify_entry_is_free (v))
                      continue;

                    send_classify_session_details
                      (q, table_id, t->match_n_vectors * sizeof (u32x4),
                       v, mp->context);
                  }
              }
          }
        break;
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_ipfix_enable_t_handler (vl_api_ipfix_enable_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  flow_report_main_t *frm = &flow_report_main;
  vl_api_ipfix_enable_reply_t *rmp;
  ip4_address_t collector, src;
  u16 collector_port = UDP_DST_PORT_ipfix;
  u32 path_mtu;
  u32 template_interval;
  u32 fib_id;
  u32 fib_index = ~0;
  int rv = 0;

  memcpy (collector.data, mp->collector_address, sizeof (collector.data));
  collector_port = ntohs (mp->collector_port);
  if (collector_port == (u16) ~ 0)
    collector_port = UDP_DST_PORT_ipfix;
  memcpy (src.data, mp->src_address, sizeof (src.data));
  fib_id = ntohl (mp->vrf_id);

  ip4_main_t *im = &ip4_main;
  uword *p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  fib_index = p[0];

  path_mtu = ntohl (mp->path_mtu);
  if (path_mtu == ~0)
    path_mtu = 512;		// RFC 7011 section 10.3.3.
  template_interval = ntohl (mp->template_interval);
  if (template_interval == ~0)
    template_interval = 20;

  if (collector.as_u32 == 0)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  if (src.as_u32 == 0)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  if (path_mtu > 1450 /* vpp does not support fragmentation */ )
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  if (path_mtu < 68)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  /* Reset report streams if we are reconfiguring IP addresses */
  if (frm->ipfix_collector.as_u32 != collector.as_u32 ||
      frm->src_address.as_u32 != src.as_u32 ||
      frm->collector_port != collector_port)
    vnet_flow_reports_reset (frm);

  frm->ipfix_collector.as_u32 = collector.as_u32;
  frm->collector_port = collector_port;
  frm->src_address.as_u32 = src.as_u32;
  frm->fib_index = fib_index;
  frm->path_mtu = path_mtu;
  frm->template_interval = template_interval;

  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);

out:
  REPLY_MACRO (VL_API_IPFIX_ENABLE_REPLY);
}

static void
vl_api_ipfix_dump_t_handler (vl_api_ipfix_dump_t * mp)
{
  flow_report_main_t *frm = &flow_report_main;
  unix_shared_memory_queue_t *q;
  vl_api_ipfix_details_t *rmp;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IPFIX_DETAILS);
  rmp->context = mp->context;
  memcpy (rmp->collector_address, frm->ipfix_collector.data,
	  sizeof (frm->ipfix_collector.data));
  rmp->collector_port = htons (frm->collector_port);
  memcpy (rmp->src_address, frm->src_address.data,
	  sizeof (frm->src_address.data));
  rmp->fib_index = htonl (frm->fib_index);
  rmp->path_mtu = htonl (frm->path_mtu);
  rmp->template_interval = htonl (frm->template_interval);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_pg_create_interface_t_handler (vl_api_pg_create_interface_t * mp)
{
  vl_api_pg_create_interface_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 sw_if_index = pg_interface_add_or_get (pg, ntohl (mp->interface_id));

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PG_CREATE_INTERFACE_REPLY,
  ({
    rmp->sw_if_index = ntohl(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_pg_capture_t_handler (vl_api_pg_capture_t * mp)
{
  vl_api_pg_capture_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = 0;

  u8 *intf_name = format (0, "pg%d", ntohl (mp->interface_id), 0);
  u32 hw_if_index = ~0;
  uword *p = hash_get_mem (im->hw_interface_by_name, intf_name);
  if (p)
    hw_if_index = *p;
  vec_free (intf_name);

  if (hw_if_index != ~0)
    {
      pg_capture_args_t _a, *a = &_a;

      u32 len = ntohl (mp->pcap_name_length);
      u8 *pcap_file_name = vec_new (u8, len);
      clib_memcpy (pcap_file_name, mp->pcap_file_name, len);

      hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
      a->hw_if_index = hw_if_index;
      a->dev_instance = hi->dev_instance;
      a->is_enabled = mp->is_enabled;
      a->pcap_file_name = pcap_file_name;
      a->count = ntohl (mp->count);

      clib_error_t *e = pg_capture (a);
      if (e)
	{
	  clib_error_report (e);
	  rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
	}

      vec_free (pcap_file_name);
    }
  REPLY_MACRO (VL_API_PG_CAPTURE_REPLY);
}

static void
vl_api_pg_enable_disable_t_handler (vl_api_pg_enable_disable_t * mp)
{
  vl_api_pg_enable_disable_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 stream_index = ~0;

  int is_enable = mp->is_enabled != 0;
  u32 len = ntohl (mp->stream_name_length) - 1;

  if (len > 0)
    {
      u8 *stream_name = vec_new (u8, len);
      clib_memcpy (stream_name, mp->stream_name, len);
      uword *p = hash_get_mem (pg->stream_index_by_name, stream_name);
      if (p)
	stream_index = *p;
      vec_free (stream_name);
    }

  pg_enable_disable (stream_index, is_enable);

  REPLY_MACRO (VL_API_PG_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_ip_source_and_port_range_check_add_del_t_handler
  (vl_api_ip_source_and_port_range_check_add_del_t * mp)
{
  vl_api_ip_source_and_port_range_check_add_del_reply_t *rmp;
  int rv = 0;

  u8 is_ipv6 = mp->is_ipv6;
  u8 is_add = mp->is_add;
  u8 mask_length = mp->mask_length;
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;
  u16 *low_ports = 0;
  u16 *high_ports = 0;
  u32 vrf_id;
  u16 tmp_low, tmp_high;
  u8 num_ranges;
  int i;

  // Validate port range
  num_ranges = mp->number_of_ranges;
  if (num_ranges > 32)
    {				// This is size of array in VPE.API
      rv = VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;
      goto reply;
    }

  vec_reset_length (low_ports);
  vec_reset_length (high_ports);

  for (i = 0; i < num_ranges; i++)
    {
      tmp_low = mp->low_ports[i];
      tmp_high = mp->high_ports[i];
      // If tmp_low <= tmp_high then only need to check tmp_low = 0
      // If tmp_low <= tmp_high then only need to check tmp_high > 65535
      if (tmp_low > tmp_high || tmp_low == 0 || tmp_high > 65535)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto reply;
	}
      vec_add1 (low_ports, tmp_low);
      vec_add1 (high_ports, tmp_high + 1);
    }

  // Validate mask_length
  if ((is_ipv6 && mask_length > 128) || (!is_ipv6 && mask_length > 32))
    {
      rv = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
      goto reply;
    }

  vrf_id = ntohl (mp->vrf_id);

  if (vrf_id < 1)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }


  if (is_ipv6)
    {
      clib_memcpy (ip6_addr.as_u8, mp->address, sizeof (ip6_addr.as_u8));
      rv = ip6_source_and_port_range_check_add_del (&ip6_addr,
						    mask_length,
						    vrf_id,
						    low_ports,
						    high_ports, is_add);
    }
  else
    {
      clib_memcpy (ip4_addr.data, mp->address, sizeof (ip4_addr));
      rv = ip4_source_and_port_range_check_add_del (&ip4_addr,
						    mask_length,
						    vrf_id,
						    low_ports,
						    high_ports, is_add);
    }

reply:
  vec_free (low_ports);
  vec_free (high_ports);
  REPLY_MACRO (VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY);
}

static void
  vl_api_ip_source_and_port_range_check_interface_add_del_t_handler
  (vl_api_ip_source_and_port_range_check_interface_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *rmp;
  ip4_main_t *im = &ip4_main;
  int rv;
  u32 sw_if_index;
  u32 fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  u32 vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  uword *p = 0;
  int i;

  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT] =
    ntohl (mp->tcp_out_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT] =
    ntohl (mp->udp_out_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN] =
    ntohl (mp->tcp_in_vrf_id);
  vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN] =
    ntohl (mp->udp_in_vrf_id);


  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
    {
      if (vrf_id[i] != 0 && vrf_id[i] != ~0)
	{
	  p = hash_get (im->fib_index_by_table_id, vrf_id[i]);

	  if (p == 0)
	    {
	      rv = VNET_API_ERROR_INVALID_VALUE;
	      goto reply;
	    }

	  fib_index[i] = p[0];
	}
      else
	fib_index[i] = ~0;
    }
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    set_ip_source_and_port_range_check (vm, fib_index, sw_if_index,
					mp->is_add);

  BAD_SW_IF_INDEX_LABEL;
reply:

  REPLY_MACRO (VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY);
}

#define BOUNCE_HANDLER(nn)                                              \
static void vl_api_##nn##_t_handler (                                   \
    vl_api_##nn##_t *mp)                                                \
{                                                                       \
    vpe_client_registration_t *reg;                                     \
    vpe_api_main_t * vam = &vpe_api_main;                               \
    unix_shared_memory_queue_t * q;                                     \
                                                                        \
    /* One registration only... */                                      \
    pool_foreach(reg, vam->nn##_registrations,                          \
    ({                                                                  \
        q = vl_api_client_index_to_input_queue (reg->client_index);     \
        if (q) {                                                        \
            /*                                                          \
             * If the queue is stuffed, turf the msg and complain       \
             * It's unlikely that the intended recipient is             \
             * alive; avoid deadlock at all costs.                      \
             */                                                         \
            if (q->cursize == q->maxsize) {                             \
                clib_warning ("ERROR: receiver queue full, drop msg");  \
                vl_msg_api_free (mp);                                   \
                return;                                                 \
            }                                                           \
            vl_msg_api_send_shmem (q, (u8 *)&mp);                       \
            return;                                                     \
        }                                                               \
    }));                                                                \
    vl_msg_api_free (mp);                                               \
}

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */

static clib_error_t *
vpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Manually register the sr tunnel add del msg, so we trace
   * enough bytes to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_TUNNEL_ADD_DEL,
			   "sr_tunnel_add_del",
			   vl_api_sr_tunnel_add_del_t_handler,
			   vl_noop_handler,
			   vl_api_sr_tunnel_add_del_t_endian,
			   vl_api_sr_tunnel_add_del_t_print, 256, 1);


  /*
   * Manually register the sr policy add del msg, so we trace
   * enough bytes to capture a typical tunnel name list
   */
  vl_msg_api_set_handlers (VL_API_SR_POLICY_ADD_DEL,
			   "sr_policy_add_del",
			   vl_api_sr_policy_add_del_t_handler,
			   vl_noop_handler,
			   vl_api_sr_policy_add_del_t_endian,
			   vl_api_sr_policy_add_del_t_print, 256, 1);

  /*
   * Trace space for 8 MPLS encap labels, classifier mask+match
   */
  am->api_trace_cfg[VL_API_MPLS_ADD_DEL_ENCAP].size += 8 * sizeof (u32);
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_TABLE].size += 5 * sizeof (u32x4);
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_SESSION].size
    += 5 * sizeof (u32x4);
  am->api_trace_cfg[VL_API_VXLAN_ADD_DEL_TUNNEL].size += 16 * sizeof (u32);

  /*
   * Thread-safe API messages
   */
  am->is_mp_safe[VL_API_IP_ADD_DEL_ROUTE] = 1;
  am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;

  return 0;
}

VLIB_API_INIT_FUNCTION (vpe_api_hookup);

static clib_error_t *
vpe_api_init (vlib_main_t * vm)
{
  vpe_api_main_t *am = &vpe_api_main;

  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();
  am->interface_events_registration_hash = hash_create (0, sizeof (uword));
  am->to_netconf_server_registration_hash = hash_create (0, sizeof (uword));
  am->from_netconf_server_registration_hash = hash_create (0, sizeof (uword));
  am->to_netconf_client_registration_hash = hash_create (0, sizeof (uword));
  am->from_netconf_client_registration_hash = hash_create (0, sizeof (uword));
  am->oam_events_registration_hash = hash_create (0, sizeof (uword));

  vl_api_init (vm);
  vl_set_memory_region_name ("/vpe-api");
  vl_enable_disable_memory_api (vm, 1 /* enable it */ );

  return 0;
}

VLIB_INIT_FUNCTION (vpe_api_init);


static clib_error_t *
api_segment_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *chroot_path;
  int uid, gid, rv;
  char *s, buf[128];
  struct passwd _pw, *pw;
  struct group _grp, *grp;
  clib_error_t *e;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %s", &chroot_path))
	{
	  vec_add1 (chroot_path, 0);
	  vl_set_memory_root_path ((char *) chroot_path);
	}
      else if (unformat (input, "uid %d", &uid))
	vl_set_memory_uid (uid);
      else if (unformat (input, "gid %d", &gid))
	vl_set_memory_gid (gid);
      else if (unformat (input, "uid %s", &s))
	{
	  /* lookup the username */
	  pw = NULL;
	  rv = getpwnam_r (s, &_pw, buf, sizeof (buf), &pw);
	  if (rv < 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch username %s", s);
	      vec_free (s);
	      return e;
	    }
	  if (pw == NULL)
	    {
	      e =
		clib_error_return_fatal (0, "username %s does not exist", s);
	      vec_free (s);
	      return e;
	    }
	  vec_free (s);
	  vl_set_memory_uid (pw->pw_uid);
	}
      else if (unformat (input, "gid %s", &s))
	{
	  /* lookup the group name */
	  grp = NULL;
	  rv = getgrnam_r (s, &_grp, buf, sizeof (buf), &grp);
	  if (rv != 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch group %s", s);
	      vec_free (s);
	      return e;
	    }
	  if (grp == NULL)
	    {
	      e = clib_error_return_fatal (0, "group %s does not exist", s);
	      vec_free (s);
	      return e;
	    }
	  vec_free (s);
	  vl_set_memory_gid (grp->gr_gid);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (api_segment_config, "api-segment");

void *
get_unformat_vnet_sw_interface (void)
{
  return (void *) &unformat_vnet_sw_interface;
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp-api/vpe.api.h>
#undef vl_api_version

int
vl_msg_api_version_check (vl_api_memclnt_create_t * mp)
{
  if (clib_host_to_net_u32 (mp->api_versions[0]) != vpe_api_version)
    {
      clib_warning ("vpe API mismatch: 0x%08x instead of 0x%08x",
		    clib_host_to_net_u32 (mp->api_versions[0]),
		    vpe_api_version);
      return -1;
    }
  return 0;
}

static u8 *
format_arp_event (u8 * s, va_list * args)
{
  vl_api_ip4_arp_event_t *event = va_arg (*args, vl_api_ip4_arp_event_t *);

  s = format (s, "pid %d: %U", event->pid,
	      format_ip4_address, &event->address);
  return s;
}

static clib_error_t *
show_ip4_arp_events_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_ip4_arp_event_t *event;

  if (pool_elts (am->arp_events) == 0)
    {
      vlib_cli_output (vm, "No active arp event registrations");
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (event, am->arp_events,
  ({
    vlib_cli_output (vm, "%U", format_arp_event, event);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_arp_events, static) = {
  .path = "show arp event registrations",
  .function = show_ip4_arp_events_fn,
  .short_help = "Show arp event registrations",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
