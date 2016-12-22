/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010-2016 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/mpls/mpls.h>
#include <vnet/mpls/mpls_tunnel.h>
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
#include <vnet/classify/flow_classify.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/map/map.h>
#include <vnet/cop/cop.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/policer/policer.h>
#include <vnet/flow/flow_report.h>
#include <vnet/flow/flow_report_classify.h>
#include <vnet/ip/punt.h>
#include <vnet/feature/feature.h>

#undef BIHASH_TYPE
#undef __included_bihash_template_h__
#include <vnet/l2/l2_fib.h>

#if DPDK > 0
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <stats/stats.h>
#include <oam/oam.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/interface.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_bd.h>
#include <vpp-api/vpe_msg_enum.h>
#include <vnet/span/span.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_api.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
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
#include <vlibapi/api_helper_macros.h>
#define foreach_vpe_api_msg                                             \
_(WANT_OAM_EVENTS, want_oam_events)                                     \
_(OAM_ADD_DEL, oam_add_del)                                             \
_(MPLS_ROUTE_ADD_DEL, mpls_route_add_del)                               \
_(MPLS_IP_BIND_UNBIND, mpls_ip_bind_unbind)                             \
_(IS_ADDRESS_REACHABLE, is_address_reachable)                           \
_(SW_INTERFACE_SET_MPLS_ENABLE, sw_interface_set_mpls_enable)           \
_(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath)                       \
_(SW_INTERFACE_SET_VXLAN_BYPASS, sw_interface_set_vxlan_bypass)         \
_(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect)           \
_(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge)               \
_(SW_INTERFACE_SET_DPDK_HQOS_PIPE, sw_interface_set_dpdk_hqos_pipe)     \
_(SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, sw_interface_set_dpdk_hqos_subport) \
_(SW_INTERFACE_SET_DPDK_HQOS_TCTBL, sw_interface_set_dpdk_hqos_tctbl)   \
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)                         \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                               \
_(BRIDGE_DOMAIN_DETAILS, bridge_domain_details)                         \
_(BRIDGE_DOMAIN_SW_IF_DETAILS, bridge_domain_sw_if_details)             \
_(L2FIB_ADD_DEL, l2fib_add_del)                                         \
_(L2_FLAGS, l2_flags)                                                   \
_(BRIDGE_FLAGS, bridge_flags)                                           \
_(CREATE_VLAN_SUBIF, create_vlan_subif)                                 \
_(CREATE_SUBIF, create_subif)                                           \
_(MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del)				\
_(PROXY_ARP_ADD_DEL, proxy_arp_add_del)                                 \
_(PROXY_ARP_INTFC_ENABLE_DISABLE, proxy_arp_intfc_enable_disable)       \
_(VNET_GET_SUMMARY_STATS, vnet_get_summary_stats)			\
_(RESET_FIB, reset_fib)							\
_(DHCP_PROXY_CONFIG,dhcp_proxy_config)					\
_(DHCP_PROXY_CONFIG_2,dhcp_proxy_config_2)				\
_(DHCP_PROXY_SET_VSS,dhcp_proxy_set_vss)                                \
_(DHCP_CLIENT_CONFIG, dhcp_client_config)				\
_(CREATE_LOOPBACK, create_loopback)					\
_(CONTROL_PING, control_ping)                                           \
_(CLI_REQUEST, cli_request)                                             \
_(CLI_INBAND, cli_inband)						\
_(SET_ARP_NEIGHBOR_LIMIT, set_arp_neighbor_limit)			\
_(L2_PATCH_ADD_DEL, l2_patch_add_del)					\
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)			\
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)			\
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)     \
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)   \
_(GET_NODE_INDEX, get_node_index)                                       \
_(ADD_NODE_NEXT, add_node_next)						\
_(VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel)                           \
_(VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump)                                 \
_(L2_FIB_CLEAR_TABLE, l2_fib_clear_table)                               \
_(L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter)                     \
_(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite)         \
_(SHOW_VERSION, show_version)						\
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)	                                \
_(L2_FIB_TABLE_ENTRY, l2_fib_table_entry)                               \
_(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel)                   \
_(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump)                         \
_(INTERFACE_NAME_RENUMBER, interface_name_renumber)			\
_(WANT_IP4_ARP_EVENTS, want_ip4_arp_events)                             \
_(WANT_IP6_ND_EVENTS, want_ip6_nd_events)                               \
_(INPUT_ACL_SET_INTERFACE, input_acl_set_interface)                     \
_(DELETE_LOOPBACK, delete_loopback)                                     \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)                                 \
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable)		\
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)		\
_(GET_NODE_GRAPH, get_node_graph)                                       \
_(IOAM_ENABLE, ioam_enable)                                             \
_(IOAM_DISABLE, ioam_disable)                                           \
_(SR_MULTICAST_MAP_ADD_DEL, sr_multicast_map_add_del)                   \
_(POLICER_ADD_DEL, policer_add_del)                                     \
_(POLICER_DUMP, policer_dump)                                           \
_(POLICER_CLASSIFY_SET_INTERFACE, policer_classify_set_interface)       \
_(POLICER_CLASSIFY_DUMP, policer_classify_dump)                         \
_(MPLS_TUNNEL_DUMP, mpls_tunnel_dump)                                   \
_(MPLS_TUNNEL_DETAILS, mpls_tunnel_details)                             \
_(MPLS_FIB_DUMP, mpls_fib_dump)                                         \
_(MPLS_FIB_DETAILS, mpls_fib_details)                                   \
_(CLASSIFY_TABLE_IDS,classify_table_ids)                                \
_(CLASSIFY_TABLE_BY_INTERFACE, classify_table_by_interface)             \
_(CLASSIFY_TABLE_INFO,classify_table_info)                              \
_(CLASSIFY_SESSION_DUMP,classify_session_dump)                          \
_(CLASSIFY_SESSION_DETAILS,classify_session_details)                    \
_(SET_IPFIX_EXPORTER, set_ipfix_exporter)                               \
_(IPFIX_EXPORTER_DUMP, ipfix_exporter_dump)                             \
_(SET_IPFIX_CLASSIFY_STREAM, set_ipfix_classify_stream)                 \
_(IPFIX_CLASSIFY_STREAM_DUMP, ipfix_classify_stream_dump)               \
_(IPFIX_CLASSIFY_TABLE_ADD_DEL, ipfix_classify_table_add_del)           \
_(IPFIX_CLASSIFY_TABLE_DUMP, ipfix_classify_table_dump)                 \
_(GET_NEXT_INDEX, get_next_index)                                       \
_(PG_CREATE_INTERFACE, pg_create_interface)                             \
_(PG_CAPTURE, pg_capture)                                               \
_(PG_ENABLE_DISABLE, pg_enable_disable)                                 \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL,                               \
  ip_source_and_port_range_check_add_del)                               \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL,                     \
  ip_source_and_port_range_check_interface_add_del)                     \
_(DELETE_SUBIF, delete_subif)                                           \
_(L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite)           \
_(PUNT, punt)                                                           \
_(FLOW_CLASSIFY_SET_INTERFACE, flow_classify_set_interface)             \
_(FLOW_CLASSIFY_DUMP, flow_classify_dump)                               \
_(FEATURE_ENABLE_DISABLE, feature_enable_disable)

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)
typedef enum
{
  RESOLVE_IP4_ADD_DEL_ROUTE = 1,
  RESOLVE_IP6_ADD_DEL_ROUTE,
} resolve_t;

static vlib_node_registration_t vpe_resolver_process_node;
vpe_api_main_t vpe_api_main;

static int arp_change_delete_callback (u32 pool_index, u8 * notused);
static int nd_change_delete_callback (u32 pool_index, u8 * notused);

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

pub_sub_handler (oam_events, OAM_EVENTS);

#define RESOLUTION_EVENT 1
#define RESOLUTION_PENDING_EVENT 2
#define IP4_ARP_EVENT 3
#define IP6_ND_EVENT 4

int ip4_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);

int ip6_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);

void
handle_ip4_arp_event (u32 pool_index)
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

void
handle_ip6_nd_event (u32 pool_index)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_main_t *vnm = vam->vnet_main;
  vlib_main_t *vm = vam->vlib_main;
  vl_api_ip6_nd_event_t *event;
  vl_api_ip6_nd_event_t *mp;
  unix_shared_memory_queue_t *q;

  /* Client can cancel, die, etc. */
  if (pool_is_free_index (vam->nd_events, pool_index))
    return;

  event = pool_elt_at_index (vam->nd_events, pool_index);

  q = vl_api_client_index_to_input_queue (event->client_index);
  if (!q)
    {
      (void) vnet_add_del_ip6_nd_change_event
	(vnm, nd_change_delete_callback,
	 event->pid, &event->address,
	 vpe_resolver_process_node.index, IP6_ND_EVENT,
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
	  clib_warning ("ip6 nd event for %U to pid %d: queue stuffed!",
			format_ip6_address, &event->address, event->pid);
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
  int i;

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
	  clib_warning ("resolver: BOGUS TYPE");
	  break;

	case IP4_ARP_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_ip4_arp_event (event_data[i]);
	  break;

	case IP6_ND_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_ip6_nd_event (event_data[i]);
	  break;

	case ~0:		/* timeout */
	  break;
	}

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
mpls_route_add_del_t_handler (vnet_main_t * vnm,
			      vl_api_mpls_route_add_del_t * mp)
{
  u32 fib_index, next_hop_fib_index;
  mpls_label_t *label_stack = NULL;
  int rv, ii, n_labels;;

  fib_prefix_t pfx = {
    .fp_len = 21,
    .fp_proto = FIB_PROTOCOL_MPLS,
    .fp_eos = mp->mr_eos,
    .fp_label = ntohl (mp->mr_label),
  };
  if (pfx.fp_eos)
    {
      if (mp->mr_next_hop_proto_is_ip4)
	{
	  pfx.fp_payload_proto = DPO_PROTO_IP4;
	}
      else
	{
	  pfx.fp_payload_proto = DPO_PROTO_IP6;
	}
    }
  else
    {
      pfx.fp_payload_proto = DPO_PROTO_MPLS;
    }

  rv = add_del_route_check (FIB_PROTOCOL_MPLS,
			    mp->mr_table_id,
			    mp->mr_next_hop_sw_if_index,
			    dpo_proto_to_fib (pfx.fp_payload_proto),
			    mp->mr_next_hop_table_id,
			    mp->mr_create_table_if_needed,
			    &fib_index, &next_hop_fib_index);

  if (0 != rv)
    return (rv);

  ip46_address_t nh;
  memset (&nh, 0, sizeof (nh));

  if (mp->mr_next_hop_proto_is_ip4)
    memcpy (&nh.ip4, mp->mr_next_hop, sizeof (nh.ip4));
  else
    memcpy (&nh.ip6, mp->mr_next_hop, sizeof (nh.ip6));

  n_labels = mp->mr_next_hop_n_out_labels;
  if (n_labels == 0)
    ;
  else if (1 == n_labels)
    vec_add1 (label_stack, ntohl (mp->mr_next_hop_out_label_stack[0]));
  else
    {
      vec_validate (label_stack, n_labels - 1);
      for (ii = 0; ii < n_labels; ii++)
	label_stack[ii] = ntohl (mp->mr_next_hop_out_label_stack[ii]);
    }

  return (add_del_route_t_handler (mp->mr_is_multipath, mp->mr_is_add, 0,	// mp->is_drop,
				   0,	// mp->is_unreach,
				   0,	// mp->is_prohibit,
				   0,	// mp->is_local,
				   mp->mr_is_classify,
				   mp->mr_classify_table_index,
				   mp->mr_is_resolve_host,
				   mp->mr_is_resolve_attached,
				   fib_index, &pfx,
				   mp->mr_next_hop_proto_is_ip4,
				   &nh, ntohl (mp->mr_next_hop_sw_if_index),
				   next_hop_fib_index,
				   mp->mr_next_hop_weight,
				   ntohl (mp->mr_next_hop_via_label),
				   label_stack));
}

void
vl_api_mpls_route_add_del_t_handler (vl_api_mpls_route_add_del_t * mp)
{
  vl_api_mpls_route_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  rv = mpls_route_add_del_t_handler (vnm, mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_MPLS_ROUTE_ADD_DEL_REPLY);
}

static int
mpls_ip_bind_unbind_handler (vnet_main_t * vnm,
			     vl_api_mpls_ip_bind_unbind_t * mp)
{
  u32 mpls_fib_index, ip_fib_index;

  mpls_fib_index =
    fib_table_find (FIB_PROTOCOL_MPLS, ntohl (mp->mb_mpls_table_id));

  if (~0 == mpls_fib_index)
    {
      if (mp->mb_create_table_if_needed)
	{
	  mpls_fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_MPLS,
					       ntohl (mp->mb_mpls_table_id));
	}
      else
	return VNET_API_ERROR_NO_SUCH_FIB;
    }

  ip_fib_index = fib_table_find ((mp->mb_is_ip4 ?
				  FIB_PROTOCOL_IP4 :
				  FIB_PROTOCOL_IP6),
				 ntohl (mp->mb_ip_table_id));
  if (~0 == ip_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_prefix_t pfx = {
    .fp_len = mp->mb_address_length,
  };

  if (mp->mb_is_ip4)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      clib_memcpy (&pfx.fp_addr.ip4, mp->mb_address,
		   sizeof (pfx.fp_addr.ip4));
    }
  else
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      clib_memcpy (&pfx.fp_addr.ip6, mp->mb_address,
		   sizeof (pfx.fp_addr.ip6));
    }

  if (mp->mb_is_bind)
    fib_table_entry_local_label_add (ip_fib_index, &pfx,
				     ntohl (mp->mb_label));
  else
    fib_table_entry_local_label_remove (ip_fib_index, &pfx,
					ntohl (mp->mb_label));

  return (0);
}

void
vl_api_mpls_ip_bind_unbind_t_handler (vl_api_mpls_ip_bind_unbind_t * mp)
{
  vl_api_mpls_route_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  rv = mpls_ip_bind_unbind_handler (vnm, mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_MPLS_ROUTE_ADD_DEL_REPLY);
}

static void
vl_api_sw_interface_set_vpath_t_handler (vl_api_sw_interface_set_vpath_t * mp)
{
  vl_api_sw_interface_set_vpath_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_VPATH, mp->enable);
  vnet_feature_enable_disable ("ip4-unicast", "vpath-input-ip4",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip4-multicast", "vpath-input-ip4",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "vpath-input-ip6",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip6-multicast", "vpath-input-ip6",
			       sw_if_index, mp->enable, 0, 0);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VPATH_REPLY);
}

static void
  vl_api_sw_interface_set_vxlan_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_ipv6)
    {
      /* not yet implemented */
    }
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-vxlan-bypass",
				 sw_if_index, mp->enable, 0, 0);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_BYPASS_REPLY);
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
  vl_api_sw_interface_set_dpdk_hqos_pipe_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  u32 pipe = ntohl (mp->pipe);
  u32 profile = ntohl (mp->profile);
  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_pipe_config (xd->hqos_ht->hqos, subport, pipe, profile);

  BAD_SW_IF_INDEX_LABEL;
#else
  clib_warning ("setting HQoS pipe parameters without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_subport_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  struct rte_sched_subport_params p;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  p.tb_rate = ntohl (mp->tb_rate);
  p.tb_size = ntohl (mp->tb_size);
  p.tc_rate[0] = ntohl (mp->tc_rate[0]);
  p.tc_rate[1] = ntohl (mp->tc_rate[1]);
  p.tc_rate[2] = ntohl (mp->tc_rate[2]);
  p.tc_rate[3] = ntohl (mp->tc_rate[3]);
  p.tc_period = ntohl (mp->tc_period);

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport, &p);

  BAD_SW_IF_INDEX_LABEL;
#else
  clib_warning
    ("setting HQoS subport parameters without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_tctbl_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
  dpdk_main_t *dm = &dpdk_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 entry = ntohl (mp->entry);
  u32 tc = ntohl (mp->tc);
  u32 queue = ntohl (mp->queue);
  u32 val, i;

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      clib_warning ("invalid traffic class !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (queue >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
    {
      clib_warning ("invalid queue !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");

  if (p == 0)
    {
      clib_warning ("worker thread registration AWOL !!");
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto done;
    }

  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  val = tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;
  for (i = 0; i < worker_thread_count; i++)
    xd->hqos_wt[worker_thread_first + i].hqos_tc_table[entry] = val;

  BAD_SW_IF_INDEX_LABEL;
done:
#else
  clib_warning ("setting HQoS DSCP table entry without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY);
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

      bd_set_mac_age (vm, bd_index, mp->mac_age);
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
  mp->mac_age = bd_config->mac_age;
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
      filter_mac = mp->filter_mac ? 1 : 0;
      if (filter_mac == 0)
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
	}
      static_mac = mp->static_mac ? 1 : 0;
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
vl_api_mpls_tunnel_add_del_t_handler (vl_api_mpls_tunnel_add_del_t * mp)
{
  vl_api_mpls_tunnel_add_del_reply_t *rmp;
  int rv = 0;
  stats_main_t *sm = &stats_main;
  u32 tunnel_sw_if_index;
  int ii;

  dslock (sm, 1 /* release hint */ , 5 /* tag */ );

  if (mp->mt_is_add)
    {
      fib_route_path_t rpath, *rpaths = NULL;
      mpls_label_t *label_stack = NULL;

      memset (&rpath, 0, sizeof (rpath));

      if (mp->mt_next_hop_proto_is_ip4)
	{
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  clib_memcpy (&rpath.frp_addr.ip4,
		       mp->mt_next_hop, sizeof (rpath.frp_addr.ip4));
	}
      else
	{
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  clib_memcpy (&rpath.frp_addr.ip6,
		       mp->mt_next_hop, sizeof (rpath.frp_addr.ip6));
	}
      rpath.frp_sw_if_index = ntohl (mp->mt_next_hop_sw_if_index);

      for (ii = 0; ii < mp->mt_next_hop_n_out_labels; ii++)
	vec_add1 (label_stack, ntohl (mp->mt_next_hop_out_label_stack[ii]));

      vec_add1 (rpaths, rpath);

      vnet_mpls_tunnel_add (rpaths, label_stack,
			    mp->mt_l2_only, &tunnel_sw_if_index);
      vec_free (rpaths);
      vec_free (label_stack);
    }
  else
    {
      tunnel_sw_if_index = ntohl (mp->mt_sw_if_index);
      vnet_mpls_tunnel_del (tunnel_sw_if_index);
    }

  dsunlock (sm);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl(tunnel_sw_if_index);
  }));
  /* *INDENT-ON* */
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
      // FIXME NOT an ADJ
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
  vl_api_sw_interface_set_mpls_enable_t_handler
  (vl_api_sw_interface_set_mpls_enable_t * mp)
{
  vl_api_sw_interface_set_mpls_enable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  mpls_sw_interface_enable_disable (&mpls_main,
				    ntohl (mp->sw_if_index), mp->enable);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY);
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

  rmp->total_pkts[VLIB_RX] = clib_host_to_net_u64 (total_pkts[VLIB_RX]);
  rmp->total_bytes[VLIB_RX] = clib_host_to_net_u64 (total_bytes[VLIB_RX]);
  rmp->total_pkts[VLIB_TX] = clib_host_to_net_u64 (total_pkts[VLIB_TX]);
  rmp->total_bytes[VLIB_TX] = clib_host_to_net_u64 (total_bytes[VLIB_TX]);
  rmp->vector_rate =
    clib_host_to_net_u64 (vlib_last_vector_length_per_node (sm->vlib_main));

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
  static u32 *sw_if_indices_to_shut;
  stats_main_t *sm = &stats_main;
  fib_table_t *fib_table;
  ip4_fib_t *fib;
  u32 sw_if_index;
  int i;
  int rv = VNET_API_ERROR_NO_SUCH_FIB;
  u32 target_fib_id = ntohl (mp->vrf_id);

  dslock (sm, 1 /* release hint */ , 8 /* tag */ );

  /* *INDENT-OFF* */
  pool_foreach (fib_table, im4->fibs,
  ({
    fib = &fib_table->v4;
    vnet_sw_interface_t * si;

    if (fib->table_id != target_fib_id)
      continue;

    /* remove any mpls encap/decap labels */
    mpls_fib_reset_labels (fib->table_id);

    /* remove any proxy arps in this fib */
    vnet_proxy_arp_fib_reset (fib->table_id);

    /* Set the flow hash for this fib to the default */
    vnet_set_ip4_flow_hash (fib->table_id, IP_FLOW_HASH_DEFAULT);

    vec_reset_length (sw_if_indices_to_shut);

    /* Shut down interfaces in this FIB / clean out intfc routes */
    pool_foreach (si, im->sw_interfaces,
    ({
      u32 sw_if_index = si->sw_if_index;

      if (sw_if_index < vec_len (im4->fib_index_by_sw_if_index)
          && (im4->fib_index_by_sw_if_index[si->sw_if_index] ==
              fib->index))
        vec_add1 (sw_if_indices_to_shut, si->sw_if_index);
    }));

    for (i = 0; i < vec_len (sw_if_indices_to_shut); i++) {
      sw_if_index = sw_if_indices_to_shut[i];
      // vec_foreach (sw_if_index, sw_if_indices_to_shut) {

      u32 flags = vnet_sw_interface_get_flags (vnm, sw_if_index);
      flags &= ~(VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
    }

    fib_table_flush(fib->index, FIB_PROTOCOL_IP4, FIB_SOURCE_API);
    fib_table_flush(fib->index, FIB_PROTOCOL_IP4, FIB_SOURCE_INTERFACE);

    rv = 0;
    break;
    })); /* pool_foreach (fib) */
    /* *INDENT-ON* */

  dsunlock (sm);
  return rv;
}

static int
ip6_reset_fib_t_handler (vl_api_reset_fib_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip6_main_t *im6 = &ip6_main;
  stats_main_t *sm = &stats_main;
  static u32 *sw_if_indices_to_shut;
  fib_table_t *fib_table;
  ip6_fib_t *fib;
  u32 sw_if_index;
  int i;
  int rv = VNET_API_ERROR_NO_SUCH_FIB;
  u32 target_fib_id = ntohl (mp->vrf_id);

  dslock (sm, 1 /* release hint */ , 9 /* tag */ );

  /* *INDENT-OFF* */
  pool_foreach (fib_table, im6->fibs,
  ({
    vnet_sw_interface_t * si;
    fib = &(fib_table->v6);

    if (fib->table_id != target_fib_id)
      continue;

    vec_reset_length (sw_if_indices_to_shut);

    /* Shut down interfaces in this FIB / clean out intfc routes */
    pool_foreach (si, im->sw_interfaces,
                  ({
                    if (im6->fib_index_by_sw_if_index[si->sw_if_index] ==
                        fib->index)
                      vec_add1 (sw_if_indices_to_shut, si->sw_if_index);
                  }));

    for (i = 0; i < vec_len (sw_if_indices_to_shut); i++) {
      sw_if_index = sw_if_indices_to_shut[i];
      // vec_foreach (sw_if_index, sw_if_indices_to_shut) {

      u32 flags = vnet_sw_interface_get_flags (vnm, sw_if_index);
      flags &= ~(VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
    }

    fib_table_flush(fib->index, FIB_PROTOCOL_IP6, FIB_SOURCE_API);
    fib_table_flush(fib->index, FIB_PROTOCOL_IP6, FIB_SOURCE_INTERFACE);

    rv = 0;
    break;
  })); /* pool_foreach (fib) */
  /* *INDENT-ON* */

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

  rv = dhcpv6_proxy_set_server_2 ((ip6_address_t *) (&mp->dhcp_server),
				  (ip6_address_t *) (&mp->dhcp_src_address),
				  (u32) ntohl (mp->rx_vrf_id),
				  (u32) ntohl (mp->server_vrf_id),
				  (int) mp->insert_circuit_id,
				  (int) (mp->is_add == 0));

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

  if (NULL != host_mac)
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
inband_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **mem_vecp = (u8 **) arg;
  u8 *mem_vec = *mem_vecp;
  u32 offset = vec_len (mem_vec);

  vec_validate (mem_vec, offset + buffer_bytes - 1);
  clib_memcpy (mem_vec + offset, buffer, buffer_bytes);
  *mem_vecp = mem_vec;
}

static void
vl_api_cli_inband_t_handler (vl_api_cli_inband_t * mp)
{
  vl_api_cli_inband_reply_t *rmp;
  int rv = 0;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = vlib_get_main ();
  unformat_input_t input;
  u8 *out_vec = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  unformat_init_string (&input, (char *) mp->cmd, ntohl (mp->length));
  vlib_cli_input (vm, &input, inband_cli_output, (uword) & out_vec);

  u32 len = vec_len (out_vec);
  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_CLI_INBAND_REPLY, len,
  ({
    rmp->length = htonl (len);
    clib_memcpy (rmp->reply, out_vec, len);
  }));
  /* *INDENT-ON* */
  vec_free (out_vec);
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
#if IP6SR == 0
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
#if IP6SR == 0
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
#if IP6SR == 0
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
_(miss_next_index)                              \
_(current_data_flag)                            \
_(current_data_offset)

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
  if (mp->is_add == 0)		/* delete */
    {
      if (pool_is_free_index (cm->tables, table_index))
	{
	  rv = VNET_API_ERROR_NO_SUCH_TABLE;
	  goto out;
	}
    }
  else				/* add or update */
    {
      if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
	table_index = ~0;
    }

  rv = vnet_classify_add_del_table
    (cm, mp->mask, nbuckets, memory_size,
     skip_n_vectors, match_n_vectors,
     next_table_index, miss_next_index, &table_index,
     current_data_flag, current_data_offset, mp->is_add, mp->del_chain);

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
  u32 table_index, hit_next_index, opaque_index, metadata;
  i32 advance;
  u8 action;

  table_index = ntohl (mp->table_index);
  hit_next_index = ntohl (mp->hit_next_index);
  opaque_index = ntohl (mp->opaque_index);
  advance = ntohl (mp->advance);
  action = mp->action;
  metadata = ntohl (mp->metadata);

  rv = vnet_classify_add_del_session
    (cm, table_index, mp->match, hit_next_index, opaque_index,
     advance, action, metadata, mp->is_add);

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

  if (mp->is_input)
    rv = vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
					    ip6_table_index,
					    other_table_index);
  else
    rv = vnet_l2_output_classify_set_tables (sw_if_index, ip4_table_index,
					     ip6_table_index,
					     other_table_index);

  if (rv == 0)
    {
      if (ip4_table_index != ~0 || ip6_table_index != ~0
	  || other_table_index != ~0)
	enable = 1;
      else
	enable = 0;

      if (mp->is_input)
	vnet_l2_input_classify_enable_disable (sw_if_index, enable);
      else
	vnet_l2_output_classify_enable_disable (sw_if_index, enable);
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

static void vl_api_vxlan_add_del_tunnel_t_handler
  (vl_api_vxlan_add_del_tunnel_t * mp)
{
  vl_api_vxlan_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index;
  uword *p;
  ip4_main_t *im = &ip4_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  a->is_ip6 = mp->is_ipv6;

  /* ip addresses sent in network byte order */
  ip46_from_addr_buf (mp->is_ipv6, mp->dst_address, &a->dst);
  ip46_from_addr_buf (mp->is_ipv6, mp->src_address, &a->src);

  /* Check src & dst are different */
  if (ip46_address_cmp (&a->dst, &a->src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  a->mcast_sw_if_index = ntohl (mp->mcast_sw_if_index);
  if (ip46_address_is_multicast (&a->dst) &&
      pool_is_free_index (vnm->interface_main.sw_interfaces,
			  a->mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
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
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->src_address, t->src.ip6.as_u8, 16);
      memcpy (rmp->dst_address, t->dst.ip6.as_u8, 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
    }
  else
    {
      memcpy (rmp->src_address, t->src.ip4.as_u8, 4);
      memcpy (rmp->dst_address, t->dst.ip4.as_u8, 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
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
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      memcpy (rmp->local, &(t->local.ip4), 4);
      memcpy (rmp->remote, &(t->remote.ip4), 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
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
  /* *INDENT-OFF* */
  if (memcmp (&event->new_mac, new_mac, sizeof (event->new_mac)))
    {
      clib_memcpy (event->new_mac, new_mac, sizeof (event->new_mac));
    }
  else
    {				/* same mac */
      if (sw_if_index == event->sw_if_index &&
	  (!event->mac_ip ||
	   /* for BD case, also check IP address with 10 sec timeout */
	   (address == event->address &&
	    (now - arp_event_last_time) < 10.0)))
	return 1;
    }
  /* *INDENT-ON* */

  arp_event_last_time = now;
  event->sw_if_index = sw_if_index;
  if (event->mac_ip)
    event->address = address;
  return 0;
}

static int
nd_change_data_callback (u32 pool_index, u8 * new_mac,
			 u32 sw_if_index, ip6_address_t * address)
{
  vpe_api_main_t *am = &vpe_api_main;
  vlib_main_t *vm = am->vlib_main;
  vl_api_ip6_nd_event_t *event;
  static f64 nd_event_last_time;
  f64 now = vlib_time_now (vm);

  if (pool_is_free_index (am->nd_events, pool_index))
    return 1;

  event = pool_elt_at_index (am->nd_events, pool_index);

  /* *INDENT-OFF* */
  if (memcmp (&event->new_mac, new_mac, sizeof (event->new_mac)))
    {
      clib_memcpy (event->new_mac, new_mac, sizeof (event->new_mac));
    }
  else
    {				/* same mac */
      if (sw_if_index == event->sw_if_index &&
	  (!event->mac_ip ||
	   /* for BD case, also check IP address with 10 sec timeout */
	   (ip6_address_is_equal (address,
				  (ip6_address_t *) event->address) &&
	    (now - nd_event_last_time) < 10.0)))
	return 1;
    }
  /* *INDENT-ON* */

  nd_event_last_time = now;
  event->sw_if_index = sw_if_index;
  if (event->mac_ip)
    clib_memcpy (event->address, address, sizeof (event->address));
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

static int
nd_change_delete_callback (u32 pool_index, u8 * notused)
{
  vpe_api_main_t *am = &vpe_api_main;

  if (pool_is_free_index (am->nd_events, pool_index))
    return 1;

  pool_put_index (am->nd_events, pool_index);
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
      if (mp->address == 0)
	event->mac_ip = 1;

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

static void
vl_api_want_ip6_nd_events_t_handler (vl_api_want_ip6_nd_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_want_ip6_nd_events_reply_t *rmp;
  vl_api_ip6_nd_event_t *event;
  int rv;

  if (mp->enable_disable)
    {
      pool_get (am->nd_events, event);
      memset (event, 0, sizeof (*event));

      event->_vl_msg_id = ntohs (VL_API_IP6_ND_EVENT);
      event->client_index = mp->client_index;
      event->context = mp->context;
      clib_memcpy (event->address, mp->address, 16);
      event->pid = mp->pid;
      if (ip6_address_is_zero ((ip6_address_t *) mp->address))
	event->mac_ip = 1;

      rv = vnet_add_del_ip6_nd_change_event
	(vnm, nd_change_data_callback,
	 mp->pid, mp->address /* addr, in net byte order */ ,
	 vpe_resolver_process_node.index,
	 IP6_ND_EVENT, event - am->nd_events, 1 /* is_add */ );
    }
  else
    {
      rv = vnet_add_del_ip6_nd_change_event
	(vnm, nd_change_delete_callback,
	 mp->pid, mp->address /* addr, in net byte order */ ,
	 vpe_resolver_process_node.index,
	 IP6_ND_EVENT, ~0 /* pool index */ , 0 /* is_add */ );
    }
  REPLY_MACRO (VL_API_WANT_IP6_ND_EVENTS_REPLY);
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

static void
vl_api_ioam_enable_t_handler (vl_api_ioam_enable_t * mp)
{
  int rv = 0;
  vl_api_ioam_enable_reply_t *rmp;
  clib_error_t *error;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = ip6_ioam_enable (mp->trace_enable, mp->pot_enable,
			   mp->seqno, mp->analyse);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_IOAM_ENABLE_REPLY);
}

static void
vl_api_ioam_disable_t_handler (vl_api_ioam_disable_t * mp)
{
  int rv = 0;
  vl_api_ioam_disable_reply_t *rmp;
  clib_error_t *error;

  error = clear_ioam_rewrite_fn ();
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_IOAM_DISABLE_REPLY);
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
vl_api_mpls_tunnel_details_t_handler (vl_api_mpls_fib_details_t * mp)
{
  clib_warning ("BUG");
}

typedef struct mpls_tunnel_send_walk_ctx_t_
{
  unix_shared_memory_queue_t *q;
  u32 index;
  u32 context;
} mpls_tunnel_send_walk_ctx_t;

static void
send_mpls_tunnel_entry (u32 mti, void *arg)
{
  mpls_tunnel_send_walk_ctx_t *ctx;
  vl_api_mpls_tunnel_details_t *mp;
  const mpls_tunnel_t *mt;
  u32 nlabels;

  ctx = arg;

  if (~0 != ctx->index && mti != ctx->index)
    return;

  mt = mpls_tunnel_get (mti);
  nlabels = vec_len (mt->mt_label_stack);

  mp = vl_msg_api_alloc (sizeof (*mp) + nlabels * sizeof (u32));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_TUNNEL_DETAILS);
  mp->context = ctx->context;

  mp->tunnel_index = ntohl (mti);
  memcpy (mp->mt_next_hop_out_labels,
	  mt->mt_label_stack, nlabels * sizeof (u32));

  // FIXME

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);
}

static void
vl_api_mpls_tunnel_dump_t_handler (vl_api_mpls_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  mpls_tunnel_send_walk_ctx_t ctx = {
    .q = q,
    .index = ntohl (mp->tunnel_index),
    .context = mp->context,
  };
  mpls_tunnel_walk (send_mpls_tunnel_entry, &ctx);
}

static void
vl_api_mpls_fib_details_t_handler (vl_api_mpls_fib_details_t * mp)
{
  clib_warning ("BUG");
}

static void
vl_api_mpls_fib_details_t_endian (vl_api_mpls_fib_details_t * mp)
{
  clib_warning ("BUG");
}

static void
vl_api_mpls_fib_details_t_print (vl_api_mpls_fib_details_t * mp)
{
  clib_warning ("BUG");
}

static void
send_mpls_fib_details (vpe_api_main_t * am,
		       unix_shared_memory_queue_t * q,
		       u32 table_id, u32 label, u32 eos,
		       fib_route_path_encode_t * api_rpaths, u32 context)
{
  vl_api_mpls_fib_details_t *mp;
  fib_route_path_encode_t *api_rpath;
  vl_api_fib_path2_t *fp;
  int path_count;

  path_count = vec_len (api_rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*fp));
  if (!mp)
    return;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MPLS_FIB_DETAILS);
  mp->context = context;

  mp->table_id = htonl (table_id);
  mp->eos_bit = eos;
  mp->label = htonl (label);

  mp->count = htonl (path_count);
  fp = mp->path;
  vec_foreach (api_rpath, api_rpaths)
  {
    memset (fp, 0, sizeof (*fp));
    fp->weight = htonl (api_rpath->rpath.frp_weight);
    fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    copy_fib_next_hop (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_mpls_fib_dump_t_handler (vl_api_mpls_fib_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  mpls_main_t *mm = &mpls_main;
  fib_table_t *fib_table;
  fib_node_index_t lfei, *lfeip, *lfeis = NULL;
  mpls_label_t key;
  fib_prefix_t pfx;
  u32 fib_index;
  fib_route_path_encode_t *api_rpaths;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (fib_table, mm->fibs,
  ({
    hash_foreach(key, lfei, fib_table->mpls.mf_entries,
    ({
	vec_add1(lfeis, lfei);
    }));
  }));
  vec_sort_with_function(lfeis, fib_entry_cmp_for_sort);

  vec_foreach(lfeip, lfeis)
  {
    fib_entry_get_prefix(*lfeip, &pfx);
    fib_index = fib_entry_get_fib_index(*lfeip);
    fib_table = fib_table_get(fib_index, pfx.fp_proto);
    api_rpaths = NULL;
    fib_entry_encode(*lfeip, &api_rpaths);
    send_mpls_fib_details (am, q,
			   fib_table->ft_table_id,
			   pfx.fp_label,
			   pfx.fp_eos,
                           api_rpaths,
			   mp->context);
    vec_free(api_rpaths);
  }

  vec_free (lfeis);
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
  if (!q)
    return;

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
vl_api_set_ipfix_exporter_t_handler (vl_api_set_ipfix_exporter_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  flow_report_main_t *frm = &flow_report_main;
  vl_api_set_ipfix_exporter_reply_t *rmp;
  ip4_address_t collector, src;
  u16 collector_port = UDP_DST_PORT_ipfix;
  u32 path_mtu;
  u32 template_interval;
  u8 udp_checksum;
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
  if (fib_id == ~0)
    {
      fib_index = ~0;
    }
  else
    {
      uword *p = hash_get (im->fib_index_by_table_id, fib_id);
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	  goto out;
	}
      fib_index = p[0];
    }

  path_mtu = ntohl (mp->path_mtu);
  if (path_mtu == ~0)
    path_mtu = 512;		// RFC 7011 section 10.3.3.
  template_interval = ntohl (mp->template_interval);
  if (template_interval == ~0)
    template_interval = 20;
  udp_checksum = mp->udp_checksum;

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
  frm->udp_checksum = udp_checksum;

  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);

out:
  REPLY_MACRO (VL_API_SET_IPFIX_EXPORTER_REPLY);
}

static void
vl_api_ipfix_exporter_dump_t_handler (vl_api_ipfix_exporter_dump_t * mp)
{
  flow_report_main_t *frm = &flow_report_main;
  unix_shared_memory_queue_t *q;
  vl_api_ipfix_exporter_details_t *rmp;
  ip4_main_t *im = &ip4_main;
  u32 vrf_id;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IPFIX_EXPORTER_DETAILS);
  rmp->context = mp->context;
  memcpy (rmp->collector_address, frm->ipfix_collector.data,
	  sizeof (frm->ipfix_collector.data));
  rmp->collector_port = htons (frm->collector_port);
  memcpy (rmp->src_address, frm->src_address.data,
	  sizeof (frm->src_address.data));
  if (frm->fib_index == ~0)
    vrf_id = ~0;
  else
    vrf_id = im->fibs[frm->fib_index].ft_table_id;
  rmp->vrf_id = htonl (vrf_id);
  rmp->path_mtu = htonl (frm->path_mtu);
  rmp->template_interval = htonl (frm->template_interval);
  rmp->udp_checksum = (frm->udp_checksum != 0);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_set_ipfix_classify_stream_t_handler
  (vl_api_set_ipfix_classify_stream_t * mp)
{
  vl_api_set_ipfix_classify_stream_reply_t *rmp;
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  u32 domain_id = 0;
  u32 src_port = UDP_DST_PORT_ipfix;
  int rv = 0;

  domain_id = ntohl (mp->domain_id);
  src_port = ntohs (mp->src_port);

  if (fcm->src_port != 0 &&
      (fcm->domain_id != domain_id || fcm->src_port != (u16) src_port))
    {
      int rv = vnet_stream_change (frm, fcm->domain_id, fcm->src_port,
				   domain_id, (u16) src_port);
      ASSERT (rv == 0);
    }

  fcm->domain_id = domain_id;
  fcm->src_port = (u16) src_port;

  REPLY_MACRO (VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY);
}

static void
  vl_api_ipfix_classify_stream_dump_t_handler
  (vl_api_ipfix_classify_stream_dump_t * mp)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  unix_shared_memory_queue_t *q;
  vl_api_ipfix_classify_stream_details_t *rmp;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IPFIX_CLASSIFY_STREAM_DETAILS);
  rmp->context = mp->context;
  rmp->domain_id = htonl (fcm->domain_id);
  rmp->src_port = htons (fcm->src_port);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_ipfix_classify_table_add_del_t_handler
  (vl_api_ipfix_classify_table_add_del_t * mp)
{
  vl_api_ipfix_classify_table_add_del_reply_t *rmp;
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t args;
  ipfix_classify_table_t *table;
  int is_add;
  u32 classify_table_index;
  u8 ip_version;
  u8 transport_protocol;
  int rv = 0;

  classify_table_index = ntohl (mp->table_id);
  ip_version = mp->ip_version;
  transport_protocol = mp->transport_protocol;
  is_add = mp->is_add;

  if (fcm->src_port == 0)
    {
      /* call set_ipfix_classify_stream first */
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto out;
    }

  memset (&args, 0, sizeof (args));

  table = 0;
  int i;
  for (i = 0; i < vec_len (fcm->tables); i++)
    if (ipfix_classify_table_index_valid (i))
      if (fcm->tables[i].classify_table_index == classify_table_index)
	{
	  table = &fcm->tables[i];
	  break;
	}

  if (is_add)
    {
      if (table)
	{
	  rv = VNET_API_ERROR_VALUE_EXIST;
	  goto out;
	}
      table = ipfix_classify_add_table ();
      table->classify_table_index = classify_table_index;
    }
  else
    {
      if (!table)
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto out;
	}
    }

  table->ip_version = ip_version;
  table->transport_protocol = transport_protocol;

  args.opaque.as_uword = table - fcm->tables;
  args.rewrite_callback = ipfix_classify_template_rewrite;
  args.flow_data_callback = ipfix_classify_send_flows;
  args.is_add = is_add;
  args.domain_id = fcm->domain_id;
  args.src_port = fcm->src_port;

  rv = vnet_flow_report_add_del (frm, &args);

  /* If deleting, or add failed */
  if (is_add == 0 || (rv && is_add))
    ipfix_classify_delete_table (table - fcm->tables);

out:
  REPLY_MACRO (VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY);
}

static void
send_ipfix_classify_table_details (u32 table_index,
				   unix_shared_memory_queue_t * q,
				   u32 context)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vl_api_ipfix_classify_table_details_t *mp;

  ipfix_classify_table_t *table = &fcm->tables[table_index];

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IPFIX_CLASSIFY_TABLE_DETAILS);
  mp->context = context;
  mp->table_id = htonl (table->classify_table_index);
  mp->ip_version = table->ip_version;
  mp->transport_protocol = table->transport_protocol;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
  vl_api_ipfix_classify_table_dump_t_handler
  (vl_api_ipfix_classify_table_dump_t * mp)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  unix_shared_memory_queue_t *q;
  u32 i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  for (i = 0; i < vec_len (fcm->tables); i++)
    if (ipfix_classify_table_index_valid (i))
      send_ipfix_classify_table_details (i, q, mp->context);
}

static void
vl_api_pg_create_interface_t_handler (vl_api_pg_create_interface_t * mp)
{
  vl_api_pg_create_interface_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 pg_if_id = pg_interface_add_or_get (pg, ntohl (mp->interface_id));
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PG_CREATE_INTERFACE_REPLY,
  ({
    rmp->sw_if_index = ntohl(pi->sw_if_index);
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

static void
vl_api_delete_subif_t_handler (vl_api_delete_subif_t * mp)
{
  vl_api_delete_subif_reply_t *rmp;
  int rv;

  rv = vnet_delete_sub_interface (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_DELETE_SUBIF_REPLY);
}

static void
  vl_api_l2_interface_pbb_tag_rewrite_t_handler
  (vl_api_l2_interface_pbb_tag_rewrite_t * mp)
{
  vl_api_l2_interface_pbb_tag_rewrite_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 vtr_op;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vtr_op = ntohl (mp->vtr_op);

  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
    case L2_VTR_PUSH_2:
    case L2_VTR_POP_2:
    case L2_VTR_TRANSLATE_2_1:
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  rv = l2pbb_configure (vm, vnm, ntohl (mp->sw_if_index), vtr_op,
			mp->b_dmac, mp->b_smac, ntohs (mp->b_vlanid),
			ntohl (mp->i_sid), ntohs (mp->outer_tag));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY);

}

static void
vl_api_punt_t_handler (vl_api_punt_t * mp)
{
  vl_api_punt_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  clib_error_t *error;

  error = vnet_punt_add_del (vm, mp->ipv, mp->l4_protocol,
			     ntohs (mp->l4_port), mp->is_add);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  REPLY_MACRO (VL_API_PUNT_REPLY);
}

static void
  vl_api_flow_classify_set_interface_t_handler
  (vl_api_flow_classify_set_interface_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_flow_classify_set_interface_reply_t *rmp;
  int rv;
  u32 sw_if_index, ip4_table_index, ip6_table_index;

  ip4_table_index = ntohl (mp->ip4_table_index);
  ip6_table_index = ntohl (mp->ip6_table_index);
  sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_set_flow_classify_intfc (vm, sw_if_index, ip4_table_index,
				     ip6_table_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY);
}

static void
send_flow_classify_details (u32 sw_if_index,
			    u32 table_index,
			    unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_flow_classify_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_FLOW_CLASSIFY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->table_index = htonl (table_index);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_flow_classify_dump_t_handler (vl_api_flow_classify_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  flow_classify_main_t *pcm = &flow_classify_main;
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

	  send_flow_classify_details (i, vec_elt (vec_tbl, i), q,
				      mp->context);
	}
    }
}

static void
vl_api_feature_enable_disable_t_handler (vl_api_feature_enable_disable_t * mp)
{
  vl_api_feature_enable_disable_reply_t *rmp;
  int rv = 0;
  u8 *arc_name, *feature_name;

  VALIDATE_SW_IF_INDEX (mp);

  arc_name = format (0, "%s%c", mp->arc_name, 0);
  feature_name = format (0, "%s%c", mp->feature_name, 0);

  vnet_feature_registration_t *reg;
  reg =
    vnet_get_feature_reg ((const char *) arc_name,
			  (const char *) feature_name);
  if (reg == 0)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    {
      u32 sw_if_index;
      clib_error_t *error = 0;

      sw_if_index = ntohl (mp->sw_if_index);
      if (reg->enable_disable_cb)
	error = reg->enable_disable_cb (sw_if_index, mp->enable);
      if (!error)
	vnet_feature_enable_disable ((const char *) arc_name,
				     (const char *) feature_name,
				     sw_if_index, mp->enable, 0, 0);
      else
	{
	  clib_error_report (error);
	  rv = VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;
	}
    }

  vec_free (feature_name);
  vec_free (arc_name);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FEATURE_ENABLE_DISABLE_REPLY);
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

static void setup_message_id_table (api_main_t * am);

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
  am->api_trace_cfg[VL_API_MPLS_TUNNEL_ADD_DEL].size += 8 * sizeof (u32);
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_TABLE].size += 5 * sizeof (u32x4);
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_SESSION].size
    += 5 * sizeof (u32x4);
  am->api_trace_cfg[VL_API_VXLAN_ADD_DEL_TUNNEL].size += 16 * sizeof (u32);

  /*
   * Thread-safe API messages
   */
  am->is_mp_safe[VL_API_IP_ADD_DEL_ROUTE] = 1;
  am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
  am->bfd_events_registration_hash = hash_create (0, sizeof (uword));

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
  u64 baseva, size, pvt_heap_size;
  int uid, gid, rv;
  const int max_buf_size = 4096;
  char *s, *buf;
  struct passwd _pw, *pw;
  struct group _grp, *grp;
  clib_error_t *e;
  buf = vec_new (char, 128);
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
      else if (unformat (input, "baseva %llx", &baseva))
	vl_set_global_memory_baseva (baseva);
      else if (unformat (input, "global-size %lldM", &size))
	vl_set_global_memory_size (size * (1ULL << 20));
      else if (unformat (input, "global-size %lldG", &size))
	vl_set_global_memory_size (size * (1ULL << 30));
      else if (unformat (input, "global-size %lld", &size))
	vl_set_global_memory_size (size);
      else if (unformat (input, "global-pvt-heap-size %lldM", &pvt_heap_size))
	vl_set_global_pvt_heap_size (pvt_heap_size * (1ULL << 20));
      else if (unformat (input, "global-pvt-heap-size size %lld",
			 &pvt_heap_size))
	vl_set_global_pvt_heap_size (pvt_heap_size);
      else if (unformat (input, "api-pvt-heap-size %lldM", &pvt_heap_size))
	vl_set_api_pvt_heap_size (pvt_heap_size * (1ULL << 20));
      else if (unformat (input, "api-pvt-heap-size size %lld",
			 &pvt_heap_size))
	vl_set_api_pvt_heap_size (pvt_heap_size);
      else if (unformat (input, "api-size %lldM", &size))
	vl_set_api_memory_size (size * (1ULL << 20));
      else if (unformat (input, "api-size %lldG", &size))
	vl_set_api_memory_size (size * (1ULL << 30));
      else if (unformat (input, "api-size %lld", &size))
	vl_set_api_memory_size (size);
      else if (unformat (input, "uid %s", &s))
	{
	  /* lookup the username */
	  pw = NULL;
	  while (((rv =
		   getpwnam_r (s, &_pw, buf, vec_len (buf), &pw)) == ERANGE)
		 && (vec_len (buf) <= max_buf_size))
	    {
	      vec_resize (buf, vec_len (buf) * 2);
	    }
	  if (rv < 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch username %s", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  if (pw == NULL)
	    {
	      e =
		clib_error_return_fatal (0, "username %s does not exist", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  vec_free (s);
	  vl_set_memory_uid (pw->pw_uid);
	}
      else if (unformat (input, "gid %s", &s))
	{
	  /* lookup the group name */
	  grp = NULL;
	  while (((rv =
		   getgrnam_r (s, &_grp, buf, vec_len (buf), &grp)) == ERANGE)
		 && (vec_len (buf) <= max_buf_size))
	    {
	      vec_resize (buf, vec_len (buf) * 2);
	    }
	  if (rv != 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch group %s", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  if (grp == NULL)
	    {
	      e = clib_error_return_fatal (0, "group %s does not exist", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  vec_free (s);
	  vec_free (buf);
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

static u8 *
format_arp_event (u8 * s, va_list * args)
{
  vl_api_ip4_arp_event_t *event = va_arg (*args, vl_api_ip4_arp_event_t *);

  s = format (s, "pid %d: ", event->pid);
  if (event->mac_ip)
    s = format (s, "bd mac/ip4 binding events");
  else
    s = format (s, "resolution for %U", format_ip4_address, &event->address);
  return s;
}

static u8 *
format_nd_event (u8 * s, va_list * args)
{
  vl_api_ip6_nd_event_t *event = va_arg (*args, vl_api_ip6_nd_event_t *);

  s = format (s, "pid %d: ", event->pid);
  if (event->mac_ip)
    s = format (s, "bd mac/ip6 binding events");
  else
    s = format (s, "resolution for %U", format_ip6_address, event->address);
  return s;
}

static clib_error_t *
show_ip_arp_nd_events_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_ip4_arp_event_t *arp_event;
  vl_api_ip6_nd_event_t *nd_event;

  if ((pool_elts (am->arp_events) == 0) && (pool_elts (am->nd_events) == 0))
    {
      vlib_cli_output (vm, "No active arp or nd event registrations");
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (arp_event, am->arp_events,
  ({
    vlib_cli_output (vm, "%U", format_arp_event, arp_event);
  }));

  pool_foreach (nd_event, am->nd_events,
  ({
    vlib_cli_output (vm, "%U", format_nd_event, nd_event);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_arp_nd_events, static) = {
  .path = "show arp-nd-event registrations",
  .function = show_ip_arp_nd_events_fn,
  .short_help = "Show ip4 arp and ip6 nd event registrations",
};
/* *INDENT-ON* */

#define vl_msg_name_crc_list
#include <vpp-api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_memclnt;
  foreach_vl_msg_name_crc_vpe;
#undef _
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
